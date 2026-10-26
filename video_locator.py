"""Step 4: 视频段定位（Click-and-Block 模式）。

定位用户点击进视频的初始阶段：
  1. 将所有 QUIC 下行流量合并，按 100ms 时间桶聚合成包大小序列
  2. 从 operate.log 提取标记点：
     - Android: "Start search target video"
     - iOS: "已打开目标视频" 前 3 秒
  3. 时区偏移处理：通过 operate.log 中的 "pcap file:" 行对齐 PCAP 首包时间戳，
     计算 log_epoch → pcap_epoch 的偏移量
  4. 以标记点为搜索起点，在时间桶序列中定位首个突发下行大流量的起点
  5. 突发回落到 0 的位置作为终点
"""

import re
import bisect
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

from collections import Counter

from extract import DatagramRecord, DNSRecord
from utils import is_private_ip as _is_private_ip, infer_device_ip as _infer_device_ip

logger = logging.getLogger(__name__)


@dataclass
class VideoInterval:
    """识别到的视频初始阶段时间区间。"""
    start_time: float  # epoch seconds
    end_time: float    # epoch seconds
    method: str        # "click_and_block"
    confidence: str    # "high", "medium", "low"
    video_cdn_ips: List[str]
    resolved_device_ip: str = ""  # 实际使用的设备 IP（可能由推断得到）
    notes: str = ""


# ── 平台识别 ──────────────────────────────────────────────────

def detect_platform(pcap_path: Path) -> str:
    """
    从 PCAP 文件名识别平台。

    框架格式: YouTube-EncryptedVideo-{Platform}-{hash}-...
    Platform 字段: Android / iOS / IPhone / Windows 等

    Returns:
        "android", "ios" 或 "windows"，无法识别时默认 "android"
    """
    stem = pcap_path.stem.lower()
    if "ios" in stem or "iphone" in stem:
        return "ios"
    if "windows" in stem:
        return "windows"
    return "android"


# ── operate.log 单次解析（偏移量 + 标记点）─────────────────────

def parse_operate_log(
    operate_log_path: Optional[Path],
    platform: str,
    pcap_first_timestamp: float,
    phone_to_server_time_offset: int = 0,
) -> Tuple[float, Optional[float], bool]:
    """
    单次读取 operate.log，同时提取 log-to-pcap 偏移量和标记点时间。

    偏移量：
      Android/iOS: 从 "pcap file:" 行或 "tcpdump 已启动" 行的 epoch 与 PCAP 首包时间戳对齐计算。
      Windows: 无 "pcap file:" 行，用 metadata 的 phone_to_server_time_offset。
    标记点：
      Android: "Start search target video"（旧）或 "Start target video"（新）的 epoch
      iOS: "已打开目标视频" 的 epoch - 3s
      Windows: "启动抓包" 的本地时间转 epoch + phone_to_server_time_offset

    Args:
        operate_log_path: operate.log 文件路径
        platform: "android", "ios" 或 "windows"
        pcap_first_timestamp: PCAP 首包时间戳
        phone_to_server_time_offset: 手机与服务器时间偏移（毫秒），Windows 用作偏移量

    Returns:
        (log_to_pcap_offset, marker_time_pcap_basis, marker_is_direct)
        marker_time 已转换为 PCAP 时间基准；无法提取时为 None
        marker_is_direct: True 表示标记点直接对应视频播放起点（新格式 "Start target video"），
                         False 表示标记点后需搜索偏移（旧格式 "Start search target video"）
    """
    if not operate_log_path or not operate_log_path.exists():
        logger.warning("operate.log not available, cannot compute offset or extract marker")
        return 0.0, None, False

    pcap_line_epoch = None
    marker_epoch = None
    marker_is_direct = False

    try:
        with open(operate_log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # 提取 pcap file 行的 epoch（用于偏移量计算，Android/iOS）
                if pcap_line_epoch is None and (
                    "pcap file" in line.lower() or "pcap_file" in line.lower()
                    or "tcpdump 已启动" in line or "tcpdump已启动" in line
                ):
                    m = re.search(r'UTC\s+(\d+\.\d+)', line)
                    if m:
                        pcap_line_epoch = float(m.group(1))

                # 提取标记点（平台特定）
                if marker_epoch is None:
                    line_lower = line.lower()
                    if platform == "android":
                        if "start search target video" in line_lower:
                            m = re.search(r'UTC\s+(\d+\.\d+)', line)
                            if m:
                                marker_epoch = float(m.group(1))
                                marker_is_direct = False
                        elif "start target video" in line_lower:
                            m = re.search(r'UTC\s+(\d+\.\d+)', line)
                            if m:
                                marker_epoch = float(m.group(1))
                                marker_is_direct = True
                    elif platform == "ios":
                        if "已打开目标视频" in line or "opened target video" in line_lower:
                            m = re.search(r'UTC\s+(\d+\.\d+)', line)
                            if m:
                                marker_epoch = float(m.group(1)) - 3.0
                    elif platform == "windows":
                        if "启动抓包" in line:
                            m = re.search(
                                r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),(\d{3})\]',
                                line,
                            )
                            if m:
                                from datetime import datetime
                                dt_str = f"{m.group(1)}.{m.group(2)}"
                                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
                                marker_epoch = dt.timestamp()
    except Exception as e:
        logger.error(f"Failed to parse operate.log: {e}")
        return 0.0, None, False

    # 计算偏移量
    if platform == "windows":
        # Windows: 无 "pcap file:" 行，用 metadata 的 phone_to_server_time_offset
        offset = phone_to_server_time_offset / 1000.0
        logger.info(
            f"Windows log-to-PCAP offset: phone_to_server_time_offset={phone_to_server_time_offset}ms "
            f"= {offset:.3f}s"
        )
    elif pcap_line_epoch is not None:
        offset = pcap_first_timestamp - pcap_line_epoch
        logger.info(
            f"Log-to-PCAP offset: pcap_first={pcap_first_timestamp:.3f}, "
            f"log_pcap_line_epoch={pcap_line_epoch:.3f}, offset={offset:.3f}s"
        )
    else:
        logger.warning("No 'pcap file:' line found in operate.log, cannot compute log-to-pcap offset")
        offset = 0.0

    # 标记点转换为 PCAP 时间基准
    marker_time = None
    if marker_epoch is not None:
        marker_time = marker_epoch + offset

    return offset, marker_time, marker_is_direct


# ── 100ms 时间桶聚合 ─────────────────────────────────────────

def build_time_bins_combined(
    datagrams: List[DatagramRecord],
    device_ip: str,
    cdn_ips: set,
    bin_size_s: float = 0.1,
    pcap_start_time: float = 0.0,
) -> Tuple[str, List[Tuple[int, int]], List[Tuple[int, int]]]:
    """
    单次遍历同时构建全通道下行时间桶和 CDN-only 下行时间桶。

    全通道桶用于播放段检测，CDN-only 桶用于段内 CDN 字节校验。

    Args:
        datagrams: UDP 数据报列表
        device_ip: 设备 IP，为空时自动推断
        cdn_ips: video_cdn IP 集合
        bin_size_s: 桶宽度（秒），默认 0.1（100ms）
        pcap_start_time: PCAP 起始时间

    Returns:
        (resolved_device_ip, all_bins, cdn_bins)
        all_bins: [(bin_index, downstream_bytes), ...]
        cdn_bins: [(bin_index, cdn_downstream_bytes), ...]
    """
    if not device_ip:
        device_ip = _infer_device_ip(datagrams)
        if device_ip:
            logger.info(f"device_ip was empty, inferred as {device_ip}")
        else:
            logger.warning("device_ip was empty and could not be inferred from traffic")
            return device_ip, [], []

    cdn_set = cdn_ips or set()
    all_bins = {}
    cdn_bins = {}

    for d in datagrams:
        if not d.has_udp:
            continue
        if d.dst_ip != device_ip:
            continue
        payload = d.udp_payload_length or 0
        bin_idx = int((d.timestamp - pcap_start_time) / bin_size_s)
        all_bins[bin_idx] = all_bins.get(bin_idx, 0) + payload
        if d.src_ip in cdn_set:
            cdn_bins[bin_idx] = cdn_bins.get(bin_idx, 0) + payload

    return device_ip, sorted(all_bins.items()), sorted(cdn_bins.items())


# ── 播放段检测 ──────────────────────────────────────────────────

def _search_windowed_bins(
    bin_map: dict,
    search_start_bin: int,
    search_end_bin: int,
    search_forward: bool,
    window_size: int,
    threshold_bytes: int,
    min_count: int,
) -> Optional[int]:
    """在搜索范围内，用滑动窗口查找满足条件的播放段起点。

    滑动窗口语义：在 window_size 个连续桶的窗口内，至少 min_count 个桶
    ≥ threshold_bytes，则该窗口中首个达标桶为播放段起点。

    Args:
        bin_map: bin_index -> downstream_bytes 的映射
        search_start_bin: 搜索范围起始桶索引
        search_end_bin: 搜索范围结束桶索引
        search_forward: True=正向搜索，False=逆向搜索
        window_size: 滑动窗口宽度（桶数）
        threshold_bytes: 达标阈值（字节）
        min_count: 窗口内达标桶的最少数量

    Returns:
        播放段起点桶索引（窗口内首个达标桶），未找到返回 None
    """
    if window_size < min_count or min_count <= 0:
        return None

    play_start_bin = None

    if search_forward:
        for anchor in range(search_start_bin, search_end_bin - window_size + 2):
            # 计算窗口 [anchor, anchor + window_size - 1] 内达标桶数
            count = 0
            first_hit = None
            for b in range(anchor, anchor + window_size):
                if bin_map.get(b, 0) >= threshold_bytes:
                    count += 1
                    if first_hit is None:
                        first_hit = b
            if count >= min_count and first_hit is not None:
                play_start_bin = first_hit
                break
    else:
        # 逆向搜索：窗口右边界从 search_end_bin 向左滑动
        for anchor_end in range(search_end_bin, search_start_bin + window_size - 2, -1):
            # 窗口 [anchor_end - window_size + 1, anchor_end]
            anchor_start = anchor_end - window_size + 1
            count = 0
            first_hit = None
            for b in range(anchor_start, anchor_end + 1):
                if bin_map.get(b, 0) >= threshold_bytes:
                    count += 1
                    if first_hit is None:
                        first_hit = b
            if count >= min_count and first_hit is not None:
                play_start_bin = first_hit
                break

    return play_start_bin


def find_play_segment(
    time_bins: List[Tuple[int, int]],
    search_start_bin: int,
    search_end_bin: int,
    search_forward: bool = True,
    bin_size_s: float = 0.1,
    play_window_bins: int = 10,
    play_threshold_bytes: int = 1000,
    play_min_count: int = 5,
    zero_window_bins: int = 10,
    zero_min_count: int = 5,
    zero_threshold_bytes: int = 10,
    fallback_window_bins: int = 15,
    fallback_threshold_bytes: int = 0,
    fallback_min_count: int = 10,
    cdn_bin_map: Optional[dict] = None,
    min_cdn_bytes: int = 0,
) -> Tuple[Optional[int], Optional[int], str]:
    """
    在时间桶序列中定位视频播放段的起止桶索引。

    起点判定（两级优先，滑动窗口语义）：
      优先：play_window_bins 个桶的窗口内，至少 play_min_count 个桶
            ≥ play_threshold_bytes（默认 10桶内≥5桶≥1000B）
      次优：fallback_window_bins 个桶的窗口内，至少 fallback_min_count 个桶
            > fallback_threshold_bytes（默认 15桶内≥10桶>0B，即15桶内10个非零桶）
      均未找到：返回 (None, None, "none")，由调用方记录质量问题

    终点判定（桶密度滑动窗口）：
      从播放段起点向后扫描，维护尾部 zero_window_bins 个桶的滑动窗口，
      统计窗口内 > zero_threshold_bytes 的桶数，当 < zero_min_count 时判定回落
      （默认 10桶内 <5个>10B桶 → 回落），最后一个非零桶为播放段终点。
      相比连续零桶判定：(1) 允许突发内出现短暂间隙，不会因少量小包间隔而过早终止；
      (2) 以桶密度而非零桶密度判定，过滤API/ACK等低量拖尾对区间的拉长。

    搜索方向：
      search_forward=True:  从 search_start_bin 向 search_end_bin 搜索（Android）
      search_forward=False: 从 search_end_bin 向 search_start_bin 搜索（iOS，逆向找最近的播放段）

    Args:
        time_bins: [(bin_index, downstream_bytes), ...] 排序后的非空桶
        search_start_bin: 搜索窗口起始桶索引
        search_end_bin: 搜索窗口结束桶索引
        search_forward: True=正向搜索，False=逆向搜索
        bin_size_s: 桶宽度（秒）
        play_window_bins: 优先方案滑动窗口宽度（桶数）
        play_threshold_bytes: 优先方案单桶阈值（字节），≥此值视为有视频数据
        play_min_count: 优先方案窗口内最少达标桶数
        zero_window_bins: 终点判定滑动窗口宽度（桶数），默认10
        zero_min_count: 终点判定窗口内达标桶最少数量，<此值判定回落，默认5
        zero_threshold_bytes: 终点判定单桶阈值（字节），>此值视为有效桶，默认10
        fallback_window_bins: 次优方案滑动窗口宽度（桶数）
        fallback_threshold_bytes: 次优方案阈值（默认0）
        fallback_min_count: 次优方案窗口内最少达标桶数
        cdn_bin_map: video_cdn 下行流量的 bin_index→bytes 映射，用于段内
                     CDN 字节校验。None 时跳过 CDN 校验。
        min_cdn_bytes: 段内 video_cdn 下行最少字节数，低于此值视为非视频段，
                       触发重试搜索。默认 0（不校验）。

    段有效性校验（两个条件并列，任一不满足即触发重试）：
      1. 段长度 ≥ play_window_bins（初始缓冲突发检测）
      2. 段内 video_cdn 下行字节 ≥ min_cdn_bytes（API 突发排除）

    Returns:
        (start_bin, end_bin, confidence)
        confidence: "high"（优先方案） / "medium"（次优方案） / "none"（均未找到）
        start_bin 和 end_bin 在 confidence="none" 时均为 None
    """
    # 构建 bin_index -> bytes 的快速查找表
    bin_map = {idx: nbytes for idx, nbytes in time_bins}

    # 最小有效段长度（桶数）：短于此长度的段视为初始缓冲突发，
    # 从其后继续搜索真正的持续播放段
    min_segment_bins = play_window_bins  # 默认 10 桶 = 1.0s

    # 搜索窗口的绝对边界
    abs_search_end = search_end_bin

    best_start_bin = None
    best_end_bin = None
    best_confidence = "none"

    while True:
        # Step 1a: 优先方案 — 窗口内达标桶比例检测
        play_start_bin = _search_windowed_bins(
            bin_map, search_start_bin, search_end_bin,
            search_forward, play_window_bins, play_threshold_bytes, play_min_count,
        )
        detect_method = "primary"

        if play_start_bin is None:
            # Step 1b: 次优方案 — 窗口内非零桶比例检测
            play_start_bin = _search_windowed_bins(
                bin_map, search_start_bin, search_end_bin,
                search_forward, fallback_window_bins, fallback_threshold_bytes + 1, fallback_min_count,
            )
            detect_method = "fallback"

        if play_start_bin is None:
            if best_start_bin is not None:
                # 之前找到过短段，但后续搜索无更多满足条件的段
                break
            direction = "forward" if search_forward else "backward"
            logger.warning(
                f"No play segment found ({direction}) in range "
                f"[{search_start_bin}, {search_end_bin}] "
                f"(primary: {play_window_bins}-bin window ≥{play_min_count}×≥{play_threshold_bytes}B, "
                f"fallback: {fallback_window_bins}-bin window ≥{fallback_min_count}×>{fallback_threshold_bytes}B)"
            )
            return None, None, "none"

        # Step 2: 从播放段起点开始，用桶密度滑动窗口检测回落
        # 维护最近 zero_window_bins 个桶中 > zero_threshold_bytes 的桶计数，
        # 当 < zero_min_count 时判定回落（即有效包密度不足，视为非视频数据）
        play_end_bin = play_start_bin
        max_bin = max(bin_map.keys()) if bin_map else play_start_bin

        # 用固定大小队列维护尾部窗口
        window_big = 0  # 窗口内 > zero_threshold_bytes 的桶计数
        window_buf = []  # 最近 zero_window_bins 个桶是否为有效包(1=>threshold, 0=≤threshold)

        for b in range(play_start_bin, max_bin + 1):
            nbytes = bin_map.get(b, 0)
            is_big = 1 if nbytes > zero_threshold_bytes else 0

            if nbytes > 0:
                play_end_bin = b

            # 更新滑动窗口
            window_buf.append(is_big)
            window_big += is_big

            if len(window_buf) > zero_window_bins:
                removed = window_buf.pop(0)
                window_big -= removed

            # 窗口填满后检查条件：大包桶数 < zero_min_count → 回落
            if len(window_buf) >= zero_window_bins and window_big < zero_min_count:
                break

        confidence = "high" if detect_method == "primary" else "medium"

        # 段有效性校验：时长 + CDN 字节（两个条件并列）
        segment_bins = play_end_bin - play_start_bin
        duration_ok = segment_bins >= min_segment_bins

        # CDN 字节校验：统计段内 video_cdn 下行字节数
        cdn_bytes = 0
        if cdn_bin_map is not None and min_cdn_bytes > 0:
            for b in range(play_start_bin, play_end_bin + 1):
                cdn_bytes += cdn_bin_map.get(b, 0)
        cdn_ok = (cdn_bytes >= min_cdn_bytes) if min_cdn_bytes > 0 else True

        if duration_ok and cdn_ok:
            return play_start_bin, play_end_bin, confidence

        # 段不满足条件，记录原因并从终点之后继续搜索
        if not duration_ok and not cdn_ok:
            reason = f"short({segment_bins} bins < {min_segment_bins}) and low CDN ({cdn_bytes}B < {min_cdn_bytes}B)"
        elif not duration_ok:
            reason = f"short burst ({segment_bins} bins < {min_segment_bins})"
        else:
            reason = f"low CDN ({cdn_bytes}B < {min_cdn_bytes}B, duration {segment_bins} bins ok)"
        logger.info(
            f"Segment rejected (bins {play_start_bin}-{play_end_bin}): {reason}, "
            f"continuing search"
        )
        best_start_bin = play_start_bin
        best_end_bin = play_end_bin
        best_confidence = confidence

        # 从当前段终点之后继续搜索
        search_start_bin = play_end_bin + 1

        # 检查剩余窗口是否足够容纳一个 play_window_bins 的窗口
        if search_start_bin + play_window_bins - 1 > abs_search_end:
            break

    # 所有重试都失败，返回最后一个找到的短段
    # 上层会通过 duration 检查排除该样本（short_video）
    return best_start_bin, best_end_bin, best_confidence


# ── 精准定位辅助（二分查找）──────────────────────────────────

def _build_timestamp_index(datagrams: List[DatagramRecord]) -> Tuple[List[float], List[int]]:
    """预构建按 timestamp 排序的索引，供二分查找使用。

    Returns:
        (sorted_timestamps, sorted_indices) — sorted_indices[i] 指向 datagrams 中对应元素
    """
    pairs = sorted(enumerate(datagrams), key=lambda x: x[1].timestamp)
    timestamps = [d.timestamp for _, d in pairs]
    indices = [i for i, _ in pairs]
    return timestamps, indices


def _find_first_downstream_in_bin(
    datagrams: List[DatagramRecord],
    device_ip: str,
    bin_start: float,
    bin_end: float,
    ts_index: Optional[Tuple[List[float], List[int]]] = None,
) -> Optional[float]:
    """在指定时间桶内找第一个下行数据报的时间戳（二分查找）。"""
    if ts_index is not None:
        timestamps, indices = ts_index
        lo = bisect.bisect_left(timestamps, bin_start)
        hi = bisect.bisect_left(timestamps, bin_end)
        for i in range(lo, hi):
            d = datagrams[indices[i]]
            if d.has_udp and device_ip and d.dst_ip == device_ip:
                return d.timestamp
        return None

    # 回退：线性扫描
    earliest = None
    for d in datagrams:
        if not d.has_udp:
            continue
        if device_ip and d.dst_ip == device_ip:
            if bin_start <= d.timestamp < bin_end:
                if earliest is None or d.timestamp < earliest:
                    earliest = d.timestamp
    return earliest


def _find_last_downstream_in_bin(
    datagrams: List[DatagramRecord],
    device_ip: str,
    bin_start: float,
    bin_end: float,
    ts_index: Optional[Tuple[List[float], List[int]]] = None,
) -> Optional[float]:
    """在指定时间桶内找最后一个下行数据报的时间戳（二分查找）。"""
    if ts_index is not None:
        timestamps, indices = ts_index
        lo = bisect.bisect_left(timestamps, bin_start)
        hi = bisect.bisect_left(timestamps, bin_end)
        latest = None
        for i in range(lo, hi):
            d = datagrams[indices[i]]
            if d.has_udp and device_ip and d.dst_ip == device_ip:
                if latest is None or d.timestamp > latest:
                    latest = d.timestamp
        return latest

    # 回退：线性扫描
    latest = None
    for d in datagrams:
        if not d.has_udp:
            continue
        if device_ip and d.dst_ip == device_ip:
            if bin_start <= d.timestamp < bin_end:
                if latest is None or d.timestamp > latest:
                    latest = d.timestamp
    return latest


# ── 主入口 ────────────────────────────────────────────────────

def locate_video_segment(
    datagrams: List[DatagramRecord],
    dns_records: List[DNSRecord],
    pcap_path: Path = None,
    device_ip: str = "",
    operate_log_path: Optional[Path] = None,
    phone_to_server_time_offset: int = 0,
    video_cdn_patterns: list = None,
    pcap_start_time: float = 0,
    pcap_end_time: float = 0,
    # click_and_block 专属参数
    play_window_bins: int = 10,
    play_threshold_bytes: int = 1000,
    play_min_count: int = 5,
    zero_window_bins: int = 10,
    zero_min_count: int = 5,
    zero_threshold_bytes: int = 10,
    fallback_window_bins: int = 15,
    fallback_min_count: int = 10,
    search_window_s: float = 10.0,
    search_window_start_offset_s: float = 3.0,
    search_window_ios_s: float = 10.0,
    search_window_windows_s: float = 10.0,
    search_window_windows_start_offset_s: float = 0.0,
    bin_size_s: float = 0.1,
    min_cdn_bytes: int = 50 * 1024,
) -> VideoInterval:
    """
    Click-and-Block 模式定位视频初始阶段。

    时区偏移处理：
      通过 operate.log 中的 "pcap file:" 行对齐 PCAP 首包时间戳，
      自动计算 log_epoch → pcap_epoch 的偏移量（涵盖时区差异和
      phone_to_server_time_offset）。若无法从 operate.log 计算偏移，
      回退使用 metadata 中的 phone_to_server_time_offset。

    平台差异：
      Android: marker = "Start search target video"，视频数据在 marker 之后
               → 正向搜索 [marker_bin + start_offset, marker_bin + search_window_s]
      iOS:     marker = "已打开目标视频" - 3s，视频数据在 marker 之前
               → 正向搜索 [marker_bin - search_window_ios_s, marker_bin]
      Windows: marker = "启动抓包"，视频数据在 marker 之后不久
               → 正向搜索 [marker_bin + start_offset, marker_bin + search_window_windows_s]

    播放段检测算法（滑动窗口语义）：
      1. 将 QUIC 下行流量按 100ms 桶聚合
      2. 优先方案：在 play_window_bins 个桶的窗口内，至少 play_min_count 个桶
         ≥ play_threshold_bytes，窗口内首个达标桶为播放段起点
      3. 次优方案：在 fallback_window_bins 个桶的窗口内，至少 fallback_min_count 个桶
         > 0，窗口内首个达标桶为播放段起点
      4. 起点桶内精准定位：找该桶内第一个下行数据报的时间戳
      5. 从播放段起点向后搜索，>1KB桶密度滑动窗口判定回落：
         维护尾部 zero_window_bins 个桶的窗口，统计>1000B桶数，
         当 < zero_min_count 时判定回落
      6. 终点桶内精准定位：找该桶内最后一个下行数据报的时间戳

    Args:
        datagrams: 提取的 UDP 数据报列表
        dns_records: DNS A 记录列表
        pcap_path: PCAP 文件路径（用于平台识别）
        device_ip: 设备 IP 地址
        operate_log_path: operate.log 文件路径
        phone_to_server_time_offset: 手机与服务器时间偏移（毫秒），仅作回退
        video_cdn_patterns: CDN 域名匹配模式（用于记录 CDN IP，不用于定位）
        pcap_start_time: PCAP 起始时间
        pcap_end_time: PCAP 结束时间
        play_window_bins: 优先方案滑动窗口宽度（桶数），默认10
        play_threshold_bytes: 优先方案单桶阈值（字节），≥此值视为有视频数据
        play_min_count: 优先方案窗口内最少达标桶数，默认5
        zero_window_bins: 终点判定滑动窗口宽度（桶数），默认10
        zero_min_count: 终点判定窗口内达标桶最少数量，<此值判定回落，默认5
        zero_threshold_bytes: 终点判定单桶阈值（字节），>此值视为有效桶，默认10
        fallback_window_bins: 次优方案滑动窗口宽度（桶数），默认15
        fallback_min_count: 次优方案窗口内最少达标桶数，默认10
        search_window_s: Android 搜索窗口长度（秒），起点为 marker + search_window_start_offset_s
        search_window_start_offset_s: Android 搜索起点相对 marker 的偏移（秒），默认3.0
        search_window_ios_s: iOS 搜索窗口（秒），从 marker 向前
        search_window_windows_s: Windows 搜索窗口长度（秒），默认10.0
        search_window_windows_start_offset_s: Windows 搜索起点相对 marker 的偏移（秒），默认0.0
        bin_size_s: 时间桶宽度（秒）

    Returns:
        VideoInterval
    """
    if video_cdn_patterns is None:
        video_cdn_patterns = ["googlevideo.com"]

    # 从 DNS 记录构建视频 CDN IP 集合（仅用于记录，不参与定位）
    video_cdn_ips = set()
    for dns in dns_records:
        for pattern in video_cdn_patterns:
            if _domain_matches(dns.query_domain, pattern):
                video_cdn_ips.update(dns.answer_ips)

    # 平台识别
    platform = detect_platform(pcap_path) if pcap_path else "android"

    # 单次读取 operate.log，同时提取偏移量和标记点
    log_to_pcap_offset, marker_time, marker_is_direct = parse_operate_log(
        operate_log_path, platform, pcap_start_time,
        phone_to_server_time_offset=phone_to_server_time_offset,
    )

    # 若无法从 operate.log 计算偏移，回退使用 phone_to_server_time_offset
    if log_to_pcap_offset == 0.0 and phone_to_server_time_offset != 0:
        log_to_pcap_offset = phone_to_server_time_offset / 1000.0
        logger.info(
            f"Using phone_to_server_time_offset as fallback: "
            f"{phone_to_server_time_offset}ms = {log_to_pcap_offset:.3f}s"
        )
        # 若标记点存在但偏移量回退了，需重新应用偏移
        if marker_time is not None:
            marker_time = marker_time + log_to_pcap_offset

    if marker_time is None:
        logger.warning(
            f"No marker found in operate.log (platform={platform}), "
            f"falling back to PCAP start time as search origin"
        )
        marker_time = pcap_start_time

    # 单次遍历构建全通道下行时间桶 + CDN-only 下行时间桶
    resolved_device_ip, time_bins, cdn_time_bins = build_time_bins_combined(
        datagrams, device_ip, video_cdn_ips, bin_size_s, pcap_start_time,
    )
    cdn_bin_map = {idx: nbytes for idx, nbytes in cdn_time_bins} if cdn_time_bins else None

    # CDN IP 集合为空时（如 Windows Chrome 使用 DoH，无明文 DNS 记录），
    # CDN 字节校验无意义，跳过以避免所有段被误拒
    effective_min_cdn_bytes = min_cdn_bytes if video_cdn_ips else 0

    # 根据平台确定搜索方向和窗口
    marker_bin = int((marker_time - pcap_start_time) / bin_size_s)

    if platform == "ios":
        # iOS: marker 是"已打开目标视频-3s"，视频数据在 marker 之前
        # 搜索区间 [marker - search_window_ios_s, marker]
        # 正向搜索：从区间起点向 marker 方向搜索，找到最早的满足条件的突发
        search_start_bin = max(0, int((marker_time - search_window_ios_s - pcap_start_time) / bin_size_s))
        search_end_bin = marker_bin
        search_forward = True
    elif platform == "windows":
        # Windows: marker 是"启动抓包"，视频数据在 marker 之后不久
        # 搜索区间 [marker + start_offset, marker + search_window_windows_s]
        # 正向搜索：从 marker 向后搜索 [M, M+5]
        search_start_bin = int((marker_time + search_window_windows_start_offset_s - pcap_start_time) / bin_size_s)
        search_end_bin = int((marker_time + search_window_windows_s - pcap_start_time) / bin_size_s)
        search_forward = True
    else:
        # Android: marker 是"Start search target video"（旧）或 "Start target video"（新）
        # 旧标记: 视频数据在 marker + 3s 之后（搜索+点击延迟），正向搜索 [M+3, M+search_window_s]
        # 新标记: 视频数据在 marker 前后 3s 内（session intent 直接启动播放，YouTube 有预加载），
        #         搜索区间 [S, M+3]，S=0 if M<3 else S=M-3
        if marker_is_direct:
            marker_rel = marker_time - pcap_start_time
            search_start_s = 0.0 if marker_rel < 3.0 else marker_rel - 3.0
            search_start_bin = int(search_start_s / bin_size_s)
            search_end_bin = int((marker_time + 3.0 - pcap_start_time) / bin_size_s)
        else:
            search_start_bin = int((marker_time + search_window_start_offset_s - pcap_start_time) / bin_size_s)
            search_end_bin = int((marker_time + search_window_s - pcap_start_time) / bin_size_s)
        search_forward = True

    # 定位播放段起止桶
    start_bin, end_bin, confidence = find_play_segment(
        time_bins, search_start_bin, search_end_bin,
        search_forward=search_forward,
        bin_size_s=bin_size_s,
        play_window_bins=play_window_bins,
        play_threshold_bytes=play_threshold_bytes,
        play_min_count=play_min_count,
        zero_window_bins=zero_window_bins,
        zero_min_count=zero_min_count,
        zero_threshold_bytes=zero_threshold_bytes,
        fallback_window_bins=fallback_window_bins,
        fallback_min_count=fallback_min_count,
        cdn_bin_map=cdn_bin_map,
        min_cdn_bytes=effective_min_cdn_bytes,
    )

    # 优先和次优方案均未找到 → 返回 confidence="none"，由上层记录质量问题
    if confidence == "none":
        logger.warning(
            f"No play segment detected for {pcap_path.name if pcap_path else '(unknown)'}: "
            f"primary({play_window_bins}-bin window ≥{play_min_count}×≥{play_threshold_bytes}B) and "
            f"fallback({fallback_window_bins}-bin window ≥{fallback_min_count}×>0B) both failed in "
            f"{'forward' if search_forward else 'backward'} range "
            f"[{search_start_bin}, {search_end_bin}]"
        )
        return VideoInterval(
            start_time=pcap_start_time,
            end_time=pcap_start_time,
            method="click_and_block",
            confidence="none",
            video_cdn_ips=list(video_cdn_ips),
            resolved_device_ip=resolved_device_ip,
            notes=(
                f"platform={platform}, marker_time={marker_time:.3f}, "
                f"log_to_pcap_offset={log_to_pcap_offset:.3f}s, "
                f"device_ip={resolved_device_ip or '(unknown)'}, "
                f"cdn_ips={len(video_cdn_ips)}, "
                f"play_window={play_window_bins},play_min_count={play_min_count},play_threshold={play_threshold_bytes}B, "
                f"fallback_window={fallback_window_bins},fallback_min_count={fallback_min_count}, "
                f"zero_window={zero_window_bins},zero_min_count={zero_min_count}, "
                f"search={'forward' if search_forward else 'backward'}, "
                f"search_window={_format_search_window(platform, search_window_start_offset_s, search_window_s, search_window_ios_s, search_window_windows_start_offset_s, search_window_windows_s)}, "
                f"FAILED: primary_and_fallback_both_missed"
            ),
        )

    # ── 精准定位：在起止桶内找首/末下行数据报时间戳 ───────────
    start_bin_time = pcap_start_time + start_bin * bin_size_s
    end_bin_time = pcap_start_time + end_bin * bin_size_s
    next_bin_time = end_bin_time + bin_size_s

    # 预构建时间戳索引，供二分查找使用
    ts_index = _build_timestamp_index(datagrams)

    # 起点精准定位：起点桶内第一个下行数据报
    precise_start = _find_first_downstream_in_bin(
        datagrams, resolved_device_ip, start_bin_time, start_bin_time + bin_size_s,
        ts_index=ts_index,
    )
    start_time = precise_start if precise_start is not None else start_bin_time

    # 终点精准定位：终点桶内最后一个下行数据报
    precise_end = _find_last_downstream_in_bin(
        datagrams, resolved_device_ip, end_bin_time, next_bin_time,
        ts_index=ts_index,
    )
    end_time = precise_end if precise_end is not None else next_bin_time

    return VideoInterval(
        start_time=start_time,
        end_time=end_time,
        method="click_and_block",
        confidence=confidence,
        video_cdn_ips=list(video_cdn_ips),
        resolved_device_ip=resolved_device_ip,
        notes=(
            f"platform={platform}, marker_time={marker_time:.3f}, "
            f"log_to_pcap_offset={log_to_pcap_offset:.3f}s, "
            f"device_ip={resolved_device_ip or '(unknown)'}, "
            f"cdn_ips={len(video_cdn_ips)}, "
            f"play_window={play_window_bins},play_min_count={play_min_count},play_threshold={play_threshold_bytes}B, "
            f"fallback_window={fallback_window_bins},fallback_min_count={fallback_min_count}, "
            f"zero_window={zero_window_bins},zero_min_count={zero_min_count}, "
            f"search={'forward' if search_forward else 'backward'}, "
            f"search_window={_format_search_window(platform, search_window_start_offset_s, search_window_s, search_window_ios_s, search_window_windows_start_offset_s, search_window_windows_s)}, "
            f"start_bin={start_bin}(precise={'Y' if precise_start else 'N'}), "
            f"end_bin={end_bin}(precise={'Y' if precise_end else 'N'})"
        ),
    )


# ── 辅助函数 ──────────────────────────────────────────────────

def _format_search_window(
    platform: str,
    android_offset: float, android_window: float,
    ios_window: float,
    windows_offset: float, windows_window: float,
) -> str:
    """格式化搜索窗口信息用于日志/notes。"""
    if platform == "ios":
        return f"ios:{ios_window}s"
    elif platform == "windows":
        return f"windows:[{windows_offset}s,{windows_window}s]"
    else:
        return f"android:[{android_offset}s,{android_window}s]"

def _domain_matches(domain: str, pattern: str) -> bool:
    """检查 DNS 域名是否匹配模式（支持 *.prefix 通配符）。"""
    domain = domain.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return domain == pattern or domain.endswith("." + pattern)
