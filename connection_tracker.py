"""Step 5: 连接跟踪（五元组 + DCID 映射）。

为每个 UDP 数据报分配匿名 path_id，基于五元组分组。
支持从握手阶段构建 DCID 到五元组的映射，用于 CID 迁移场景。
当 device_ip 为空时，自动从流量中推断设备 IP（启发式：私有网段中
同时作为源和目的出现的 IP，且作为源时以小包为主、作为目的时以大包为主）。
"""

import logging
from collections import Counter
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from extract import DatagramRecord
from utils import is_private_ip, infer_device_ip

logger = logging.getLogger(__name__)


@dataclass
class PathInfo:
    """单条五元组路径的信息。"""
    path_key: frozenset  # {(ip, port), (ip, port)}
    path_id: int
    packet_count: int = 0
    total_bytes: int = 0
    first_seen_time: float = 0.0
    last_seen_time: float = 0.0
    is_quic: bool = False
    quic_version: str = ""
    dcid_list: List[str] = field(default_factory=list)
    is_video_cdn: bool = False
    src_ip_port: Tuple[str, int] = ("", 0)
    dst_ip_port: Tuple[str, int] = ("", 0)
    channel_id: Optional[int] = None       # 语义通道 (0-4), None=未分类
    channel_name: str = ""                  # 通道名称 (video_cdn/thumbnail/...)
    channel_source: str = ""                # 分类来源 (SNI/DNS/unmapped)


def track_connections(
    datagrams: List[DatagramRecord],
    device_ip: str,
    video_cdn_ips: List[str],
    path_selection: str = "all",
    top_k: int = 4,
    merge_other: bool = False,
    ip_channel_map: Optional[Dict[str, Tuple[int, str]]] = None,
) -> Tuple[List[dict], Dict[frozenset, PathInfo]]:
    """
    跟踪连接并为每个数据报分配 path_id。

    处理流程：
      Phase 1: 从 QUIC 长头部（握手包）构建 DCID → 五元组映射
      Phase 2: 按五元组对所有 UDP 数据报分组，统计每条路径信息
      Phase 3: 按 packet_count 降序分配 path_id
      Phase 4: 为每条路径分配语义通道标签
      Phase 5: 生成带 path_id 和方向的输出记录

    Args:
        datagrams: UDP 数据报列表
        device_ip: 设备 IP
        video_cdn_ips: 视频 CDN IP 列表
        path_selection: 路径选择策略 ("all" / "top_k" / "video_cdn_only")
        top_k: top_k 策略保留的路径数
        merge_other: 是否将非 top_k 路径合并为 "other"
        ip_channel_map: 语义通道映射 {ip: (channel_id, source_tier)}，
                        来自 SemanticClassifier.classify()

    Returns:
        (records, path_stats) — records 为每包记录字典列表，path_stats 为路径统计
    """
    video_cdn_set = set(video_cdn_ips)
    udp_datagrams = [d for d in datagrams if d.has_udp]

    # device_ip 为空时，从流量中启发式推断
    if not device_ip and udp_datagrams:
        device_ip = infer_device_ip(udp_datagrams)
        if device_ip:
            logger.info(f"device_ip was empty, inferred as {device_ip}")
        else:
            logger.warning("device_ip was empty and could not be inferred from traffic")

    # Phase 1: 从握手包构建 DCID → 五元组映射
    # 服务器→客户端的 1-RTT 短头部包 DCID 可见度为 0%，
    # 需要从 Initial 包的 DCID/SCID 建立映射关系
    cid_to_path: Dict[str, frozenset] = {}
    for d in udp_datagrams:
        if d.quic_header_form == 1:  # Long header = Initial/Handshake
            path_key = _make_path_key(d.src_ip, d.src_port, d.dst_ip, d.dst_port)
            if d.src_ip == device_ip and d.quic_dcid:
                cid_to_path[d.quic_dcid] = path_key
            if d.src_ip != device_ip and d.quic_scid:
                cid_to_path[d.quic_scid] = path_key

    # Phase 2: 为每个数据报分配 path_key，按五元组分组
    path_stats: Dict[frozenset, PathInfo] = {}
    path_keys = []  # 缓存每个数据报的 path_key，供 Phase 5 复用
    for d in udp_datagrams:
        path_key = _make_path_key(d.src_ip, d.src_port, d.dst_ip, d.dst_port)
        path_keys.append(path_key)
        if path_key not in path_stats:
            is_cdn = d.src_ip in video_cdn_set or d.dst_ip in video_cdn_set
            # 以设备 IP 为基准确定 src/dst 方向
            if d.src_ip == device_ip:
                src_pair = (d.src_ip, d.src_port)
                dst_pair = (d.dst_ip, d.dst_port)
            else:
                src_pair = (d.dst_ip, d.dst_port)
                dst_pair = (d.src_ip, d.src_port)
            path_stats[path_key] = PathInfo(
                path_key=path_key,
                path_id=-1,
                first_seen_time=d.timestamp,
                is_quic=d.quic_header_form is not None,
                quic_version=d.quic_version or "",
                is_video_cdn=is_cdn,
                src_ip_port=src_pair,
                dst_ip_port=dst_pair,
            )

        info = path_stats[path_key]
        info.packet_count += 1
        info.total_bytes += d.udp_payload_length or 0
        info.last_seen_time = d.timestamp
        if d.quic_header_form is not None:
            info.is_quic = True
        if d.quic_dcid and d.quic_dcid not in info.dcid_list:
            info.dcid_list.append(d.quic_dcid)
        if d.quic_scid and d.quic_scid not in info.dcid_list:
            info.dcid_list.append(d.quic_scid)

    # Phase 3: 按 packet_count 降序分配 path_id
    _assign_path_ids(path_stats, path_selection, top_k, merge_other)

    # Phase 4: 分配语义通道标签
    if ip_channel_map:
        from semantic_classifier import CHANNEL_NAMES
        for path_key, info in path_stats.items():
            remote_ip = info.dst_ip_port[0] if info.src_ip_port[0] == device_ip else info.src_ip_port[0]
            ch_id, ch_src = ip_channel_map.get(remote_ip, (None, "unmapped"))
            info.channel_id = ch_id
            info.channel_name = CHANNEL_NAMES.get(ch_id, "unmapped") if ch_id is not None else "unmapped"
            info.channel_source = ch_src

    # Phase 5: 生成输出记录（复用 Phase 2 缓存的 path_keys）
    results = []
    for i, d in enumerate(udp_datagrams):
        path_key = path_keys[i]
        info = path_stats.get(path_key)
        pid = info.path_id if info else -1
        # direction: +1 = 下行（到设备），-1 = 上行（从设备）
        direction = -1 if d.src_ip == device_ip else 1
        signed_length = direction * (d.udp_payload_length or 0)

        results.append({
            "frame_number": d.frame_number,
            "timestamp": d.timestamp,
            "direction": direction,
            "udp_payload_length": d.udp_payload_length or 0,
            "signed_udp_payload_length": signed_length,
            "path_id": pid,
            "channel_id": info.channel_id if info else None,
            "channel_name": info.channel_name if info else "",
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
            "src_port": d.src_port,
            "dst_port": d.dst_port,
            "quic_header_form": d.quic_header_form,
            "quic_dcid": d.quic_dcid,
            "quic_scid": d.quic_scid,
            "quic_version": d.quic_version,
            "is_fragmented": d.is_fragmented,
            "is_truncated": d.is_truncated,
        })

    logger.info(
        f"Tracked {len(path_stats)} paths from {len(udp_datagrams)} datagrams, "
        f"DCID mapping: {len(cid_to_path)} entries"
    )
    return results, path_stats


def _make_path_key(src_ip, src_port, dst_ip, dst_port) -> frozenset:
    """创建双向规范的五元组键（方向无关）。"""
    return frozenset([(src_ip, src_port), (dst_ip, dst_port)])


def _assign_path_ids(
    path_stats: Dict[frozenset, PathInfo],
    strategy: str,
    top_k: int,
    merge_other: bool,
):
    """根据选择策略分配 path_id。"""
    if strategy == "video_cdn_only":
        cdn_paths = [(k, v) for k, v in path_stats.items() if v.is_video_cdn]
        cdn_paths.sort(key=lambda x: -x[1].packet_count)
        for i, (_, info) in enumerate(cdn_paths):
            info.path_id = min(i, top_k - 1) if merge_other and i >= top_k else i
        for k, v in path_stats.items():
            if not v.is_video_cdn:
                v.path_id = -1
    else:
        # "all" 或 "top_k"
        sorted_paths = sorted(path_stats.items(), key=lambda x: -x[1].packet_count)
        for i, (_, info) in enumerate(sorted_paths):
            if strategy == "top_k" and merge_other and i >= top_k:
                info.path_id = top_k  # "other" 桶
            else:
                info.path_id = i


