"""流程编排：Click-and-Block 预处理流水线。

定位用户点击进视频的初始阶段，生成三种特征表示。

输出目录结构:
  OUTPUT_DIR/dataset/
    features/
      event_sequences/{video_id}/{session_id}.npz
      time_bins_10ms/{video_id}/{session_id}.npz
      time_bins_20ms/{video_id}/{session_id}.npz
    quality/
      excluded_{batch_id}.json
      summary_{batch_id}.json
    manifests/
      sessions_{batch_id}.json
    provenance/
      parser_config_{batch_id}.json
      preprocessing_version.json

  聚合后（运行 aggregate.py）额外生成:
    manifests/sessions.json
    quality/excluded_sessions.json
    quality/summary.json
"""

import json
import logging
import traceback
from pathlib import Path
from typing import List, Dict
from datetime import datetime

import numpy as np

from quality_check import QualityResult
from fast_scan import fast_scan
from video_locator import locate_video_segment, VideoInterval
from connection_tracker import track_connections
from semantic_classifier import SemanticClassifier, extract_sni_mapping, build_dns_mapping, CHANNEL_NAMES
from event_generator import (
    generate_event_sequence, generate_time_bins,
    EventSequence, TimeBinFeature,
)
from session_builder import build_session, discover_pcaps, SessionRecord

logger = logging.getLogger(__name__)

__version__ = "3.5.0"

# ── 失败原因常量 ──────────────────────────────────────────────

FAILURE_NO_METADATA = "no_metadata"
FAILURE_METADATA_PARSE_ERROR = "metadata_parse_error"
FAILURE_QUALITY_CHECK_ERROR = "quality_check_error"
FAILURE_NO_QUIC_TRAFFIC = "no_quic_traffic"
FAILURE_NO_DATAGRAMS = "no_datagrams"
FAILURE_SHORT_VIDEO = "short_video"
FAILURE_LONG_VIDEO = "long_video"
FAILURE_NO_MARKER = "no_marker"
FAILURE_NO_PLAY_SEGMENT = "no_play_segment"
FAILURE_PROCESSING_EXCEPTION = "processing_exception"
FAILURE_UNMAPPED_LARGE_IP = "unmapped_large_ip"


# ── 流水线配置 ────────────────────────────────────────────────

class PipelineConfig:
    """流水线配置，所有参数集中管理。"""

    def __init__(self, **kwargs):
        # 过滤
        self.quic_ports = kwargs.get("quic_ports", {443})
        # 视频 CDN（仅用于记录，不参与定位）
        self.video_cdn_patterns = kwargs.get("video_cdn_patterns", ["googlevideo.com"])
        # click-and-block 定位参数（滑动窗口语义）
        self.play_window_bins = kwargs.get("play_window_bins", 10)
        self.play_threshold_bytes = kwargs.get("play_threshold_bytes", 1000)
        self.play_min_count = kwargs.get("play_min_count", 5)
        self.zero_window_bins = kwargs.get("zero_window_bins", 10)
        self.zero_min_count = kwargs.get("zero_min_count", 5)
        self.zero_threshold_bytes = kwargs.get("zero_threshold_bytes", 10)
        self.fallback_window_bins = kwargs.get("fallback_window_bins", 15)
        self.fallback_min_count = kwargs.get("fallback_min_count", 10)
        self.search_window_s = kwargs.get("search_window_s", 10.0)
        self.search_window_start_offset_s = kwargs.get("search_window_start_offset_s", 3.0)
        self.search_window_ios_s = kwargs.get("search_window_ios_s", 10.0)
        self.search_window_windows_s = kwargs.get("search_window_windows_s", 10.0)
        self.search_window_windows_start_offset_s = kwargs.get("search_window_windows_start_offset_s", 0.0)
        self.locator_bin_size_s = kwargs.get("locator_bin_size_s", 0.1)  # 100ms
        # 视频时长范围（秒），超出范围排除
        self.min_video_duration_s = kwargs.get("min_video_duration_s", 1)
        self.max_video_duration_s = kwargs.get("max_video_duration_s", 5)
        # 段内 video_cdn 下行最少字节数，低于此值视为非视频段
        self.min_cdn_bytes = kwargs.get("min_cdn_bytes", 50 * 1024)  # 50KB
        # 连接跟踪
        self.path_selection = kwargs.get("path_selection", "all")
        self.top_k = kwargs.get("top_k", 4)
        self.merge_other = kwargs.get("merge_other", False)
        # 质量
        self.mtu_threshold = kwargs.get("mtu_threshold", 1514)
        self.max_snaplen = kwargs.get("max_snaplen", 262144)


# ── 单 PCAP 处理 ──────────────────────────────────────────────

def process_single_pcap(
    pcap_path: Path,
    output_dir: Path,
    config: PipelineConfig,
) -> tuple:
    """
    处理单个 PCAP 文件，执行 Click-and-Block 流水线。

    Args:
        pcap_path: PCAP 文件路径
        output_dir: 输出根目录
        config: 流水线配置

    Returns:
        (SessionRecord | None, failure_reason: str | None)
    """
    from session_builder import find_companion_files, parse_metadata, parse_pcap_filename

    # ── Step 0: 查找伴随文件 + 解析文件名 ──────────────────────
    companions = find_companion_files(pcap_path)
    name_info = parse_pcap_filename(pcap_path)

    if not companions["metadata"]:
        logger.warning(f"No .metadata found for {pcap_path.name}, skipping")
        return None, FAILURE_NO_METADATA

    meta = parse_metadata(companions["metadata"])
    if not meta:
        logger.warning(f"Failed to parse metadata for {pcap_path.name}")
        return None, FAILURE_METADATA_PARSE_ERROR

    device_ip = meta.get("device_ip", "")
    device_ip_inferred = False
    if not device_ip:
        logger.warning(f"device_ip is empty in metadata for {pcap_path.name}, "
                       f"will be auto-inferred from traffic by video_locator")
        device_ip_inferred = True
    raw_offset = meta.get("phone_to_server_time_offset", 0)
    try:
        time_offset = int(raw_offset)
    except (ValueError, TypeError):
        time_offset = 0

    # ── Step 1+2+3: 合并单次遍历（质量检查 + 过滤 + 提取） ────
    quality_result, datagrams, dns_records = fast_scan(
        pcap_path, config.quic_ports, config.mtu_threshold, config.max_snaplen,
    )

    if quality_result.status == "error":
        logger.warning(f"Quality check failed for {pcap_path.name}: {quality_result.notes}")
        return None, FAILURE_QUALITY_CHECK_ERROR

    pcap_start_time = quality_result.first_timestamp
    pcap_end_time = quality_result.last_timestamp
    total_packets = quality_result.packet_count

    if not datagrams and not dns_records:
        logger.warning(f"No QUIC/DNS traffic in {pcap_path.name}")
        return None, FAILURE_NO_QUIC_TRAFFIC

    if not datagrams:
        logger.warning(f"No datagrams extracted from {pcap_path.name}")
        return None, FAILURE_NO_DATAGRAMS

    try:

        # ── Step 4: 视频段定位（Click-and-Block） ────────────────
        operate_log_path = companions["operate_log"]
        video_interval = locate_video_segment(
            datagrams=datagrams,
            dns_records=dns_records,
            pcap_path=pcap_path,
            device_ip=device_ip,
            operate_log_path=operate_log_path,
            phone_to_server_time_offset=time_offset,
            video_cdn_patterns=config.video_cdn_patterns,
            pcap_start_time=pcap_start_time,
            pcap_end_time=pcap_end_time,
            play_window_bins=config.play_window_bins,
            play_threshold_bytes=config.play_threshold_bytes,
            play_min_count=config.play_min_count,
            zero_window_bins=config.zero_window_bins,
            zero_min_count=config.zero_min_count,
            zero_threshold_bytes=config.zero_threshold_bytes,
            fallback_window_bins=config.fallback_window_bins,
            fallback_min_count=config.fallback_min_count,
            search_window_s=config.search_window_s,
            search_window_start_offset_s=config.search_window_start_offset_s,
            search_window_ios_s=config.search_window_ios_s,
            search_window_windows_s=config.search_window_windows_s,
            search_window_windows_start_offset_s=config.search_window_windows_start_offset_s,
            bin_size_s=config.locator_bin_size_s,
            min_cdn_bytes=config.min_cdn_bytes,
        )

        # 优先和次优方案均未找到播放段 → 记录质量问题，不回退到完整PCAP
        # 必须在 duration 检查之前，否则 confidence=none 时 start/end 为 0
        # 会导致 duration=0 返回 SHORT_VIDEO 而非真实失败原因
        if video_interval.confidence == "none":
            logger.warning(
                f"No play segment detected for {pcap_path.name}: "
                f"primary(10-bin window ≥5×≥1000B) and "
                f"fallback(15-bin window ≥10×>0B) both failed"
            )
            return None, FAILURE_NO_PLAY_SEGMENT

        # 视频时长范围检查（1s < duration < 5s，不含边界）
        video_duration = video_interval.end_time - video_interval.start_time
        if video_duration <= config.min_video_duration_s:
            logger.warning(
                f"Video duration too short for {pcap_path.name}: "
                f"{video_duration:.2f}s <= {config.min_video_duration_s}s threshold"
            )
            return None, FAILURE_SHORT_VIDEO
        if video_duration >= config.max_video_duration_s:
            logger.warning(
                f"Video duration too long for {pcap_path.name}: "
                f"{video_duration:.2f}s >= {config.max_video_duration_s}s threshold"
            )
            return None, FAILURE_LONG_VIDEO

        # 标记点缺失时给出低置信度提示
        if video_interval.confidence == "low" and "marker_time" not in video_interval.notes:
            logger.warning(f"No marker found for {pcap_path.name}, result unreliable")
            return None, FAILURE_NO_MARKER

        # ── Step 4.5: 语义通道分类 ───────────────────────────────
        # Tier 1: SNI 提取（从 QUIC Initial ClientHello）
        sni_map = extract_sni_mapping(pcap_path, sha256=quality_result.sha256)
        # Tier 2: DNS 映射（复用 fast_scan 已提取的 dns_records）
        dns_map = build_dns_mapping(dns_records)
        # 构建分类器
        classifier = SemanticClassifier()
        classifier.build(sni_map, dns_map)

        if classifier.anomalies:
            for a in classifier.anomalies:
                logger.warning(
                    f"SNI-DNS mismatch: {a['ip']} "
                    f"SNI={a['sni_channels']} DNS={a['dns_channels']} "
                    f"=> {CHANNEL_NAMES.get(a['resolved_channel'], '?')}"
                )

        # ── Step 5: 连接跟踪 ─────────────────────────────────────
        # 使用 video_locator 解析后的 device_ip（可能由推断得到）
        effective_device_ip = video_interval.resolved_device_ip or device_ip

        # 在 track_connections 之前，对所有远程 IP 完成分类（含 Tier 3 延迟匹配），
        # 确保 ip_channel_map 完整，避免通道标签未回写至连接记录
        _pre_classify_all_ips(datagrams, effective_device_ip, classifier)

        conn_records, path_stats = track_connections(
            datagrams=datagrams,
            device_ip=effective_device_ip,
            video_cdn_ips=video_interval.video_cdn_ips,
            path_selection=config.path_selection,
            top_k=config.top_k,
            merge_other=config.merge_other,
            ip_channel_map=classifier.ip_channel,
        )

        # 处理仍未分类 IP（5 层均未命中）
        # 小流量（≤50 包且 ≤10KB）：丢弃，不报错
        # 大流量（>50 包或 >10KB）：记录质量问题，排除整个样本
        UNMAPPED_PKT_THRESHOLD = 50
        UNMAPPED_BYTES_THRESHOLD = 10 * 1024  # 10KB

        small_noise_path_ids = set()
        has_large_unmapped = False

        for path_info in path_stats.values():
            if path_info.channel_id is None:
                remote_ip = (path_info.dst_ip_port[0]
                             if path_info.src_ip_port[0] == effective_device_ip
                             else path_info.src_ip_port[0])
                if (path_info.packet_count <= UNMAPPED_PKT_THRESHOLD
                        and path_info.total_bytes <= UNMAPPED_BYTES_THRESHOLD):
                    # 小流量未映射：丢弃，不报错
                    small_noise_path_ids.add(path_info.path_id)
                    logger.debug(
                        f"Dropping small unmapped IP: {remote_ip} "
                        f"pkts={path_info.packet_count} bytes={path_info.total_bytes}"
                    )
                else:
                    # 大流量未映射：记录质量问题
                    classifier.classify_with_quality(
                        remote_ip, path_info.packet_count, path_info.total_bytes,
                    )
                    has_large_unmapped = True

        if has_large_unmapped:
            for q in classifier.quality_issues:
                logger.warning(
                    f"Unmapped IP (large): {q['ip']} pkts={q['pkts']} "
                    f"bytes={q['bytes']} avg={q['avg_pkt_size']}B — sample excluded"
                )
            return None, FAILURE_UNMAPPED_LARGE_IP

        # 过滤掉小流量未映射 IP 的记录
        if small_noise_path_ids:
            conn_records = [
                r for r in conn_records if r.get("path_id") not in small_noise_path_ids
            ]

        # 视频区间数据报计数 + 预过滤排序（合并为一次遍历）
        vs, ve = video_interval.start_time, video_interval.end_time
        video_records = sorted(
            [r for r in conn_records if vs <= r["timestamp"] <= ve],
            key=lambda r: r["timestamp"],
        )
        video_datagram_count = len(video_records)

        features_dir = output_dir / "dataset" / "features"
        session_info = _build_session_id(name_info, pcap_path)
        video_id = name_info["video_id"]

        # (1) 原始事件序列
        event_seq = generate_event_sequence(
            records=video_records,
            path_stats=path_stats,
            video_start=vs,
            video_end=ve,
            session_id=session_info,
            video_id=video_id,
        )
        _save_event_sequence(event_seq, features_dir / "event_sequences")

        # (2) 10ms 时间桶
        t10 = generate_time_bins(
            records=video_records,
            path_stats=path_stats,
            video_start=vs,
            video_end=ve,
            session_id=session_info,
            video_id=video_id,
            bin_size_ms=10,
        )
        _save_time_bins(t10, features_dir / "time_bins_10ms")

        # (3) 20ms 时间桶
        t20 = generate_time_bins(
            records=video_records,
            path_stats=path_stats,
            video_start=vs,
            video_end=ve,
            session_id=session_info,
            video_id=video_id,
            bin_size_ms=20,
        )
        _save_time_bins(t20, features_dir / "time_bins_20ms")

        # ── Step 7: 会话构建 ─────────────────────────────────────
        quality_notes_list = list(quality_result.notes) if quality_result.notes else []
        if device_ip_inferred:
            quality_notes_list.append("device_ip_inferred: metadata device_ip was empty, auto-inferred from traffic")
        if small_noise_path_ids:
            quality_notes_list.append(
                f"dropped_small_unmapped: {len(small_noise_path_ids)} paths "
                f"(≤50 pkts and ≤10KB, not classified by any tier)"
            )
        if classifier.ip_attributions:
            owners = sorted(set(a.owner for a in classifier.ip_attributions.values()))
            quality_notes_list.append(
                f"ip_attributed: {len(classifier.ip_attributions)} IPs "
                f"identified by Tier 5 CIDR ({', '.join(owners)})"
            )
        if classifier.anomalies:
            quality_notes_list.append(
                f"sni_dns_anomalies: {len(classifier.anomalies)} SNI-DNS mismatches"
            )
        session = build_session(
            pcap_path=pcap_path,
            quality_status=quality_result.status if not device_ip_inferred else "warning",
            quality_notes="; ".join(quality_notes_list),
            video_interval=video_interval,
            datagram_count=len(datagrams),
            video_datagram_count=video_datagram_count,
            total_packets=total_packets,
            pre_companions=companions,
            pre_meta=meta,
            pre_name_info=name_info,
            pre_session_id=session_info,
        )
        # 使用 video_locator 解析后的 device_ip（可能由推断得到）
        if effective_device_ip:
            session.device_ip = effective_device_ip
        session.pcap_sha256 = quality_result.sha256
        session.capture_duration_s = quality_result.capture_duration_s

        return session, None

    except Exception as e:
        logger.error(f"Processing exception for {pcap_path.name}: {e}\n{traceback.format_exc()}")
        return None, FAILURE_PROCESSING_EXCEPTION


# ── 批处理 ────────────────────────────────────────────────────

def run_batch(input_dir: Path, output_dir: Path, config: PipelineConfig = None,
              max_workers: int = 0):
    """
    批量处理 PCAP 文件（支持并行）。

    Args:
        input_dir: 输入目录（递归查找 .pcap）
        output_dir: 输出根目录
        config: 流水线配置
        max_workers: 并行进程数，0=串行，>0=并行（ProcessPoolExecutor）
    """
    if config is None:
        config = PipelineConfig()

    output_dir = Path(output_dir)
    input_dir = Path(input_dir)

    # 确保输出目录存在
    for subdir in ["dataset/features/event_sequences",
                   "dataset/features/time_bins_10ms",
                   "dataset/features/time_bins_20ms",
                   "dataset/quality",
                   "dataset/manifests",
                   "dataset/provenance"]:
        (output_dir / subdir).mkdir(parents=True, exist_ok=True)

    # 发现所有 PCAP
    pcaps = discover_pcaps(input_dir)
    if not pcaps:
        logger.warning(f"No .pcap files found in {input_dir}")
        return

    logger.info(f"Found {len(pcaps)} PCAP files to process")

    sessions = []
    excluded = []

    if max_workers > 0:
        from concurrent.futures import ProcessPoolExecutor, as_completed

        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(process_single_pcap, p, output_dir, config): p
                for p in pcaps
            }
            for future in as_completed(futures):
                pcap_path = futures[future]
                try:
                    session, failure_reason = future.result()
                    if session:
                        sessions.append(session)
                        logger.info(f"  -> OK: {session.session_id}")
                    else:
                        excluded.append({
                            "pcap_path": str(pcap_path),
                            "reason": failure_reason or "unknown",
                        })
                        logger.info(f"  -> EXCLUDED: {failure_reason}")
                except Exception as e:
                    logger.error(f"  -> EXCEPTION: {e}\n{traceback.format_exc()}")
                    excluded.append({
                        "pcap_path": str(pcap_path),
                        "reason": FAILURE_PROCESSING_EXCEPTION,
                        "detail": str(e),
                    })
    else:
        for i, pcap_path in enumerate(pcaps):
            logger.info(f"Processing [{i+1}/{len(pcaps)}]: {pcap_path.name}")

            try:
                session, failure_reason = process_single_pcap(pcap_path, output_dir, config)
                if session:
                    sessions.append(session)
                    logger.info(f"  -> OK: {session.session_id}")
                else:
                    excluded.append({
                        "pcap_path": str(pcap_path),
                        "reason": failure_reason or "unknown",
                    })
                    logger.info(f"  -> EXCLUDED: {failure_reason}")
            except Exception as e:
                logger.error(f"  -> EXCEPTION: {e}\n{traceback.format_exc()}")
                excluded.append({
                    "pcap_path": str(pcap_path),
                    "reason": FAILURE_PROCESSING_EXCEPTION,
                    "detail": str(e),
                })

    # 生成 batch_id
    batch_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 保存 manifests 和 provenance
    _save_manifests(sessions, excluded, output_dir / "dataset", batch_id)
    _save_provenance(config, output_dir / "dataset", batch_id)

    logger.info(
        f"Batch complete: {len(sessions)} sessions processed, "
        f"{len(excluded)} excluded"
    )


# ── 特征保存 ──────────────────────────────────────────────────

def _save_event_sequence(seq: EventSequence, output_dir: Path):
    """保存事件序列为 .npz 文件，按 video_id 分目录。"""
    save_dir = output_dir / seq.video_id if seq.video_id else output_dir
    save_dir.mkdir(parents=True, exist_ok=True)
    path = save_dir / f"{seq.session_id}.npz"
    np.savez(path,
             events=seq.events,
             path_ids=seq.path_ids,
             metadata=json.dumps(seq.metadata))


def _save_time_bins(tb: TimeBinFeature, output_dir: Path):
    """保存时间桶特征为 .npz 文件，按 video_id 分目录。"""
    save_dir = output_dir / tb.video_id if tb.video_id else output_dir
    save_dir.mkdir(parents=True, exist_ok=True)
    path = save_dir / f"{tb.session_id}.npz"
    np.savez(path,
             bins=tb.bins,
             bin_size_ms=tb.bin_size_ms,
             metadata=json.dumps(tb.metadata))


# ── Manifest / Provenance 保存 ────────────────────────────────

def _save_manifests(sessions: List[SessionRecord], excluded: list,
                    dataset_dir: Path, batch_id: str):
    """保存本批次的会话清单和排除列表。"""
    from dataclasses import asdict

    sessions_data = [asdict(s) for s in sessions]

    sessions_path = dataset_dir / "manifests" / f"sessions_{batch_id}.json"
    with open(sessions_path, "w", encoding="utf-8") as f:
        json.dump(sessions_data, f, indent=2, ensure_ascii=False)

    excluded_path = dataset_dir / "quality" / f"excluded_{batch_id}.json"
    with open(excluded_path, "w", encoding="utf-8") as f:
        json.dump(excluded, f, indent=2, ensure_ascii=False)

    all_video_ids = {s.video_id for s in sessions}
    summary = {
        "batch_id": batch_id,
        "total_sessions": len(sessions),
        "total_excluded": len(excluded),
        "unique_videos": len(all_video_ids),
        "processing_time": datetime.now().isoformat(),
    }
    summary_path = dataset_dir / "quality" / f"summary_{batch_id}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


def _save_provenance(config: PipelineConfig, dataset_dir: Path, batch_id: str = ""):
    """保存预处理版本和配置信息。"""
    provenance_dir = dataset_dir / "provenance"

    version_info = {
        "version": __version__,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "changes": [
            "Click-and-Block mode: marker + sliding-window play segment detection",
            "Two-tier detection: primary(10-bin >=5x>=1000B) + fallback(15-bin >=10x>0B)",
            "CDN byte validation: segment must have >=min_cdn_bytes video_cdn downstream",
            "5-tier semantic classification: SNI > DNS > /24 > /16 > CIDR attribution",
            "Three feature representations: event sequence, 10ms bins, 20ms bins",
            "Platform-aware marker extraction (Android/iOS) with search direction",
            "Numpy-vectorized time-bin aggregation, bisect-accelerated bin lookup",
            "Parallel batch processing with ProcessPoolExecutor",
        ],
    }
    with open(provenance_dir / "preprocessing_version.json", "w", encoding="utf-8") as f:
        json.dump(version_info, f, indent=2, ensure_ascii=False)

    parser_config = {
        "batch_id": batch_id,
        "mode": "click_and_block",
        "quic_ports": sorted(config.quic_ports),
        "video_cdn_patterns": config.video_cdn_patterns,
        "play_window_bins": config.play_window_bins,
        "play_threshold_bytes": config.play_threshold_bytes,
        "play_min_count": config.play_min_count,
        "zero_window_bins": config.zero_window_bins,
        "zero_min_count": config.zero_min_count,
        "zero_threshold_bytes": config.zero_threshold_bytes,
        "fallback_window_bins": config.fallback_window_bins,
        "fallback_min_count": config.fallback_min_count,
        "search_window_s": config.search_window_s,
        "search_window_start_offset_s": config.search_window_start_offset_s,
        "search_window_ios_s": config.search_window_ios_s,
        "search_window_windows_s": config.search_window_windows_s,
        "search_window_windows_start_offset_s": config.search_window_windows_start_offset_s,
        "locator_bin_size_s": config.locator_bin_size_s,
        "min_video_duration_s": config.min_video_duration_s,
        "max_video_duration_s": config.max_video_duration_s,
        "min_cdn_bytes": config.min_cdn_bytes,
        "path_selection": config.path_selection,
        "merge_other_paths": config.merge_other,
        "mtu_threshold": config.mtu_threshold,
    }
    config_name = f"parser_config_{batch_id}.json" if batch_id else "parser_config.json"
    with open(provenance_dir / config_name, "w", encoding="utf-8") as f:
        json.dump(parser_config, f, indent=2, ensure_ascii=False)


# ── 辅助函数 ──────────────────────────────────────────────────

def _pre_classify_all_ips(datagrams, device_ip: str, classifier: SemanticClassifier):
    """在 track_connections 之前，对所有远程 IP 完成分类（含 Tier 3 延迟匹配）。

    确保 classifier.ip_channel 包含 datagrams 中出现的所有远程 IP，
    使 track_connections 能直接从 ip_channel_map 获取完整通道标签。
    跳过私有 IP（设备 IP 本身无需分类）。
    """
    from utils import is_private_ip
    for d in datagrams:
        if not d.has_udp:
            continue
        if d.src_ip == device_ip:
            remote_ip = d.dst_ip
        elif d.dst_ip == device_ip:
            remote_ip = d.src_ip
        else:
            # device_ip 未确定时，跳过（无法确定哪侧是远程 IP）
            continue
        if not is_private_ip(remote_ip):
            classifier.classify(remote_ip)


def _build_session_id(name_info: dict, pcap_path: Path) -> str:
    """从已解析的文件名信息生成 session_id（避免重复调用 parse_pcap_filename）。"""
    import re
    m = re.search(r'(\d{8}_\d{6})', pcap_path.stem)
    timestamp = m.group(1) if m else ""
    parts = ["Youtube", name_info["device"], name_info["video_id"], name_info["platform"],
             name_info["network"], name_info["resolution"], name_info["region"], timestamp]
    return "-".join(p for p in parts if p)
