"""Step 6: 特征生成。

将跟踪后的数据报转换为三种结构化表示：
  - 原始事件序列（Scheme A）：每包 [signed_length, global_iat_ms, path_iat_ms, t_rel_ms] + path_id
  - 10ms 时间桶序列（Scheme T10）：每桶 [down_bytes, up_bytes, down_pkt_count, up_pkt_count]
  - 20ms 时间桶序列（Scheme T20）：每桶 [down_bytes, up_bytes, down_pkt_count, up_pkt_count]

时间桶按语义通道（channel_id, 0-4）分维度，同一通道的多条 path 流量合并。
"""

import math
import logging
from typing import Dict, List
from dataclasses import dataclass, field

import numpy as np

from connection_tracker import PathInfo
from semantic_classifier import CHANNEL_NAMES, CHANNEL_OTHER

logger = logging.getLogger(__name__)

N_CHANNELS = 5  # 固定 5 类语义通道


# ── 数据类 ────────────────────────────────────────────────────

@dataclass
class EventSequence:
    """单会话的原始事件序列（Scheme A）。"""
    session_id: str
    video_id: str
    events: np.ndarray   # shape: [N, 4] - [signed_length, global_iat_ms, path_iat_ms, t_rel_ms]
    path_ids: np.ndarray # shape: [N]
    metadata: dict = field(default_factory=dict)


@dataclass
class TimeBinFeature:
    """单尺度时间桶特征（Scheme T10 或 T20）。"""
    session_id: str
    video_id: str
    bin_size_ms: int     # 10 或 20
    bins: np.ndarray     # shape: [5, n_bins, 4] — 按语义通道聚合
    metadata: dict = field(default_factory=dict)


# ── Scheme A: 原始事件序列 ────────────────────────────────────

def generate_event_sequence(
    records: List[dict],
    path_stats: Dict[frozenset, PathInfo],
    video_start: float,
    video_end: float,
    session_id: str = "",
    video_id: str = "",
) -> EventSequence:
    """
    生成原始事件序列。

    每个事件 = [signed_udp_payload_length, global_iat_ms, path_iat_ms, t_rel_ms] + path_id。
    输入 records 应为已过滤到视频区间并按 timestamp 排序的列表（由 pipeline 预处理）。

    Args:
        records: connection_tracker 输出的记录列表（已过滤到视频区间）
        path_stats: 路径统计信息
        video_start: 视频起始时间
        video_end: 视频结束时间
        session_id: 会话 ID
        video_id: 视频 ID

    Returns:
        EventSequence
    """
    if not records:
        return EventSequence(
            session_id=session_id,
            video_id=video_id,
            events=np.zeros((0, 4), dtype=np.float32),
            path_ids=np.zeros(0, dtype=np.int32),
        )

    n = len(records)
    events = np.zeros((n, 4), dtype=np.float32)
    path_ids = np.zeros(n, dtype=np.int32)

    last_ts_per_path: Dict[int, float] = {}
    prev_ts = records[0]["timestamp"]

    for i, r in enumerate(records):
        ts = r["timestamp"]
        signed_len = r["signed_udp_payload_length"]
        pid = r["path_id"]

        global_iat = (ts - prev_ts) * 1000.0 if i > 0 else 0.0

        if pid in last_ts_per_path:
            path_iat = (ts - last_ts_per_path[pid]) * 1000.0
        else:
            path_iat = 0.0

        t_rel = (ts - video_start) * 1000.0

        events[i] = [signed_len, global_iat, path_iat, t_rel]
        path_ids[i] = pid

        last_ts_per_path[pid] = ts
        prev_ts = ts

    return EventSequence(
        session_id=session_id,
        video_id=video_id,
        events=events,
        path_ids=path_ids,
        metadata=_build_channel_metadata(path_stats),
    )


# ── 时间桶特征 ────────────────────────────────────────────────

def generate_time_bins(
    records: List[dict],
    path_stats: Dict[frozenset, PathInfo],
    video_start: float,
    video_end: float,
    session_id: str = "",
    video_id: str = "",
    bin_size_ms: int = 10,
) -> TimeBinFeature:
    """
    生成单尺度时间桶特征（numpy 向量化聚合）。

    每桶 4 维: [down_bytes, up_bytes, down_pkt_count, up_pkt_count]
    按语义通道（channel_id, 0-4）分维度，同一通道的多条 path 流量合并。
    channel_id 为 None 的记录归入 CHANNEL_OTHER (4)。
    输入 records 应为已过滤到视频区间的列表（由 pipeline 预处理）。

    Args:
        records: connection_tracker 输出的记录列表（已过滤到视频区间）
        path_stats: 路径统计信息
        video_start: 视频起始时间
        video_end: 视频结束时间
        session_id: 会话 ID
        video_id: 视频 ID
        bin_size_ms: 桶宽度（毫秒），10 或 20

    Returns:
        TimeBinFeature，bins shape: [5, n_bins, 4]
    """
    if not records:
        return TimeBinFeature(
            session_id=session_id,
            video_id=video_id,
            bin_size_ms=bin_size_ms,
            bins=np.zeros((N_CHANNELS, 0, 4), dtype=np.float32),
        )

    duration_s = video_end - video_start
    if duration_s <= 0:
        duration_s = max(r["timestamp"] for r in records) - min(r["timestamp"] for r in records)
    if duration_s <= 0:
        duration_s = 1.0

    bin_size_s = bin_size_ms / 1000.0
    n_bins = max(int(math.ceil(duration_s / bin_size_s)), 1)

    # 预提取为 numpy 数组，向量化聚合
    ch_ids = np.array([
        r.get("channel_id") if r.get("channel_id") is not None else CHANNEL_OTHER
        for r in records
    ], dtype=np.int32)
    ch_ids = np.clip(ch_ids, 0, N_CHANNELS - 1)

    timestamps = np.array([r["timestamp"] for r in records], dtype=np.float64)
    bin_idxs = np.clip(((timestamps - video_start) / bin_size_s).astype(np.int32), 0, n_bins - 1)

    directions = np.array([r["direction"] for r in records], dtype=np.int32)
    payloads = np.array([r["udp_payload_length"] for r in records], dtype=np.float32)

    bins = np.zeros((N_CHANNELS, n_bins, 4), dtype=np.float32)

    # 下行 (direction > 0)
    down_mask = directions > 0
    if np.any(down_mask):
        np.add.at(bins, (ch_ids[down_mask], bin_idxs[down_mask], 0), payloads[down_mask])
        np.add.at(bins, (ch_ids[down_mask], bin_idxs[down_mask], 2), 1.0)

    # 上行 (direction <= 0)
    up_mask = ~down_mask
    if np.any(up_mask):
        np.add.at(bins, (ch_ids[up_mask], bin_idxs[up_mask], 1), payloads[up_mask])
        np.add.at(bins, (ch_ids[up_mask], bin_idxs[up_mask], 3), 1.0)

    return TimeBinFeature(
        session_id=session_id,
        video_id=video_id,
        bin_size_ms=bin_size_ms,
        bins=bins,
        metadata=_build_channel_metadata(path_stats),
    )


# ── 辅助函数 ──────────────────────────────────────────────────

def _build_channel_metadata(path_stats) -> dict:
    """从 path_stats 构建通道标签元数据。

    Returns:
        {"channel_labels": {path_id: {"channel_id": int, "channel_name": str, "channel_source": str}}}
    """
    labels = {}
    for info in path_stats.values():
        if info.channel_id is not None:
            labels[info.path_id] = {
                "channel_id": info.channel_id,
                "channel_name": info.channel_name,
                "channel_source": info.channel_source,
            }
    return {"channel_labels": labels} if labels else {}
