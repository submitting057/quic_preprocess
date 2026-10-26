"""PCAP 质量检查结果数据类。

质量检查逻辑已内联到 fast_scan.py 的单次遍历中，
本模块仅保留 QualityResult 数据类供下游引用。
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class QualityResult:
    """PCAP 质量检查结果。"""
    pcap_path: str
    sha256: str = ""
    # PCAP 元数据
    file_type: str = ""
    link_type: str = ""
    snaplen: int = 0
    packet_count: int = 0
    capture_duration_s: float = 0.0
    interface_count: int = 1
    # 时间戳
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    timestamp_ordered: bool = True
    # 统计
    avg_packet_size: float = 0.0
    avg_packet_rate: float = 0.0
    # 异常标记
    status: str = "ok"  # "ok", "warning", "error"
    notes: list = field(default_factory=list)
