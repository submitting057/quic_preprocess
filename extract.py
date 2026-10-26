"""Step 3: QUIC/DNS 字段提取。

使用 dpkt 读取 PCAP，手写 QUIC 长头部解析器提取 header_form/dcid/scid/version，
使用 dpkt 内置 DNS 解析器提取 A 记录。

数据类 DatagramRecord / DNSRecord 同时被下游 video_locator、connection_tracker、
event_generator 等模块引用。
"""

import logging
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

import dpkt

logger = logging.getLogger(__name__)


# ── 数据类 ────────────────────────────────────────────────────

@dataclass
class DatagramRecord:
    """单个 UDP 数据报的提取字段。"""
    frame_number: int
    timestamp: float          # epoch seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    udp_length: int           # UDP 头 + 载荷总长度
    udp_payload_length: int   # UDP 载荷长度 = udp_length - 8
    ip_flags_mf: bool         # IP More Fragments flag
    ip_frag_offset: int       # IP fragment offset
    quic_header_form: Optional[int]  # 1=Long, 0=Short, None=非QUIC
    quic_dcid: Optional[str]         # hex string
    quic_scid: Optional[str]         # hex string
    quic_version: Optional[str]      # hex string (e.g. "00000001")
    is_fragmented: bool = False
    is_truncated: bool = False

    @property
    def has_udp(self) -> bool:
        return self.udp_payload_length > 0


@dataclass
class DNSRecord:
    """DNS A 记录（域名 → IP 列表）。"""
    frame_number: int
    timestamp: float
    query_domain: str
    answer_ips: List[str]


# ── QUIC 长头部解析器 ─────────────────────────────────────────

# 已知 QUIC 版本白名单，用于过滤非 QUIC 载荷（如 DNS）的误判
# 参考: https://www.iana.org/assignments/quic/quic.xhtml
_KNOWN_QUIC_VERSIONS = {
    0x00000001,  # QUIC v1 (RFC 9000)
    0x00000000,  # Version Negotiation (version 字段为 0 表示协商)
    0x6b3343cf,  # QUIC v2 (RFC 9369)
    # Google QUIC (gQUIC) — 已知版本号
    0x51303530,  # Q050
    0x51303430,  # Q046
    0x51303330,  # Q043
    0x51303230,  # Q042
    0x51303130,  # Q041
    0x51303030,  # Q040
    0x51303930,  # Q039
    0x51303830,  # Q038
    0x51303730,  # Q037
    0x51303630,  # Q036
    0x51303530,  # Q035
}


def parse_quic_long_header(udp_payload: bytes) -> Optional[dict]:
    """
    手写 IETF QUIC 长头部解析器（RFC 9000 Section 17.2）。
    仅解析长头部（Initial / 0-RTT / Handshake / Retry），不解析短头部。

    通过 version 白名单过滤非 QUIC 载荷（如 DNS 查询/响应）的误判。

    Returns:
        dict with keys: header_form, version, dcid, scid
        None if not a valid QUIC long header
    """
    if len(udp_payload) < 7:
        return None

    first_byte = udp_payload[0]

    # 长头部标志: bit 7 = 1
    if (first_byte & 0x80) == 0:
        return None  # 短头部

    # Fixed bit: bit 6 应为 1（IETF QUIC），0 可能是 Version Negotiation
    if (first_byte & 0x40) == 0:
        return None

    # Version: bytes 1-4
    version = int.from_bytes(udp_payload[1:5], 'big')

    # Version 白名单校验：过滤非 QUIC 载荷误判（如 DNS 查询/响应）
    if version not in _KNOWN_QUIC_VERSIONS:
        return None

    # DCID Length: byte 5
    dcid_len = udp_payload[5]
    offset = 6 + dcid_len
    if len(udp_payload) < offset + 1:
        return None

    # SCID Length
    scid_len = udp_payload[offset]
    offset += 1 + scid_len
    if len(udp_payload) < offset:
        return None

    dcid = udp_payload[6:6 + dcid_len].hex() if dcid_len > 0 else ""
    scid = udp_payload[offset - scid_len:offset].hex() if scid_len > 0 else ""

    return {
        "header_form": 1,
        "version": f"{version:08x}",
        "dcid": dcid,
        "scid": scid,
    }


def parse_quic_short_header(udp_payload: bytes) -> Optional[dict]:
    """
    短头部检测（1-RTT）。短头部中 DCID 无法可靠提取（需知道连接的 DCID 长度），
    因此只返回 header_form=0，不返回 dcid/scid。

    Returns:
        dict with keys: header_form=0, version=None, dcid=None, scid=None
        None if not a QUIC short header
    """
    if len(udp_payload) < 1:
        return None

    first_byte = udp_payload[0]

    # 短头部: bit 7 = 0, bit 6 = 1 (Fixed bit)
    if (first_byte & 0x80) != 0:
        return None  # 长头部
    if (first_byte & 0x40) == 0:
        return None  # 非 IETF QUIC

    return {
        "header_form": 0,
        "version": None,
        "dcid": None,
        "scid": None,
    }
