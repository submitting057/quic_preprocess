"""合并 Step 1 (quality_check) + Step 2 (filter) + Step 3 (extract) 为单次 PCAP 遍历。

原始流程：
  Step 1: 遍历原始 PCAP → SHA-256 + 包统计 (遍历1)
  Step 2: 遍历原始 PCAP → 过滤 QUIC/DNS → 写中间 PCAP (遍历2 + 磁盘写入)
  Step 3: 遍历中间 PCAP → QUIC/DNS 字段提取 (遍历3 + 磁盘读取)

优化后流程：
  一次遍历原始 PCAP，同时完成：
    - SHA-256 哈希（需要完整文件字节流，与 dpkt 遍历并行进行）
    - 包统计（计数、时间戳、snaplen）
    - QUIC/DNS 过滤 + 字段提取（跳过中间 PCAP 的磁盘写入/读取）

数据流图：
  原始 PCAP ──→ 单次遍历 ──┬── QualityResult (SHA-256 + 包统计)
                            ├── List[DatagramRecord] (QUIC 字段)
                            └── List[DNSRecord] (DNS A 记录)
"""

import hashlib
import io
import logging
import socket
from pathlib import Path
from typing import Tuple

import dpkt

from quality_check import QualityResult
from extract import DatagramRecord, DNSRecord, parse_quic_long_header, parse_quic_short_header

logger = logging.getLogger(__name__)

# 预缓存 socket 函数，避免每次调用时的属性查找
_inet_ntoa = socket.inet_ntoa
_inet_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6


def fast_scan(
    pcap_path: Path,
    quic_ports: set = None,
    mtu_threshold: int = 1514,
    max_snaplen: int = 262144,
) -> Tuple[QualityResult, list, list]:
    """
    单次遍历完成 Step 1 + Step 2 + Step 3。

    SHA-256 与 PCAP 遍历并行：先将整个文件读入内存计算哈希，
    然后在内存字节流上做 dpkt 遍历（避免二次磁盘 I/O）。

    Args:
        pcap_path: 输入 PCAP 文件路径
        quic_ports: QUIC 候选端口集合，默认 {443}
        mtu_threshold: MTU 阈值（当前未使用，保留兼容）
        max_snaplen: 最大 snaplen（当前未使用，保留兼容）

    Returns:
        (QualityResult, List[DatagramRecord], List[DNSRecord])
    """
    if quic_ports is None:
        quic_ports = {443}

    result = QualityResult(pcap_path=str(pcap_path))
    datagrams = []
    dns_records = []

    # ── Phase 1: 读取文件到内存 + 计算 SHA-256 ──────────────────
    try:
        with open(pcap_path, 'rb') as f:
            file_bytes = f.read()
    except Exception as e:
        result.status = "error"
        result.notes.append(f"Failed to read file: {e}")
        return result, datagrams, dns_records

    # SHA-256（在完整字节上计算，一次性）
    result.sha256 = hashlib.sha256(file_bytes).hexdigest()

    # ── Phase 2: 检测文件格式 ────────────────────────────────────
    magic = file_bytes[:4]
    is_pcapng = (magic == b"\x0a\x0d\x0d\x0a")

    if magic == b"\xd4\xc3\xb2\xa1":
        result.file_type = "pcap"
    elif is_pcapng:
        result.file_type = "pcapng"
    else:
        result.file_type = "unknown"
        result.status = "error"
        result.notes.append(f"Unknown PCAP format: {magic.hex()}")
        return result, datagrams, dns_records

    # ── Phase 3: 单次遍历 ────────────────────────────────────────
    f_mem = io.BytesIO(file_bytes)

    try:
        if is_pcapng:
            reader = dpkt.pcapng.Reader(f_mem)
        else:
            reader = dpkt.pcap.Reader(f_mem)
    except Exception as e:
        result.status = "error"
        result.notes.append(f"Failed to create PCAP reader: {e}")
        return result, datagrams, dns_records

    # snaplen
    result.snaplen = getattr(reader, 'snaplen', 0)

    # snaplen 检查：仅当 snaplen 小于常见 MTU（1500 字节）时才警告
    if result.snaplen > 0 and result.snaplen < 1500:
        result.notes.append(f"Small snaplen ({result.snaplen}), packets may be truncated")
        if result.status == "ok":
            result.status = "warning"

    # DNS 域名去重映射（比线性搜索更高效）
    dns_domain_map = {}  # domain -> DNSRecord

    # 时间戳顺序检查
    prev_ts = None
    total_bytes = 0
    timestamp_order_violations = 0
    frame_number = 0

    # 预绑定常用类型用于 isinstance 快速路径
    _IP = dpkt.ip.IP
    _IP6 = dpkt.ip6.IP6
    _UDP = dpkt.udp.UDP
    _Ethernet = dpkt.ethernet.Ethernet

    for ts, buf in reader:
        # ── Step 1: 包统计 ────────────────────────────────────────
        result.packet_count += 1
        total_bytes += len(buf)

        if result.packet_count == 1:
            result.first_timestamp = ts
        result.last_timestamp = ts

        if prev_ts is not None and ts < prev_ts:
            timestamp_order_violations += 1
        prev_ts = ts

        # ── Step 2+3: 解析 + 过滤 + 提取 ──────────────────────────
        frame_number += 1

        try:
            eth = _Ethernet(buf)
        except Exception:
            continue

        # 提取 IP 层
        ip = eth.data
        if isinstance(ip, _IP):
            pass
        elif isinstance(ip, _IP6):
            pass
        else:
            continue

        # 检查是否 UDP
        if not isinstance(ip.data, _UDP):
            continue

        udp = ip.data

        # ── IP 地址转换 ───────────────────────────────────────────
        if isinstance(ip, _IP):
            src_ip = _inet_ntoa(ip.src)
            dst_ip = _inet_ntoa(ip.dst)
        else:
            try:
                src_ip = _inet_ntop(_AF_INET6, ip.src)
            except (OSError, ValueError):
                src_ip = str(ip.src)
            try:
                dst_ip = _inet_ntop(_AF_INET6, ip.dst)
            except (OSError, ValueError):
                dst_ip = str(ip.dst)

        src_port = udp.sport
        dst_port = udp.dport
        udp_payload = bytes(udp.data) if udp.data else b""
        udp_payload_length = len(udp_payload)
        udp_length = udp_payload_length + 8

        # IP 分片标志
        ip_flags_mf = False
        ip_frag_offset = 0
        if isinstance(ip, _IP):
            ip_flags_mf = bool(ip.mf)
            ip_frag_offset = ip.offset

        is_fragmented = ip_flags_mf or ip_frag_offset > 0

        # ── DNS 检测 + 提取 ───────────────────────────────────────
        # 仅通过端口检测：DoQ 载荷被 QUIC 加密，dpkt 无法解析
        _DNS_PORTS = {53, 5353, 5300}
        is_dns = (src_port in _DNS_PORTS or dst_port in _DNS_PORTS)

        if is_dns:
            _extract_dns_inline(udp, frame_number, ts, dns_records, dns_domain_map)

        # ── QUIC 候选检测 + 提取 ──────────────────────────────────
        is_quic_candidate = (src_port in quic_ports or dst_port in quic_ports)
        if not is_quic_candidate and udp_payload_length > 0:
            if parse_quic_long_header(udp_payload) is not None:
                is_quic_candidate = True

        if is_quic_candidate and udp_payload_length > 0:
            # QUIC 解析
            quic_header_form = None
            quic_dcid = None
            quic_scid = None
            quic_version = None

            quic_info = parse_quic_long_header(udp_payload)
            if quic_info:
                quic_header_form = quic_info["header_form"]
                quic_dcid = quic_info["dcid"]
                quic_scid = quic_info["scid"]
                quic_version = quic_info["version"]
            else:
                quic_info = parse_quic_short_header(udp_payload)
                if quic_info:
                    quic_header_form = quic_info["header_form"]
                    quic_dcid = quic_info["dcid"]
                    quic_scid = quic_info["scid"]
                    quic_version = quic_info["version"]

            datagrams.append(DatagramRecord(
                frame_number=frame_number,
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                udp_length=udp_length,
                udp_payload_length=udp_payload_length,
                ip_flags_mf=ip_flags_mf,
                ip_frag_offset=ip_frag_offset,
                quic_header_form=quic_header_form,
                quic_dcid=quic_dcid,
                quic_scid=quic_scid,
                quic_version=quic_version,
                is_fragmented=is_fragmented,
            ))

    # ── Step 1 后处理 ─────────────────────────────────────────────
    if result.packet_count > 0:
        result.capture_duration_s = result.last_timestamp - result.first_timestamp
        result.avg_packet_size = total_bytes / result.packet_count
        result.avg_packet_rate = (
            result.packet_count / result.capture_duration_s
            if result.capture_duration_s > 0 else 0.0
        )

    if timestamp_order_violations > 0:
        result.timestamp_ordered = False
        result.notes.append(
            f"Non-monotonic timestamps: {timestamp_order_violations} violations"
        )
        if result.status == "ok":
            result.status = "warning"

    logger.info(
        f"Fast scan: {pcap_path.name} -> quality={result.status} "
        f"({result.packet_count} pkts), {len(datagrams)} QUIC datagrams, "
        f"{len(dns_records)} DNS records"
    )

    return result, datagrams, dns_records


def _extract_dns_inline(udp, frame_number: int, ts: float,
                        dns_records: list, dns_domain_map: dict):
    """内联 DNS A 记录提取。"""
    try:
        dns_obj = dpkt.dns.DNS(udp.data)
    except Exception:
        return

    # 仅处理 Response（QR=1）且有 Answer 的消息
    if not (dns_obj.qr == 1 and dns_obj.an):
        return

    for q in dns_obj.an:
        if q.type != dpkt.dns.DNS_A:
            continue
        domain = q.name
        ip_str = ""
        if hasattr(q, 'rdata'):
            if isinstance(q.rdata, bytes):
                try:
                    ip_str = _inet_ntoa(q.rdata)
                except (OSError, ValueError):
                    try:
                        ip_str = _inet_ntop(_AF_INET6, q.rdata)
                    except (OSError, ValueError):
                        ip_str = str(q.rdata)
            else:
                ip_str = str(q.rdata)

        if not ip_str:
            continue

        if domain in dns_domain_map:
            if ip_str not in dns_domain_map[domain].answer_ips:
                dns_domain_map[domain].answer_ips.append(ip_str)
        else:
            record = DNSRecord(
                frame_number=frame_number,
                timestamp=ts,
                query_domain=domain,
                answer_ips=[ip_str],
            )
            dns_domain_map[domain] = record
            dns_records.append(record)
