"""Step 4.5: 多路径语义通道分类。

基于 5 层证据为每个远程 IP 分配语义通道标签：
  Tier 1: SNI       — QUIC ClientHello 明文 server_name（最可靠，直接证据）
  Tier 2: DNS       — DNS A 记录映射（直接证据，但可能过期）
  Tier 3: /24 传播   — 同 /24 段已分类 IP 的主导通道（间接证据，精度高）
  Tier 4: /16 传播   — 同 /16 段已分类 IP 的主导通道（间接证据，精度较低）
  Tier 5: CIDR 归属  — 静态 CIDR 规则匹配所有者（仅标 other，最后兜底）

通道定义：
  0 = video_cdn     — *googlevideo*（含 redirector）
  1 = thumbnail      — *ytimg*
  2 = channel_info   — *ggpht*, *googleusercontent*
  3 = api            — *googleapis*, youtube.com, suggestqueries*, *gstatic*, *.google.com
  4 = other          — 其余

层级顺序规则：
  直接证据 (SNI/DNS) > 间接证据 (/24 /16 前缀传播) > 所有者级兜底 (CIDR)
  /24 优先于 /16：/24 段（256 IP）粒度更细，同段大概率同服务；
  /16 段（65536 IP）范围更大，可能跨服务，仅在 /24 无已分类 IP 时使用。
当 5 层均未命中时，记录为质量问题。
"""

import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils import is_private_ip as _is_private_ip
from extract import DNSRecord
from ip_attribution import lookup_attribution, AttributionResult

logger = logging.getLogger(__name__)


# ── 通道常量 ──────────────────────────────────────────────────

CHANNEL_VIDEO_CDN = 0
CHANNEL_THUMBNAIL = 1
CHANNEL_CHANNEL_INFO = 2
CHANNEL_API = 3
CHANNEL_OTHER = 4

CHANNEL_NAMES = {
    0: "video_cdn",
    1: "thumbnail",
    2: "channel_info",
    3: "api",
    4: "other",
}

# 多通道冲突时的优先级（高 → 低）
_CHANNEL_PRIORITY = [0, 1, 3, 2, 4]


# ── 域名分类 ──────────────────────────────────────────────────

def classify_domain(domain: str) -> int:
    """将域名映射到通道 ID。"""
    d = domain.lower().rstrip(".")
    if "googlevideo" in d:
        return CHANNEL_VIDEO_CDN
    if "ytimg" in d:
        return CHANNEL_THUMBNAIL
    if "ggpht" in d or "googleusercontent" in d:
        return CHANNEL_CHANNEL_INFO
    if "googleapis" in d:
        return CHANNEL_API
    if "youtube.com" in d and "googlevideo" not in d:
        return CHANNEL_API
    if "suggestqueries" in d:
        return CHANNEL_API
    if d.endswith("google.com") and "googlevideo" not in d and "googleapis" not in d:
        return CHANNEL_API
    if "gstatic" in d:
        return CHANNEL_API
    if "apple" in d:
        return CHANNEL_OTHER
    return CHANNEL_OTHER


# ── SNI 提取（tshark）─────────────────────────────────────────

import subprocess
import shutil
import os
import json

# SNI 磁盘缓存目录（与 PCAP 同级的 .sni_cache/ 目录）
_SNI_CACHE_DIR = ".sni_cache"


def _find_tshark() -> str:
    """延迟查找 tshark 路径：优先 TSHARK_PATH 环境变量，其次 PATH。

    TSHARK_PATH 优先于 PATH：容器中可能预装旧版 tshark（如 3.6.2），
    start.sh 通过 TSHARK_PATH 指定 wrapper 指向新版 tshark（如 4.6.6）。
    若 PATH 优先，shutil.which 会找到旧版而忽略 TSHARK_PATH。
    """
    env_path = os.environ.get("TSHARK_PATH", "")
    if env_path and os.path.isfile(env_path):
        return env_path
    return shutil.which("tshark") or ""


def _sni_cache_path(pcap_path: Path, sha256: str) -> Path:
    """返回 SNI 缓存文件路径。"""
    cache_dir = pcap_path.parent / _SNI_CACHE_DIR
    cache_dir.mkdir(exist_ok=True)
    return cache_dir / f"{sha256}.json"


def _load_sni_cache(pcap_path: Path, sha256: str) -> Optional[Dict[str, List[str]]]:
    """从磁盘加载 SNI 缓存，文件不存在或损坏时返回 None。"""
    cache_file = _sni_cache_path(pcap_path, sha256)
    if not cache_file.exists():
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _save_sni_cache(pcap_path: Path, sha256: str, sni_map: Dict[str, List[str]]):
    """将 SNI 映射保存到磁盘缓存。"""
    try:
        cache_file = _sni_cache_path(pcap_path, sha256)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(sni_map, f, ensure_ascii=False)
    except OSError as e:
        logger.warning(f"Failed to save SNI cache for {pcap_path.name}: {e}")


def extract_sni_mapping(pcap_path: Path, sha256: str = "") -> Dict[str, List[str]]:
    """从 PCAP 中提取 SNI 映射（远程 IP → 域名列表）。

    使用 tshark 提取 TLS ClientHello 中的 server_name (SNI) 扩展。
    QUIC Initial 载荷加密，dpkt 无法直接解析；tshark 能处理 QUIC 解密。

    当提供 sha256 时，以 SHA-256 为键将结果缓存到磁盘（.sni_cache/ 目录），
    重处理同一 PCAP 时跳过 tshark 子进程调用。

    Args:
        pcap_path: PCAP 文件路径
        sha256: PCAP 文件的 SHA-256 哈希（可选，用于磁盘缓存）

    Returns:
        {remote_ip: [domain, ...]}
    """
    # 尝试从磁盘缓存加载
    if sha256:
        cached = _load_sni_cache(pcap_path, sha256)
        if cached is not None:
            logger.info(f"SNI cache hit for {pcap_path.name} (sha256={sha256[:12]}...)")
            return cached

    ip_to_sni: Dict[str, List[str]] = {}

    tshark_path = _find_tshark()
    if not tshark_path or not os.path.isfile(tshark_path):
        logger.warning(
            f"tshark not found, SNI extraction skipped for {pcap_path.name}. "
            f"Set TSHARK_PATH env var or install Wireshark."
        )
        return ip_to_sni

    try:
        result = subprocess.run(
            [tshark_path, "-r", str(pcap_path),
             "-Y", "tls.handshake.type == 1",
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tls.handshake.extensions_server_name"],
            capture_output=True, text=True, timeout=120,
        )

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            src_ip, dst_ip, sni = parts[0], parts[1], parts[2]
            if not sni or not sni.strip():
                continue
            sni = sni.strip()

            if not _is_private_ip(src_ip):
                remote_ip = src_ip
            elif not _is_private_ip(dst_ip):
                remote_ip = dst_ip
            else:
                continue

            if remote_ip not in ip_to_sni:
                ip_to_sni[remote_ip] = []
            if sni not in ip_to_sni[remote_ip]:
                ip_to_sni[remote_ip].append(sni)

    except subprocess.TimeoutExpired:
        logger.warning(f"tshark SNI extraction timed out for {pcap_path.name}")
    except Exception as e:
        logger.warning(f"tshark SNI extraction failed for {pcap_path.name}: {e}")

    # 诊断：如果提取结果异常少，记录 tshark stderr 帮助排查
    if len(ip_to_sni) <= 5 and result and result.stderr:
        stderr_preview = result.stderr.strip()[:500]
        if stderr_preview:
            logger.warning(
                f"tshark stderr for {pcap_path.name} (only {len(ip_to_sni)} IPs extracted): {stderr_preview}"
            )

    # 诊断：如果提取结果异常少，记录 tshark 文件夹路径帮助排查
    if len(ip_to_sni) <= 5:
        try:
            folders_result = subprocess.run(
                [tshark_path, "-G", "folders"],
                capture_output=True, text=True, timeout=10,
            )
            if folders_result.stdout:
                logger.info(
                    f"tshark folders for {pcap_path.name}: {folders_result.stdout.strip()[:500]}"
                )
        except Exception:
            pass

    # 保存到磁盘缓存
    if sha256 and ip_to_sni:
        _save_sni_cache(pcap_path, sha256, ip_to_sni)

    logger.info(f"Extracted SNI for {len(ip_to_sni)} IPs from {pcap_path.name}")
    return ip_to_sni


# ── DNS 映射 ──────────────────────────────────────────────────

def build_dns_mapping(dns_records: List[DNSRecord]) -> Dict[str, set]:
    """从 DNS 记录构建 IP → 域名集合映射。"""
    ip_to_domains: Dict[str, set] = defaultdict(set)
    for rec in dns_records:
        for ip in rec.answer_ips:
            ip_to_domains[ip].add(rec.query_domain)
    return dict(ip_to_domains)


# ── 语义分类器 ────────────────────────────────────────────────

class SemanticClassifier:
    """多路径语义通道分类器。

    5 层分类：SNI → DNS → /24 前缀传播 → /16 前缀传播 → CIDR IP 归属。
    /24 和 /16 前缀映射分别参与 Tier 3 和 Tier 4 分类决策。
    """

    def __init__(self):
        self.ip_channel: Dict[str, Tuple[int, str]] = {}
        self.ip_sni_domains: Dict[str, List[str]] = {}
        self.ip_dns_domains: Dict[str, List[str]] = {}
        self.prefix_24_map: Dict[str, Counter] = {}
        self.prefix_16_map: Dict[str, Counter] = {}
        self.anomalies: List[dict] = []
        self.quality_issues: List[dict] = []
        self.ip_attributions: Dict[str, AttributionResult] = {}  # Tier 5 归属详情

    def build(self, sni_map: Dict[str, List[str]], dns_map: Dict[str, set]):
        """构建分类器。

        Args:
            sni_map: {remote_ip: [domain, ...]} from SNI extraction
            dns_map: {remote_ip: {domain, ...}} from DNS responses
        """
        all_ips = set(sni_map.keys()) | set(dns_map.keys())

        for ip in all_ips:
            sni_domains = sni_map.get(ip, [])
            dns_domains = list(dns_map.get(ip, set()))

            self.ip_sni_domains[ip] = sni_domains
            self.ip_dns_domains[ip] = dns_domains

            sni_channels = set(classify_domain(d) for d in sni_domains)
            dns_channels = set(classify_domain(d) for d in dns_domains)

            if sni_channels:
                chosen = self._pick_channel(sni_channels)
                self.ip_channel[ip] = (chosen, "SNI")
                if dns_channels and sni_channels != dns_channels:
                    self.anomalies.append({
                        "type": "SNI_DNS_mismatch",
                        "ip": ip,
                        "sni_domains": sni_domains,
                        "dns_domains": dns_domains,
                        "sni_channels": sni_channels,
                        "dns_channels": dns_channels,
                        "resolved_channel": chosen,
                    })
            elif dns_channels:
                chosen = self._pick_channel(dns_channels)
                self.ip_channel[ip] = (chosen, "DNS")

        # Tier 3-5 不在 build() 中执行——延迟到 classify() 按需匹配，
        # 避免对 all_ips 中 SNI/DNS 未命中的 IP 提前做 CIDR 查询。
        # 前缀映射基于 Tier 1/2 的直接证据构建，保证传播来源可靠。

        for ip, (channel, source) in self.ip_channel.items():
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            p24 = ".".join(parts[:3])
            p16 = ".".join(parts[:2])
            self.prefix_24_map.setdefault(p24, Counter())[channel] += 1
            self.prefix_16_map.setdefault(p16, Counter())[channel] += 1

        sni_count = sum(1 for _, s in self.ip_channel.values() if s == "SNI")
        dns_count = sum(1 for _, s in self.ip_channel.values() if s == "DNS")
        logger.info(
            f"SemanticClassifier: {len(self.ip_channel)} IPs classified "
            f"(SNI={sni_count}, DNS={dns_count}), "
            f"{len(self.anomalies)} anomalies, "
            f"prefix maps: /24={len(self.prefix_24_map)}, /16={len(self.prefix_16_map)}"
        )

    def classify(self, ip: str) -> Tuple[Optional[int], str]:
        """5 层分类：SNI → DNS → /24 传播 → /16 传播 → CIDR 归属。

        Tier 1-2 在 build() 中完成，结果缓存在 ip_channel。
        Tier 3-5 延迟匹配，命中后缓存。

        Returns:
            (channel_id, source_tier) or (None, "unmapped")
        """
        if ip in self.ip_channel:
            return self.ip_channel[ip]

        # Tier 3: /24 前缀传播（256 IP 块，精度高）
        parts = ip.split(".")
        if len(parts) == 4:
            p24 = ".".join(parts[:3])
            counter = self.prefix_24_map.get(p24)
            if counter:
                ch = counter.most_common(1)[0][0]
                self.ip_channel[ip] = (ch, "PREFIX_24")
                return self.ip_channel[ip]

            # Tier 4: /16 前缀传播（65536 IP 块，精度较低）
            p16 = ".".join(parts[:2])
            counter = self.prefix_16_map.get(p16)
            if counter:
                ch = counter.most_common(1)[0][0]
                self.ip_channel[ip] = (ch, "PREFIX_16")
                return self.ip_channel[ip]

        # Tier 5: CIDR IP 归属（仅标 other，最后兜底）
        attr = lookup_attribution(ip)
        if attr:
            self.ip_channel[ip] = (CHANNEL_OTHER, f"IP_ATTR:{attr.owner}")
            self.ip_attributions[ip] = attr
            return self.ip_channel[ip]

        return (None, "unmapped")

    def classify_with_quality(self, ip: str, pkt_count: int = 0,
                              total_bytes: int = 0) -> Tuple[Optional[int], str]:
        """分类并记录质量问题。

        当 5 层均未命中时，记录到 quality_issues 列表。
        """
        channel, source = self.classify(ip)
        if channel is None:
            avg = total_bytes / pkt_count if pkt_count > 0 else 0
            self.quality_issues.append({
                "ip": ip,
                "pkts": pkt_count,
                "bytes": total_bytes,
                "avg_pkt_size": round(avg, 1),
            })
        return (channel, source)

    def _pick_channel(self, channels: set) -> int:
        """多通道冲突解决：按优先级选择。"""
        if len(channels) == 1:
            return next(iter(channels))
        for ch in _CHANNEL_PRIORITY:
            if ch in channels:
                return ch
        return min(channels)
