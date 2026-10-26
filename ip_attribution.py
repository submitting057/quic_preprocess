"""Tier 3: 外部 IP 归属数据。

当 SNI (Tier 1) 和 DNS (Tier 2) 均未命中时，通过 CIDR 规则匹配
识别 IP 的所有者（Google、Apple、Cloudflare 等）。

数据来源: 公开知识 + 手动维护，纯本地查询，零网络依赖。

Importers: semantic_classifier.py
User instruction: 执行 PLAN.md 中的 Tier 3 IP 归属方案
"""

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AttributionResult:
    """IP 归属查询结果。"""
    owner: str        # "Google", "Apple", ...
    service: str      # "Google Public DNS", ...
    category: str     # "dns", "apple_push", ...
    cidr: str         # 匹配的 CIDR 规则


# ── 静态 CIDR 规则 ──────────────────────────────────────────────

_RULES = [
    # ── Google ──
    ("8.8.8.0/24",     "Google",    "Google Public DNS",   "dns"),
    ("8.8.4.0/24",     "Google",    "Google Public DNS",   "dns"),

    # ── Apple ──
    # 17.0.0.0/8 整段属于 Apple Inc (ASN AS714)
    ("17.0.0.0/8",     "Apple",     "Apple Services",      "apple_push"),

    # ── Cloudflare ──
    ("1.1.1.0/24",     "Cloudflare","Cloudflare DNS",      "dns"),
    ("1.0.0.0/24",     "Cloudflare","Cloudflare DNS",      "dns"),

    # ── 国内公共 DNS ──
    ("114.114.114.0/24","114DNS",   "114 Public DNS",      "dns"),
    ("223.5.5.0/24",   "Alibaba",   "AliDNS",              "dns"),
    ("223.6.6.0/24",   "Alibaba",   "AliDNS",              "dns"),
    ("119.29.29.0/24", "Tencent",   "DNSPod",              "dns"),
    ("180.76.76.0/24", "Baidu",     "Baidu DNS",           "dns"),
]


# ── 构建查找结构 ────────────────────────────────────────────────

_networks = []
for _cidr, _owner, _service, _category in _RULES:
    try:
        _networks.append((
            ipaddress.ip_network(_cidr, strict=False),
            _owner, _service, _category, _cidr,
        ))
    except ValueError as e:
        logger.error(f"Invalid CIDR rule {_cidr}: {e}")


def lookup_attribution(ip: str) -> Optional[AttributionResult]:
    """查询 IP 归属信息。

    Args:
        ip: IPv4/IPv6 字符串

    Returns:
        AttributionResult 或 None（无匹配规则时）
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for net, owner, service, category, cidr in _networks:
        if addr in net:
            return AttributionResult(
                owner=owner,
                service=service,
                category=category,
                cidr=cidr,
            )
    return None
