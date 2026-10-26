"""Step 7: 会话构建。

解析 .metadata、operate.log、debug_info.txt 等伴随文件，
结合 PCAP 数据构建完整的 SessionRecord。
"""

import re
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SessionRecord:
    """单个会话的完整记录。"""
    # 标识
    session_id: str = ""
    capture_id: str = ""
    video_id: str = ""
    device: str = ""  # 设备名（从 PCAP 文件名解析）
    platform: str = ""  # 平台（从 PCAP 文件名解析，如 Android）
    network: str = ""   # 网络类型（从 PCAP 文件名解析，如 Wifi）
    # 文件路径
    pcap_path: str = ""
    metadata_path: str = ""
    operate_log_path: str = ""
    debug_info_path: str = ""
    # 设备信息（来自 .metadata）
    device_ip: str = ""
    device_mode: str = ""
    device_vendor: str = ""
    os_version: str = ""
    application_version: str = ""
    network_information: str = ""
    phone_to_server_time_offset: int = 0
    # 采集配置
    target_resolution: str = ""
    target_protocol: str = ""
    watch_speed: float = 1.0
    # 视频信息（来自 debug_info.txt）
    codec: str = ""
    resolution: str = ""
    audio_codec: str = ""
    # PCAP 统计
    pcap_sha256: str = ""
    total_packets: int = 0
    total_datagrams: int = 0
    video_datagrams: int = 0
    capture_duration_s: float = 0.0
    # 视频区间
    video_start_time: float = 0.0
    video_end_time: float = 0.0
    video_duration_s: float = 0.0
    video_locate_method: str = ""
    video_locate_confidence: str = ""
    video_cdn_ips: List[str] = field(default_factory=list)
    # 质量状态
    quality_status: str = ""
    quality_notes: str = ""
    # 其他
    contains_ad: bool = False
    contains_foreign_video: bool = False


# ── 伴随文件查找 ──────────────────────────────────────────────

def find_companion_files(pcap_path: Path) -> Dict[str, Optional[Path]]:
    """
    在 PCAP 同目录下查找伴随文件。

    查找的文件类型：
      - .metadata（JSON 格式，必需）
      - .operate.log 或 operate.log
      - debug_info.txt

    Args:
        pcap_path: PCAP 文件路径

    Returns:
        {"metadata": Path|None, "operate_log": Path|None, "debug_info": Path|None}
    """
    parent = pcap_path.parent
    stem = pcap_path.stem

    # .metadata: 与 PCAP 同名，扩展名为 .metadata
    metadata_path = parent / f"{stem}.metadata"
    if not metadata_path.exists():
        # 也尝试直接找 .metadata 文件
        candidates = list(parent.glob("*.metadata"))
        metadata_path = candidates[0] if candidates else None
    if metadata_path is not None and not metadata_path.exists():
        metadata_path = None

    # operate.log: 先找同名 .operate.log，再找 -operator.log（Windows 命名），再找 .log（iOS 命名），再找目录下的
    # 对于格式 2b（-tcpdump 后缀），log 文件不含 -tcpdump，需额外尝试去掉后缀的 stem
    stem_no_tcpdump = stem[:-8] if stem.endswith("-tcpdump") else stem

    operate_log_path = parent / f"{stem}.operate.log"
    if not operate_log_path.exists():
        operate_log_path = parent / f"{stem}-operator.log"
    if not operate_log_path.exists():
        operate_log_path = parent / f"{stem}.log"
    if not operate_log_path.exists() and stem_no_tcpdump != stem:
        operate_log_path = parent / f"{stem_no_tcpdump}.operate.log"
    if not operate_log_path.exists() and stem_no_tcpdump != stem:
        operate_log_path = parent / f"{stem_no_tcpdump}.log"
    if not operate_log_path.exists():
        operate_log_path = parent / "operate.log"
    if not operate_log_path.exists():
        operate_log_path = None

    # debug_info.txt
    debug_info_path = parent / "debug_info.txt"
    if not debug_info_path.exists():
        debug_info_path = None

    return {
        "metadata": metadata_path,
        "operate_log": operate_log_path,
        "debug_info": debug_info_path,
    }


def discover_pcaps(root_dir: Path) -> List[Path]:
    """
    递归查找目录下所有 .pcap 文件。

    Args:
        root_dir: 搜索根目录

    Returns:
        排序后的 PCAP 路径列表
    """
    return sorted(root_dir.rglob("*.pcap"))


# ── 元数据解析 ────────────────────────────────────────────────

def parse_metadata(metadata_path: Path) -> Optional[dict]:
    """
    解析 .metadata JSON 文件。

    预期字段: device_ip, capture_id, device_mode, device_vendor,
              os_version, application_version, network_information,
              phone_to_server_time_offset, target_resolution, target_protocol, watch_speed

    Args:
        metadata_path: .metadata 文件路径

    Returns:
        解析后的字典，失败返回 None
    """
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse metadata {metadata_path}: {e}")
        return None


def parse_debug_info(debug_info_path: Path) -> dict:
    """
    解析 debug_info.txt，提取 codec、resolution、audio_codec。

    典型内容示例：
      Codec: av01
      Resolution: 1920x1080
      Audio Codec: opus

    Args:
        debug_info_path: debug_info.txt 路径

    Returns:
        {"codec": str, "resolution": str, "audio_codec": str}
    """
    result = {"codec": "", "resolution": "", "audio_codec": ""}

    try:
        with open(debug_info_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Codec
        m = re.search(r'Codec:\s*(\S+)', content, re.IGNORECASE)
        if m:
            result["codec"] = m.group(1).lower()

        # Resolution
        m = re.search(r'Resolution:\s*(\d+x\d+)', content, re.IGNORECASE)
        if m:
            result["resolution"] = m.group(1)

        # Audio Codec
        m = re.search(r'Audio\s*Codec:\s*(\S+)', content, re.IGNORECASE)
        if m:
            result["audio_codec"] = m.group(1).lower()

    except Exception as e:
        logger.error(f"Failed to parse debug_info {debug_info_path}: {e}")

    return result


def parse_operate_log_phase_times(operate_log_path: Path) -> dict:
    """
    解析 operate.log 中的播放阶段时间。

    提取 playback_start, playback_end, search_start, time_offset。

    Args:
        operate_log_path: operate.log 路径

    Returns:
        {"playback_start": float|None, "playback_end": float|None,
         "search_start": float|None, "time_offset": int}
    """
    result = {
        "playback_start": None,
        "playback_end": None,
        "search_start": None,
        "time_offset": 0,
    }

    try:
        with open(operate_log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_lower = line.lower()

                if "start watching" in line_lower or "playback_start" in line_lower:
                    m = re.search(r'UTC\s+(\d+\.\d+)', line)
                    if m:
                        result["playback_start"] = float(m.group(1))

                if "stop watching" in line_lower or "playback_end" in line_lower:
                    m = re.search(r'UTC\s+(\d+\.\d+)', line)
                    if m:
                        result["playback_end"] = float(m.group(1))

                if "search_start" in line_lower:
                    m = re.search(r'UTC\s+(\d+\.\d+)', line)
                    if m:
                        result["search_start"] = float(m.group(1))

                # time_offset
                m = re.search(r'time_offset[:\s]+(-?\d+)', line, re.IGNORECASE)
                if m:
                    result["time_offset"] = int(m.group(1))

    except Exception as e:
        logger.error(f"Failed to parse operate_log {operate_log_path}: {e}")

    return result


# ── PCAP 文件名解析 ───────────────────────────────────────────

def parse_pcap_filename(pcap_path: Path) -> dict:
    """
    从 PCAP 文件名中提取 device, video_id, resolution, region, platform, network。

    支持两种框架格式：
    格式 2a（旧）: YouTube-EncryptedVideo-{Platform}-{hash}-{Network}-Open-{ts}-{device}-{video_id}-{res}-{AppTag}-{region}.pcap
      AppTag: Android/iOS 为 "YouTube"，Windows 为 "Chrome"
      Android 例: YouTube-EncryptedVideo-Android-abc123-Wifi-Open-20260613_230813-yb01-ZRpHECexsiY-auto-YouTube-HongKong.pcap
      Windows 例: YouTube-EncryptedVideo-Windows-abc123-Fixed-Open-20260627_212130-yb01-FRLYT9L8BxM-360p-Chrome-HongKong.pcap
    格式 2b（新）: YouTube-EncryptedVideo-{Platform}-{hash}-{Network}-Open-{ts}-{device}-{video_id}-{res}-{region}-tcpdump.pcap
      无 AppTag，pcap 文件名含 -tcpdump 后缀
      Android 例: YouTube-EncryptedVideo-Android-abc123-Wifi-Open-20260914_211238-yb1-3T2Z0ibILb4-auto-beijing-tcpdump.pcap

    Args:
        pcap_path: PCAP 文件路径

    Returns:
        {"device": str, "video_id": str, "resolution": str, "region": str,
         "platform": str, "network": str}
    """
    name = pcap_path.stem
    parts = name.split("-")

    result = {"device": "", "video_id": "", "resolution": "", "region": "",
              "platform": "", "network": ""}

    if not name.startswith("YouTube-EncryptedVideo-"):
        logger.warning(f"PCAP filename does not match format 2: {name}")
        return result

    # 格式 2a: ...-{res}-{AppTag}-{region}    AppTag in ("YouTube", "Chrome")
    # 格式 2b: ...-{res}-{region}-tcpdump     末尾为 "tcpdump"
    if len(parts) >= 12 and parts[-2] in ("YouTube", "Chrome"):
        # 格式 2a（旧）
        result["platform"] = parts[2]
        result["network"] = parts[4]
        result["region"] = parts[-1]
        result["resolution"] = parts[-3]
    elif len(parts) >= 11 and parts[-1] == "tcpdump":
        # 格式 2b（新）: 末尾是 tcpdump，倒数第二是 region，倒数第三是 resolution
        result["platform"] = parts[2]
        result["network"] = parts[4]
        result["region"] = parts[-2]
        result["resolution"] = parts[-3]
    else:
        logger.warning(f"PCAP filename structure unexpected: {name}")
        return result

    # 找时间戳位置，时间戳后面是 device
    ts_idx = None
    for i, p in enumerate(parts):
        if re.match(r'\d{8}_\d{6}', p):
            ts_idx = i
            break
    if ts_idx is not None and ts_idx + 1 < len(parts):
        result["device"] = parts[ts_idx + 1]
        # video_id: 从 ts_idx+2 到 resolution 之前
        vid_parts = parts[ts_idx + 2:-3]
        result["video_id"] = "-".join(vid_parts) if vid_parts else ""

    return result


# ── 会话构建 ──────────────────────────────────────────────────

def build_session(
    pcap_path: Path,
    quality_status: str = "",
    quality_notes: str = "",
    video_interval=None,
    datagram_count: int = 0,
    video_datagram_count: int = 0,
    total_packets: int = 0,
    pre_companions: dict = None,
    pre_meta: dict = None,
    pre_name_info: dict = None,
    pre_session_id: str = "",
) -> SessionRecord:
    """
    构建完整的 SessionRecord。

    Args:
        pcap_path: PCAP 文件路径
        quality_status: 质量检查状态
        quality_notes: 质量检查备注
        video_interval: VideoInterval 对象
        datagram_count: UDP 数据报总数
        video_datagram_count: 视频区间数据报数
        total_packets: PCAP 包总数
        pre_companions: 预解析的伴随文件字典（避免重复查找）
        pre_meta: 预解析的 metadata 字典（避免重复解析）
        pre_name_info: 预解析的文件名信息字典（避免重复解析）

    Returns:
        SessionRecord
    """
    record = SessionRecord()

    # 从文件名解析基本信息
    name_info = pre_name_info if pre_name_info is not None else parse_pcap_filename(pcap_path)
    record.device = name_info["device"]
    record.video_id = name_info["video_id"]
    record.resolution = name_info["resolution"]
    record.platform = name_info["platform"]
    record.network = name_info["network"]

    # 查找伴随文件
    companions = pre_companions if pre_companions is not None else find_companion_files(pcap_path)
    record.pcap_path = str(pcap_path)
    record.metadata_path = str(companions["metadata"]) if companions["metadata"] else ""
    record.operate_log_path = str(companions["operate_log"]) if companions["operate_log"] else ""
    record.debug_info_path = str(companions["debug_info"]) if companions["debug_info"] else ""

    # 解析 .metadata
    meta = pre_meta
    if meta is None and companions["metadata"]:
        meta = parse_metadata(companions["metadata"])
    if meta:
            record.device_ip = meta.get("device_ip", "")
            record.capture_id = meta.get("capture_id", "")
            record.device_mode = meta.get("device_mode", "")
            record.device_vendor = meta.get("device_vendor", "")
            record.os_version = meta.get("os_version", "")
            record.application_version = meta.get("application_version", "")
            record.network_information = meta.get("network_information", "")
            # phone_to_server_time_offset 在框架 metadata 中可能是字符串，需转换
            raw_offset = meta.get("phone_to_server_time_offset", 0)
            try:
                record.phone_to_server_time_offset = int(raw_offset)
            except (ValueError, TypeError):
                record.phone_to_server_time_offset = 0
            record.target_resolution = meta.get("target_resolution", "")
            record.target_protocol = meta.get("target_protocol", "")
            raw_speed = meta.get("watch_speed", 1.0)
            try:
                record.watch_speed = float(raw_speed)
            except (ValueError, TypeError):
                record.watch_speed = 1.0

    # 解析 debug_info.txt
    if companions["debug_info"]:
        debug_info = parse_debug_info(companions["debug_info"])
        record.codec = debug_info["codec"]
        if not record.resolution:
            record.resolution = debug_info["resolution"]
        record.audio_codec = debug_info["audio_codec"]

    # 构建 session_id（优先使用外部传入的已构造值，避免重复构造导致不一致）
    if pre_session_id:
        record.session_id = pre_session_id
    else:
        # 格式: Youtube-{device}-{video_id}-{platform}-{network}-{resolution}-{region}-{YYYYMMDD_HHMMSS}
        region = name_info["region"]
        timestamp = ""
        m = re.search(r'(\d{8}_\d{6})', pcap_path.stem)
        if m:
            timestamp = m.group(1)

        parts = ["Youtube", record.device, record.video_id, record.platform,
                 record.network, record.resolution, region, timestamp]
        record.session_id = "-".join(p for p in parts if p)

    # PCAP 统计
    record.total_packets = total_packets
    record.total_datagrams = datagram_count
    record.video_datagrams = video_datagram_count

    # 视频区间
    if video_interval:
        record.video_start_time = video_interval.start_time
        record.video_end_time = video_interval.end_time
        record.video_duration_s = video_interval.end_time - video_interval.start_time
        record.video_locate_method = video_interval.method
        record.video_locate_confidence = video_interval.confidence
        record.video_cdn_ips = list(video_interval.video_cdn_ips)

    # 质量
    record.quality_status = quality_status
    record.quality_notes = quality_notes

    return record
