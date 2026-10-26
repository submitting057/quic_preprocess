import json
import os
import glob
import logging
from collections import Counter

logger = logging.getLogger(__name__)


# ── IP 工具函数 ──────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """判断 IP 是否属于 RFC 1918 私有网段（192.168.x.x / 172.16-31.x.x / 10.x.x.x）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def infer_device_ip(datagrams: list) -> str:
    """
    从 UDP 数据报中启发式推断设备 IP。

    策略：
      1. 筛选同时作为源 IP 和目的 IP 出现的私有网段 IP
      2. 选择"上行小包率高 + 下行大包率高"的 IP
         — 设备发送上行 ACK（小包），接收下行视频数据（大包）
      3. 无候选时回退到私有网段中总包数最多的 IP

    Args:
        datagrams: UDP 数据报列表（需有 src_ip, dst_ip, udp_payload_length, has_udp 属性）

    Returns:
        推断的设备 IP，无法推断时返回空字符串
    """
    SMALL_THRESHOLD = 200
    LARGE_THRESHOLD = 1200

    src_counter = Counter()
    dst_counter = Counter()
    src_small = Counter()
    dst_large = Counter()

    for d in datagrams:
        if not d.has_udp:
            continue
        payload = d.udp_payload_length or 0
        src_counter[d.src_ip] += 1
        dst_counter[d.dst_ip] += 1
        if d.src_ip and payload < SMALL_THRESHOLD:
            src_small[d.src_ip] += 1
        if d.dst_ip and payload >= LARGE_THRESHOLD:
            dst_large[d.dst_ip] += 1

    both_directions = set(src_counter.keys()) & set(dst_counter.keys())
    candidates = [ip for ip in both_directions if is_private_ip(ip)]

    if not candidates:
        all_private = [ip for ip in set(src_counter) | set(dst_counter)
                       if is_private_ip(ip)]
        if not all_private:
            return ""
        candidates = all_private

    best_ip = ""
    best_score = -1.0

    for ip in candidates:
        src_total = src_counter[ip]
        dst_total = dst_counter[ip]
        if src_total == 0 or dst_total == 0:
            continue
        up_small_ratio = src_small[ip] / src_total
        down_large_ratio = dst_large[ip] / dst_total
        score = up_small_ratio + down_large_ratio
        if score > best_score:
            best_score = score
            best_ip = ip

    if best_score < 0.5:
        best_ip = max(candidates, key=lambda ip: src_counter[ip] + dst_counter[ip])

    return best_ip


def resolve_input_dir():
    """
    解析输入目录路径，优先级与 start.sh 一致：
      1. DATAOPS_PLUGIN_TOOL_INPUT JSON → dataset_paths[0]（优先）或 input_dir
      2. PLUGIN_TOOL_INPUT JSON → dataset_paths[0]（优先）或 input_dir
      3. 小写 input_dir 环境变量
      4. 大写 INPUT_DIR 环境变量
      5. 兜底：项目根目录下的 input/

    Returns:
        tuple: (input_dir: str, dataset_paths: list[str])
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_input = os.path.join(base_dir, "input")

    def _extract_from_json(json_str):
        try:
            d = json.loads(json_str)
        except (json.JSONDecodeError, TypeError):
            return None, []
        input_dir = d.get("input_dir", "")
        ds_paths = d.get("dataset_paths", [])
        # 优先使用 dataset_paths[0] 作为实际数据目录
        chosen = ds_paths[0] if ds_paths else (input_dir or "")
        return chosen, ds_paths

    # 优先级 1: DATAOPS_PLUGIN_TOOL_INPUT
    val = os.environ.get("DATAOPS_PLUGIN_TOOL_INPUT")
    if val:
        input_dir, ds_paths = _extract_from_json(val)
        if input_dir:
            print(f"INPUT_DIR from DATAOPS_PLUGIN_TOOL_INPUT (dataset_paths preferred): {input_dir}")
            print(f"DATASET_PATHS: {ds_paths}")
            return input_dir, ds_paths

    # 优先级 2: PLUGIN_TOOL_INPUT
    val = os.environ.get("PLUGIN_TOOL_INPUT")
    if val:
        input_dir, ds_paths = _extract_from_json(val)
        if input_dir:
            print(f"INPUT_DIR from PLUGIN_TOOL_INPUT (dataset_paths preferred): {input_dir}")
            print(f"DATASET_PATHS: {ds_paths}")
            return input_dir, ds_paths

    # 优先级 3: 小写 input_dir
    val = os.environ.get("input_dir")
    if val:
        print(f"INPUT_DIR from env (input_dir): {val}")
        return val, []

    # 优先级 4: 大写 INPUT_DIR
    val = os.environ.get("INPUT_DIR")
    if val:
        print(f"INPUT_DIR from env: {val}")
        return val, []

    # 兜底
    print(f"WARNING: INPUT_DIR not set by framework, using default {default_input}")
    return default_input, []


def resolve_output_dir():
    """
    解析输出目录路径，优先级与 start.sh 一致：
      1. DATAOPS_PLUGIN_TOOL_OUTPUT JSON → output_dir
      2. PLUGIN_TOOL_OUTPUT JSON → output_dir
      3. 小写 output_dir 环境变量
      4. 大写 OUTPUT_DIR 环境变量
      5. 兜底：项目根目录下的 output/

    Returns:
        str: output_dir
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_output = os.path.join(base_dir, "output")

    def _extract_output_dir(json_str):
        try:
            d = json.loads(json_str)
            return d.get("output_dir", "")
        except (json.JSONDecodeError, TypeError):
            return ""

    # 优先级 1: DATAOPS_PLUGIN_TOOL_OUTPUT
    val = os.environ.get("DATAOPS_PLUGIN_TOOL_OUTPUT")
    if val:
        output_dir = _extract_output_dir(val)
        if output_dir:
            print(f"OUTPUT_DIR from DATAOPS_PLUGIN_TOOL_OUTPUT: {output_dir}")
            return output_dir

    # 优先级 2: PLUGIN_TOOL_OUTPUT
    val = os.environ.get("PLUGIN_TOOL_OUTPUT")
    if val:
        output_dir = _extract_output_dir(val)
        if output_dir:
            print(f"OUTPUT_DIR from PLUGIN_TOOL_OUTPUT: {output_dir}")
            return output_dir

    # 优先级 3: 小写 output_dir
    val = os.environ.get("output_dir")
    if val:
        print(f"OUTPUT_DIR from env (output_dir): {val}")
        return val

    # 优先级 4: 大写 OUTPUT_DIR
    val = os.environ.get("OUTPUT_DIR")
    if val:
        print(f"OUTPUT_DIR from env: {val}")
        return val

    # 兜底
    print(f"WARNING: OUTPUT_DIR not set by framework, using default {default_output}")
    return default_output


def find_files_by_ext(root_dir, extensions):
    """
    递归搜索指定扩展名的文件，返回相对于 root_dir 的路径列表。

    Args:
        root_dir: 搜索根目录
        extensions: 扩展名列表，如 [".pcap", ".log"]，或单个扩展名如 ".pcap"

    Returns:
        list[str]: 排序后的相对路径列表
    """
    if isinstance(extensions, str):
        extensions = [extensions]

    results = []
    for ext in extensions:
        pattern = os.path.join(root_dir, "**", f"*{ext}")
        results.extend(glob.glob(pattern, recursive=True))

    # 去重并排序，转为相对路径
    seen = set()
    unique = []
    for abs_path in sorted(results):
        rel = os.path.relpath(abs_path, root_dir)
        if rel not in seen:
            seen.add(rel)
            unique.append(rel)
    return unique
