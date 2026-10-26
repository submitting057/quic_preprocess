import logging
from pathlib import Path

from utils import resolve_input_dir, resolve_output_dir
from pipeline import run_batch, PipelineConfig

# ── 路径解析 ──────────────────────────────────────────────────
# 解析逻辑与 start.sh 一致，支持框架 JSON 环境变量逐级回退：
#   1. DATAOPS_PLUGIN_TOOL_INPUT/OUTPUT → 2. PLUGIN_TOOL_INPUT/OUTPUT → 3. 小写环境变量 → 4. 大写环境变量 → 5. 默认路径
# 输入路径优先取 dataset_paths[0]（实际数据目录），而非 input_dir（逻辑父目录）
INPUT_DIR, DATASET_PATHS = resolve_input_dir()
OUTPUT_DIR = resolve_output_dir()


def main():
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 使用默认配置运行批处理
    config = PipelineConfig()
    run_batch(Path(INPUT_DIR), Path(OUTPUT_DIR), config)


if __name__ == "__main__":
    main()
