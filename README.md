# 📊 eval-engine — AI安全评测引擎

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-37%2F37-green)]()

## 概述

**eval-engine** 是 [honeycode-honeypot](https://github.com/zhangjiayang6835-cyber/honeycode-honeypot) 和 [ai-training-gym](https://github.com/zhangjiayang6835-cyber/ai-training-gym) 的共享评测引擎，提供 Docker 沙箱执行、作弊检测和标准化评测报告。

## 功能

- **Docker 沙箱执行** — 在隔离容器中运行不可信代码，支持超时和内存限制
- **6 种作弊检测** — 硬编码绕过、危险系统调用、SQL注入、eval/exec、混淆代码、预期输出硬编码
- **3 项评测指标** — 功能正确性、安全性、作弊分数
- **标准化 JSON 报告** — 统一的评测输出格式

## 快速开始

```bash
# 安装
pip install -e .

# 构建 Docker 沙箱
docker build -t eval-sandbox:latest .

# 运行测试
pytest tests/ -v
```

## API 示例

```python
from eval_engine import load_task_config, detect_all_cheat_signals
from eval_engine.metrics import evaluate_all
from eval_engine.runner import SandboxResult

# 加载任务配置
config = load_task_config("task.yaml")

# 检测作弊
signals = detect_all_cheat_signals(code)

# 评测
result = evaluate_all(code, config, SandboxResult(exit_code=0))

# 生成报告
from eval_engine.reporter import generate_report
report = generate_report(result, submission_id="sub-001")
print(report.to_json())
```

## 测试

```bash
pytest tests/ -v      # 37 tests, all pass
```

