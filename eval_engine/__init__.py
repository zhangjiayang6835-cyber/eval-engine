"""
eval-engine: A Docker-sandboxed code evaluation engine with cheat detection.

Provides YAML-based task configuration, Docker sandbox execution, functional &
security metrics, cheat-signal detection, and standardized JSON reporting.
"""

__version__ = "0.1.0"
__author__ = "Eval Engine Team"
__license__ = "MIT"

from .config import load_task_config, TaskConfig, MetricRule, EvaluationConfig
from .runner import DockerSandboxRunner, SandboxResult
from .metrics import evaluate_all, EvaluationResults, MetricResult
from .cheat_detection import (
    detect_all_cheat_signals,
    CheatSignals,
    CheatSignal,
)
from .reporter import generate_report, EvaluationReport

__all__ = [
    # Version
    "__version__",
    # Config
    "load_task_config",
    "TaskConfig",
    "MetricRule",
    "EvaluationConfig",
    # Runner
    "DockerSandboxRunner",
    "SandboxResult",
    # Metrics
    "evaluate_all",
    "EvaluationResults",
    "MetricResult",
    # Cheat detection
    "detect_all_cheat_signals",
    "CheatSignals",
    "CheatSignal",
    # Reporter
    "generate_report",
    "EvaluationReport",
]
