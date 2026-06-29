"""Eval engine — code security evaluation toolkit."""
from .cheat_detection import detect_all_cheat_signals, CheatSignal, CheatSignals
from .config import load_task_config, TaskConfig, EvaluationConfig, MetricRule
from .metrics import evaluate_all, EvaluationResults, MetricResult
from .reporter import generate_report
from .runner import SandboxResult, DockerSandboxRunner

__all__ = [
    "detect_all_cheat_signals", "CheatSignal", "CheatSignals",
    "load_task_config", "TaskConfig", "EvaluationConfig", "MetricRule",
    "evaluate_all", "EvaluationResults", "MetricResult",
    "generate_report",
    "SandboxResult", "DockerSandboxRunner",
]
