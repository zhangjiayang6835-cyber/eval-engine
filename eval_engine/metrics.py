"""
Evaluation metrics for code submissions.

Provides three built-in metrics:

* ``functional_pass`` — do the provided tests pass?
* ``security_pass`` — does the code avoid dangerous patterns?
* ``cheat_score`` — aggregated cheat-detection score in ``[0, 1]``.

Each metric is registered as a plain function so the framework can discover
and invoke it by name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .cheat_detection import detect_all_cheat_signals
from .config import MetricRule, TaskConfig
from .runner import DockerSandboxRunner, SandboxResult


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricResult:
    """Outcome of a single metric evaluation.

    Attributes:
        name: Metric identifier (e.g. ``functional_pass``).
        passed: Whether the submission satisfied the metric.
        score: Normalised score in ``[0, 1]`` (1 = perfect).
        details: Human-readable explanation or list of failures.
        extra: Arbitrary data the metric wants to attach.
    """

    name: str
    passed: bool
    score: float
    details: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResults:
    """Complete evaluation output for one submission.

    Attributes:
        task_id: The task being evaluated.
        metrics: Per-metric results.
        sandbox_result: Raw sandbox execution metadata.
        cheat_signals: Aggregated cheat-detection output.
        malicious_code_found: Shorthand for ``cheat_signals.malicious_code_found``.
        cheat_score: Shorthand for ``cheat_signals.cheat_score``.
        overall_passed: All required metrics passed.
    """

    task_id: str
    metrics: List[MetricResult]
    sandbox_result: SandboxResult
    cheat_signals: Any = None  # CheatSignals — avoid circular-type issues
    malicious_code_found: bool = False
    cheat_score: float = 0.0
    overall_passed: bool = False


# ---------------------------------------------------------------------------
# Metric registry
# ---------------------------------------------------------------------------

# Map metric name → callable(submission_code, task, sandbox_result) → MetricResult
_METRIC_REGISTRY: Dict[str, Callable[..., MetricResult]] = {}


def register_metric(name: str) -> Callable:
    """Decorator to register a metric function in the global registry."""
    def decorator(fn: Callable) -> Callable:
        _METRIC_REGISTRY[name] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Built-in metrics
# ---------------------------------------------------------------------------


@register_metric("functional_pass")
def metric_functional_pass(
    submission_code: str,
    task: TaskConfig,
    sandbox_result: SandboxResult,
    **kwargs: Any,
) -> MetricResult:
    """Check whether tests passed inside the sandbox.

    A submission ``passes`` if the exit code is 0 *and* the sandbox did not
    time out.  Non-zero exit codes are treated as test failures.
    """
    passed = sandbox_result.exit_code == 0 and not sandbox_result.timed_out
    _details: str
    _score: float

    if sandbox_result.timed_out:
        _details = "Execution timed out — tests could not complete."
        _score = 0.0
    elif sandbox_result.exit_code == 0:
        _details = "All tests passed."
        _score = 1.0
    else:
        # Extract a summary from stderr (e.g. pytest output).
        stderr_tail = _tail(sandbox_result.stderr, 10)
        _details = (
            f"Tests failed (exit code {sandbox_result.exit_code}).\n"
            f"Stderr (last 10 lines):\n{stderr_tail}"
        )
        _score = 0.0

    return MetricResult(
        name="functional_pass",
        passed=passed,
        score=_score,
        details=_details,
        extra={"exit_code": sandbox_result.exit_code, "timed_out": sandbox_result.timed_out},
    )


@register_metric("security_pass")
def metric_security_pass(
    submission_code: str,
    task: TaskConfig,
    sandbox_result: SandboxResult,
    **kwargs: Any,
) -> MetricResult:
    """Check the submission for dangerous / insecure code patterns.

    A submission passes if *none* of these conditions are met:

    * Hardcoded admin bypass.
    * Dangerous system calls (subprocess, os.system, ctypes, etc.).
    * Use of ``eval`` / ``exec`` on dynamic data.
    * Hardcoded expected output.
    * Suspicious obfuscation patterns.
    * String concatenation in SQL queries (SQL injection risk).
    """
    signals = detect_all_cheat_signals(submission_code)
    failures: List[str] = []

    for sig in signals.signals:
        failures.append(f"[{sig.severity:.1f}] {sig.description}")

    # Additional check: SQL string concatenation
    sql_issues = _detect_sql_concatenation(submission_code)
    failures.extend(sql_issues)

    passed = len(failures) == 0
    score = 1.0 - min(signals.cheat_score, 1.0)

    return MetricResult(
        name="security_pass",
        passed=passed,
        score=score,
        details="; ".join(failures) if failures else "No security issues detected.",
        extra={"signal_count": len(signals.signals), "malicious": signals.malicious_code_found},
    )


@register_metric("cheat_score")
def metric_cheat_score(
    submission_code: str,
    task: TaskConfig,
    sandbox_result: SandboxResult,
    **kwargs: Any,
) -> MetricResult:
    """Compute an aggregate cheat score from all cheat signals.

    The score is the RMS of individual signal severities, normalised to
    ``[0, 1]``.  A lower score is better.
    """
    signals = detect_all_cheat_signals(submission_code)

    score = signals.cheat_score
    passed = score < 0.3  # Configurable threshold

    return MetricResult(
        name="cheat_score",
        passed=passed,
        score=score,
        details=(
            f"Cheat score {score:.3f} — {'below' if passed else 'above'} threshold 0.3. "
            f"{len(signals.signals)} signal(s) detected."
        ),
        extra={
            "signal_count": len(signals.signals),
            "signals": [s.name for s in signals.signals],
            "malicious": signals.malicious_code_found,
        },
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def evaluate_all(
    submission_code: str,
    task: TaskConfig,
    sandbox_result: SandboxResult,
    runner: Optional[DockerSandboxRunner] = None,
) -> EvaluationResults:
    """Run all enabled metrics against a submission.

    Args:
        submission_code: The submitted source code.
        task: Parsed task configuration.
        sandbox_result: Result from the sandbox execution.
        runner: Optional runner instance (used by some metrics that need
            re-execution; currently unused but reserved).

    Returns:
        Aggregated :class:`EvaluationResults`.
    """
    metrics: List[MetricResult] = []
    cheat_signals = detect_all_cheat_signals(submission_code)

    for metric_def in task.evaluation.metrics:
        if not metric_def.enabled:
            continue
        handler = _METRIC_REGISTRY.get(metric_def.name)
        if handler is None:
            metrics.append(
                MetricResult(
                    name=metric_def.name,
                    passed=False,
                    score=0.0,
                    details=f"No handler registered for metric '{metric_def.name}'.",
                )
            )
            continue

        try:
            result = handler(
                submission_code=submission_code,
                task=task,
                sandbox_result=sandbox_result,
                rules=metric_def.rules,
            )
            metrics.append(result)
        except Exception as exc:
            metrics.append(
                MetricResult(
                    name=metric_def.name,
                    passed=False,
                    score=0.0,
                    details=f"Metric '{metric_def.name}' raised an error: {exc}",
                )
            )

    overall_passed = all(m.passed for m in metrics if m.name != "cheat_score")

    return EvaluationResults(
        task_id=task.id,
        metrics=metrics,
        sandbox_result=sandbox_result,
        cheat_signals=cheat_signals,
        malicious_code_found=cheat_signals.malicious_code_found,
        cheat_score=cheat_signals.cheat_score,
        overall_passed=overall_passed,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_SQL_CONCAT_PATTERNS = [
    re.compile(r"""['"]\s*\+\s*(select|insert|update|delete|drop|alter)\s""", re.IGNORECASE),
    re.compile(r"""(select|insert|update|delete|drop|alter)\s.*\+\s*['"]""", re.IGNORECASE),
    re.compile(r"""f['\"].*\{.*(select|insert|update|delete|drop|alter)""", re.IGNORECASE),
    re.compile(r"""%(?:\([^)]*\))?s.*(?:select|insert|update|delete|drop|alter)""", re.IGNORECASE),
    re.compile(r"""\.format\(.*(?:select|insert|update|delete|drop|alter)""", re.IGNORECASE),
]


def _detect_sql_concatenation(source_code: str) -> List[str]:
    """Return human-readable descriptions of SQL injection patterns found."""
    issues: List[str] = []
    for pattern in _SQL_CONCAT_PATTERNS:
        match = pattern.search(source_code)
        if match:
            issues.append(f"Possible SQL injection via string concatenation: '{match.group()[:60]}'")
    return issues


def _tail(text: str, n: int) -> str:
    """Return the last *n* lines of *text*."""
    lines = text.splitlines()
    return "\n".join(lines[-n:]) if lines else ""
