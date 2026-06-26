"""
JSON report generation.

Takes an :class:`EvaluationResults` instance and produces a standardised
JSON report that can be consumed by CI pipelines, dashboards, or upstream
orchestrators.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .metrics import EvaluationResults, MetricResult
from .runner import SandboxResult


# ---------------------------------------------------------------------------
# Report type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvaluationReport:
    """Standardised evaluation report.

    This is the output contract of the engine.  All fields are JSON-safe.
    """

    task_id: str
    submission_id: str
    timestamp: str
    overall_passed: bool
    results: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_evaluation(
        cls,
        eval_results: EvaluationResults,
        submission_id: str,
    ) -> "EvaluationReport":
        """Build a report from an :class:`EvaluationResults` object.

        Args:
            eval_results: The completed evaluation.
            submission_id: Opaque identifier for the submission being evaluated.

        Returns:
            A JSON-serialisable report.
        """
        metrics_serialised: List[Dict[str, Any]] = []
        for m in eval_results.metrics:
            metrics_serialised.append(
                {
                    "name": m.name,
                    "passed": m.passed,
                    "score": m.score,
                    "details": m.details,
                    "extra": m.extra,
                }
            )

        cs = eval_results.cheat_signals
        cheat_signals_serialised: List[Dict[str, Any]] = []
        if cs is not None:
            for sig in cs.signals:
                cheat_signals_serialised.append(
                    {
                        "name": sig.name,
                        "description": sig.description,
                        "severity": sig.severity,
                        "snippet": sig.snippet,
                        "line_number": sig.line_number,
                    }
                )

        sandbox = eval_results.sandbox_result

        results: Dict[str, Any] = {
            "metrics": metrics_serialised,
            "functional_pass": _metric_bool(eval_results.metrics, "functional_pass"),
            "security_pass": _metric_bool(eval_results.metrics, "security_pass"),
            "cheat_signals": cheat_signals_serialised,
            "malicious_code_found": eval_results.malicious_code_found,
            "cheat_score": eval_results.cheat_score,
            "sandbox": {
                "exit_code": sandbox.exit_code,
                "timed_out": sandbox.timed_out,
                "wall_time_ms": sandbox.wall_time_ms,
                "stdout_truncated": _truncate(sandbox.stdout, 2048),
                "stderr_truncated": _truncate(sandbox.stderr, 2048),
            },
        }

        return cls(
            task_id=eval_results.task_id,
            submission_id=submission_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            overall_passed=eval_results.overall_passed,
            results=results,
        )

    def to_json(self, indent: int = 2) -> str:
        """Serialize this report to a JSON string."""
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)

    def write(self, path: os.PathLike) -> os.PathLike:
        """Write the JSON report to *path*.

        Args:
            path: Destination file path.

        Returns:
            The *path* for chaining.
        """
        path = os.fspath(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        return os.path.abspath(path)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Public convenience API
# ---------------------------------------------------------------------------


def generate_report(
    eval_results: EvaluationResults,
    submission_id: str,
    output_path: Optional[os.PathLike] = None,
) -> EvaluationReport:
    """Create and optionally persist an evaluation report.

    Args:
        eval_results: The completed evaluation.
        submission_id: Identifier for the submission.
        output_path: If provided, the report JSON is written to this path.

    Returns:
        The :class:`EvaluationReport` instance.
    """
    report = EvaluationReport.from_evaluation(eval_results, submission_id)
    if output_path is not None:
        report.write(output_path)
    return report


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _metric_bool(metrics: List[MetricResult], name: str) -> bool:
    """Return the ``passed`` value of the first metric matching *name*."""
    for m in metrics:
        if m.name == name:
            return m.passed
    return False


def _truncate(text: str, max_len: int = 2048) -> str:
    """Truncate *text* to *max_len* characters with a trailing note."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (truncated, original {len(text)} chars)"
