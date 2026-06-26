"""
YAML task configuration loader.

Reads a ``task-spec.yaml`` file and validates its structure into typed
dataclasses.  The schema supports free-form fields so that individual metrics
can attach their own configuration (e.g. pass-thresholds, forbidden APIs).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricRule:
    """A single metric definition inside a task evaluation block.

    Attributes:
        name: Machine-readable metric identifier (e.g. ``functional_pass``).
        enabled: Whether this metric is active for the task.
        fail_on: Optional list of conditions that cause the metric to fail.
        rules: Arbitrary key/value pairs consumed by the metric implementation.
    """

    name: str
    enabled: bool = True
    fail_on: Optional[List[str]] = None
    rules: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationConfig:
    """Aggregate evaluation config for a task.

    Attributes:
        metrics: Sequence of :class:`MetricRule` entries.
        timeout_seconds: Maximum wall-clock time for the sandbox run.
        memory_mb: Hard memory cap inside the container (RSS + swap).
    """

    metrics: List[MetricRule] = field(default_factory=list)
    timeout_seconds: int = 30
    memory_mb: int = 512


@dataclass(frozen=True)
class TaskConfig:
    """Fully resolved configuration for a single evaluation task.

    This is the top-level object returned by :func:`load_task_config`.
    """

    id: str
    title: str
    type: str
    difficulty: str
    source: str
    languages: List[str]
    test_cases_path: str
    evaluation: EvaluationConfig
    tags: List[str] = field(default_factory=list)
    reward_virtual: int = 0
    # Catch-all for any extra fields the YAML may carry.
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TaskConfig":
        """Build a ``TaskConfig`` from a parsed YAML mapping."""
        eval_raw = d.get("evaluation", {})

        metrics_raw: List[Dict[str, Any]] = eval_raw.get("metrics", [])
        metrics = [
            MetricRule(
                name=m["name"],
                enabled=m.get("enabled", True),
                fail_on=m.get("fail_on"),
                rules={k: v for k, v in m.items() if k not in ("name", "enabled", "fail_on")},
            )
            for m in metrics_raw
        ]

        evaluation = EvaluationConfig(
            metrics=metrics,
            timeout_seconds=eval_raw.get("timeout_seconds", 30),
            memory_mb=eval_raw.get("memory_mb", 512),
        )

        known = {
            "id", "title", "type", "difficulty", "source",
            "languages", "test_cases_path", "evaluation",
            "tags", "reward_virtual",
        }
        extra = {k: v for k, v in d.items() if k not in known}

        return cls(
            id=_required_str(d, "id"),
            title=_required_str(d, "title"),
            type=_required_str(d, "type"),
            difficulty=_required_str(d, "difficulty"),
            source=_required_str(d, "source"),
            languages=list(d.get("languages", [])),
            test_cases_path=_required_str(d, "test_cases_path"),
            evaluation=evaluation,
            tags=list(d.get("tags", [])),
            reward_virtual=int(d.get("reward_virtual", 0)),
            extra=extra,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_task_config(path: os.PathLike) -> TaskConfig:
    """Load and validate a ``task-spec.yaml`` from *path*.

    Args:
        path: Filesystem path to the YAML file.

    Returns:
        A validated :class:`TaskConfig` instance.

    Raises:
        FileNotFoundError: The file does not exist.
        ValueError: The YAML content is invalid or required fields are missing.
        RuntimeError: ``pyyaml`` is not installed.
    """
    if yaml is None:  # pragma: no cover
        raise RuntimeError(
            "The 'pyyaml' package is required but not installed. "
            "Install it with: pip install pyyaml"
        )

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Task config not found: {path}")

    raw: Dict[str, Any]
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML from {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"YAML root must be a mapping, got {type(raw).__name__}")

    return TaskConfig.from_dict(raw)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _required_str(d: Dict[str, Any], key: str) -> str:
    """Return *d[key]* coerced to string, or raise ``ValueError``."""
    val = d.get(key)
    if val is None:
        raise ValueError(f"Missing required field: '{key}'")
    s = str(val).strip()
    if not s:
        raise ValueError(f"Field '{key}' must be a non-empty string")
    return s
