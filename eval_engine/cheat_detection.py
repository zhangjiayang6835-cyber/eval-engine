"""
Cheat-signal detection for untrusted submissions.

Analyses source code for patterns that indicate cheating: hardcoded admin
bypasses, dangerous system calls, string-concatenated SQL, use of ``eval``/
``exec``, and hardcoded expected outputs.

Each detector is a standalone function that returns a ``CheatSignal`` (or
``None``) so they can be composed, tested, and extended independently.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheatSignal:
    """A single detected cheat signal.

    Attributes:
        name: Short machine-readable identifier (e.g. ``hardcoded_bypass``).
        description: Human-readable explanation of what was found.
        severity: 0.0 (info) … 1.0 (critical).
        snippet: The offending line(s) from the source, if available.
        line_number: Approximate line number in the submission.
    """

    name: str
    description: str
    severity: float = 0.5
    snippet: Optional[str] = None
    line_number: Optional[int] = None


@dataclass(frozen=True)
class CheatSignals:
    """Collection of all detected cheat signals for one submission.

    Attributes:
        signals: All individual signals found.
        malicious_code_found: ``True`` if any signal reaches severity ≥ 0.8.
        cheat_score: Aggregated score in ``[0, 1]`` (see :meth:`aggregate`).
    """

    signals: List[CheatSignal] = field(default_factory=list)
    malicious_code_found: bool = False
    cheat_score: float = 0.0

    @classmethod
    def aggregate(cls, signals: List[CheatSignal]) -> "CheatSignals":
        """Combine a list of signals into a single result.

        The aggregate cheat score is the root-mean-square (RMS) of individual
        severities, capped at 1.0.  If any signal has severity ≥ 0.8 the
        submission is flagged as *malicious*.
        """
        if not signals:
            return cls(signals=[], malicious_code_found=False, cheat_score=0.0)

        n = len(signals)
        rms = (sum(s.severity ** 2 for s in signals) / n) ** 0.5
        cheat_score = min(rms, 1.0)
        malicious = any(s.severity >= 0.8 for s in signals)

        return cls(
            signals=signals,
            malicious_code_found=malicious,
            cheat_score=cheat_score,
        )


# ---------------------------------------------------------------------------
# Top-level API
# ---------------------------------------------------------------------------


def detect_all_cheat_signals(source_code: str) -> CheatSignals:
    """Run all built-in cheat detectors on *source_code*.

    Args:
        source_code: The raw source code submitted for evaluation.

    Returns:
        An aggregated :class:`CheatSignals` result.
    """
    detectors = [
        detect_hardcoded_admin_bypass,
        detect_dangerous_system_calls,
        detect_suspicious_patterns,
        detect_eval_exec,
        detect_hardcoded_expected_output,
    ]

    signals: List[CheatSignal] = []
    for detector in detectors:
        try:
            result = detector(source_code)
            if result is not None:
                signals.append(result)
        except Exception:
            # A failing detector should not break the whole pipeline.
            pass

    return CheatSignals.aggregate(signals)


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def detect_hardcoded_admin_bypass(source_code: str) -> Optional[CheatSignal]:
    """Look for hardcoded role checks or admin bypass logic.

    Patterns include: ``is_admin = True``, ``role == "admin"``, hardcoded
    password comparisons, and ``if user == "admin"``.
    """
    patterns: List[tuple[str, Pattern[str], float]] = [
        (
            "Hardcoded admin role assignment",
            re.compile(
                r"(is_admin|isAdmin|admin_role|role)\s*=\s*(True|'admin'|\"admin\")",
                re.IGNORECASE,
            ),
            0.75,
        ),
        (
            "Hardcoded admin bypass condition",
            re.compile(
                r"(if|elif)\s+.*(user|name|username)\s*(==|is|!=)\s*['\"]admin['\"]",
                re.IGNORECASE,
            ),
            0.8,
        ),
        (
            "Hardcoded password comparison",
            re.compile(
                r"(password|passwd|pwd)\s*(==|!=|is not|is)\s*['\"][^'\"]{3,}['\"]",
                re.IGNORECASE,
            ),
            0.6,
        ),
    ]

    for description, regex, severity in patterns:
        match = regex.search(source_code)
        if match:
            _line = _line_containing(source_code, match.start())
            return CheatSignal(
                name="hardcoded_admin_bypass",
                description=description,
                severity=severity,
                snippet=_line,
                line_number=_line_number(source_code, match.start()),
            )
    return None


def detect_dangerous_system_calls(source_code: str) -> Optional[CheatSignal]:
    """Detect risky subprocess / shell invocations.

    Flags use of ``subprocess``, ``os.system``, ``os.popen``, ``shutil``,
    ``ctypes``, and ``pickle`` (deserialisation of untrusted data).
    """
    dangerous_patterns = {
        r"subprocess\.(call|Popen|run|check_output|check_call)": (
            "Direct subprocess invocation",
            0.7,
        ),
        r"os\.system\s*\(": ("os.system call", 0.7),
        r"os\.popen\s*\(": ("os.popen call", 0.7),
        r"os\.execv|[ept]?": ("os.exec family call", 0.8),
        r"ctypes\.(CDLL|cdll|windll|oledll)": ("Native code loading via ctypes", 0.85),
        r"pickle\.(load|loads)\s*\(": ("Unsafe pickle deserialisation", 0.75),
    }

    for regex_str, (description, severity) in dangerous_patterns.items():
        match = re.search(regex_str, source_code)
        if match:
            _line = _line_containing(source_code, match.start())
            return CheatSignal(
                name="dangerous_system_calls",
                description=description,
                severity=severity,
                snippet=_line,
                line_number=_line_number(source_code, match.start()),
            )
    return None


def detect_suspicious_patterns(source_code: str) -> Optional[CheatSignal]:
    """Flag obfuscated or clearly suspicious code patterns.

    This includes base64-encoded strings, ``exec`` with encoded payloads,
    ``__import__`` shenanigans, and attempts to monkey-patch builtins.
    """
    suspicious: List[tuple[str, Pattern[str], float]] = [
        (
            "Base64-encoded payload",
            re.compile(r"base64\.(b64decode|b64encode|decodebytes)"),
            0.6,
        ),
        (
            "Dynamic __import__ with string argument",
            re.compile(r"__import__\s*\(\s*['\"]"),
            0.65,
        ),
        (
            "Built-in monkey-patching attempt",
            re.compile(
                r"(__builtins__|builtins)\s*\.\s*\w+\s*=\s*",
                re.IGNORECASE,
            ),
            0.7,
        ),
        (
            "Suspicious getattr / setattr on builtins",
            re.compile(
                r"(getattr|setattr)\s*\(\s*(__builtins__|builtins)",
                re.IGNORECASE,
            ),
            0.7,
        ),
        (
            "Potential code obfuscation — hex/oct strings evaluated",
            re.compile(r"""['\"][\\]x[0-9a-fA-F]{2}['\"]"""),
            0.5,
        ),
    ]

    for description, regex, severity in suspicious:
        match = regex.search(source_code)
        if match:
            _line = _line_containing(source_code, match.start())
            return CheatSignal(
                name="suspicious_patterns",
                description=description,
                severity=severity,
                snippet=_line,
                line_number=_line_number(source_code, match.start()),
            )
    return None


def detect_eval_exec(source_code: str) -> Optional[CheatSignal]:
    """Detect use of ``eval`` / ``exec`` with user-controlled data.

    A bare ``eval`` or ``exec`` on a literal string is suspicious; one that
    references a parameter or stdin is considered a cheat attempt.
    """
    # We use the AST to distinguish calls from variable references.
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        # Fall back to regex for syntactically invalid snippets.
        return _eval_exec_regex_fallback(source_code)

    visitor = _EvalExecVisitor()
    visitor.visit(tree)
    if visitor.found:
        return CheatSignal(
            name="eval_exec_detection",
            description="Code uses eval() or exec() with dynamic input",
            severity=0.8,
            snippet=visitor.snippet,
            line_number=visitor.line_number,
        )
    return None


def detect_hardcoded_expected_output(source_code: str) -> Optional[CheatSignal]:
    """Flag submissions that contain the expected answer verbatim.

    Looks for comments like ``# expected: ...`` or ``EXPECTED_OUTPUT = ...``
    or a string that looks like a pre-computed answer (e.g. a long hex hash
    or a numeric constant assigned to ``answer`` / ``result``).
    """
    patterns: List[tuple[str, Pattern[str], float]] = [
        (
            "Hardcoded expected output in comment",
            re.compile(r"#\s*(expected|answer|result)\s*[:=]\s*.+", re.IGNORECASE),
            0.7,
        ),
        (
            "Hardcoded answer variable",
            re.compile(
                r"(expected_output|EXPECTED_OUTPUT|correct_answer|CORRECT_OUTPUT)\s*=",
                re.IGNORECASE,
            ),
            0.65,
        ),
        (
            "Hardcoded output via print of constant",
            re.compile(r"""print\s*\(\s*['\"]{3}.+['\"]{3}\s*\)""", re.DOTALL),
            0.5,
        ),
    ]

    for description, regex, severity in patterns:
        match = regex.search(source_code)
        if match:
            _line = _line_containing(source_code, match.start())
            return CheatSignal(
                name="hardcoded_expected_output",
                description=description,
                severity=severity,
                snippet=_line,
                line_number=_line_number(source_code, match.start()),
            )
    return None


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


class _EvalExecVisitor(ast.NodeVisitor):
    """AST visitor that flags ``eval`` and ``exec`` calls."""

    def __init__(self) -> None:
        self.found = False
        self.snippet: Optional[str] = None
        self.line_number: Optional[int] = None

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("eval", "exec"):
            self.found = True
            self.line_number = getattr(node, "lineno", None)
            self.snippet = ast.get_source_segment(source_code, node)  # type: ignore[arg-type]
        self.generic_visit(node)


def _eval_exec_regex_fallback(source_code: str) -> Optional[CheatSignal]:
    """Regex-based fallback when AST parsing fails."""
    match = re.search(
        r"""(?:^|\n)\s*(eval|exec)\s*\("""
        r"""(?:['\"].+['\"]|input|sys\.stdin|request|data|payload)""",
        source_code,
        re.IGNORECASE,
    )
    if match:
        return CheatSignal(
            name="eval_exec_detection",
            description="Code uses eval() or exec() with dynamic input (regex fallback)",
            severity=0.8,
            snippet=match.group(),
            line_number=_line_number(source_code, match.start()),
        )
    return None


def _line_containing(source: str, pos: int) -> str:
    """Return the source line around *pos*, stripped."""
    start = source.rfind("\n", 0, pos) + 1
    end = source.find("\n", pos)
    if end == -1:
        end = len(source)
    return source[start:end].strip()


def _line_number(source: str, pos: int) -> int:
    """Return the 1-based line number for character offset *pos*."""
    return source[:pos].count("\n") + 1
