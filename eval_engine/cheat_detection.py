"""
cheat_detection.py — Enhanced Cheat-Signal Detection (v2)

扩展了原始检测器，新增：
- LDAP injection detection
- NoSQL injection detection
- Template injection (SSTI) detection
- Hardcoded cryptographic keys
- Insecure deserialization patterns (pickle, yaml)
- Path traversal in file operations
- Command injection in subprocess wrappers
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Pattern


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheatSignal:
    name: str
    description: str
    severity: float = 0.5
    snippet: Optional[str] = None
    line_number: Optional[int] = None


@dataclass(frozen=True)
class CheatSignals:
    signals: List[CheatSignal] = field(default_factory=list)
    malicious_code_found: bool = False
    cheat_score: float = 0.0

    @classmethod
    def aggregate(cls, signals: List[CheatSignal]) -> "CheatSignals":
        if not signals:
            return cls(signals=[], malicious_code_found=False, cheat_score=0.0)
        n = len(signals)
        rms = (sum(s.severity ** 2 for s in signals) / n) ** 0.5
        cheat_score = min(rms, 1.0)
        malicious = any(s.severity >= 0.8 for s in signals)
        return cls(signals=signals, malicious_code_found=malicious, cheat_score=cheat_score)


# ---------------------------------------------------------------------------
# Top-level API
# ---------------------------------------------------------------------------

def detect_all_cheat_signals(source_code: str) -> CheatSignals:
    """Run all built-in cheat detectors on *source_code*."""
    detectors = [
        detect_hardcoded_admin_bypass,
        detect_dangerous_system_calls,
        detect_suspicious_patterns,
        detect_eval_exec,
        detect_hardcoded_expected_output,
        detect_sql_injection,
        # New detectors
        detect_ldap_injection,
        detect_nosql_injection,
        detect_template_injection,
        detect_hardcoded_crypto_keys,
        detect_insecure_deserialization,
        detect_path_traversal,
        detect_command_injection_in_wrappers,
    ]
    signals: List[CheatSignal] = []
    for detector in detectors:
        try:
            results = detector(source_code)
            if results:
                signals.extend(results)
        except Exception:
            pass
    return CheatSignals.aggregate(signals)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match_all(
    source_code: str,
    patterns: List[tuple[str, Pattern[str], float]],
    signal_name: str,
) -> List[CheatSignal]:
    results: List[CheatSignal] = []
    for description, regex, severity in patterns:
        for match in regex.finditer(source_code):
            results.append(CheatSignal(
                name=signal_name,
                description=description,
                severity=severity,
                snippet=_line_containing(source_code, match.start()),
                line_number=_line_number(source_code, match.start()),
            ))
    return results


def _line_containing(source: str, pos: int) -> Optional[str]:
    lines = source.split("\n")
    offset = 0
    for line in lines:
        offset += len(line) + 1
        if pos < offset:
            return line.strip()
    return None


def _line_number(source: str, pos: int) -> Optional[int]:
    return source[:pos].count("\n") + 1


def _safe_compile_python(code: str) -> Optional[ast.Module]:
    try:
        return ast.parse(code)
    except SyntaxError:
        return None


# ---------------------------------------------------------------------------
# Original detectors
# ---------------------------------------------------------------------------

def detect_hardcoded_admin_bypass(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        ("Hardcoded admin role assignment",
         re.compile(r"(is_admin|isAdmin|admin_role|role)\s*=\s*(True|'admin'|\"admin\")", re.IGNORECASE), 0.75),
        ("Hardcoded admin bypass condition",
         re.compile(r"(if|elif)\s+.*(user|name|username)\s*(==|is|!=)\s*['\"]admin['\"]", re.IGNORECASE), 0.8),
        ("Hardcoded password comparison",
         re.compile(r"(password|passwd|pwd)\s*(==|!=|is not|is)\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE), 0.6),
    ], "hardcoded_admin_bypass")


def detect_dangerous_system_calls(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        (desc, re.compile(pat, re.IGNORECASE), sev)
        for pat, (desc, sev) in {
            r"subprocess\.(call|Popen|run|check_output|check_call)": ("Direct subprocess invocation", 0.7),
            r"os\.system\s*\(": ("os.system shell call", 0.8),
            r"os\.popen\s*\(": ("os.popen pipe call", 0.8),
            r"pty\.spawn\s*\(": ("pty.spawn shell call", 0.7),
        }.items()
    ], "dangerous_system_call")


def detect_suspicious_patterns(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        ("Base64-encoded payload",
         re.compile(r"(base64|b64decode)\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]"), 0.6),
        ("Suspicious hex-encoded string",
         re.compile(r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}"), 0.5),
        ("Obfuscated via chr/ord",
         re.compile(r"chr\(\d{2,}\).*chr\(\d{2,}\)"), 0.4),
    ], "suspicious_pattern")


def detect_eval_exec(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        ("eval() call", re.compile(r"\beval\s*\("), 0.8),
        ("exec() call", re.compile(r"\bexec\s*\("), 0.85),
        ("compile() call", re.compile(r"\bcompile\s*\("), 0.6),
        ("__import__ dynamic import", re.compile(r"__import__\s*\("), 0.5),
    ], "eval_exec")


def detect_hardcoded_expected_output(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        ("Hardcoded test answer",
         re.compile(r"(expected|correct|expected_output)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE), 0.7),
        ("Output hardcoded to pass test",
         re.compile(r"(return|print)\s+['\"](correct|success|passed|true)['\"]", re.IGNORECASE), 0.6),
        ("Result hardcoded to True",
         re.compile(r"result\s*=\s*True\s*#.*?(pass|test|check)", re.IGNORECASE), 0.65),
    ], "hardcoded_output")


def detect_sql_injection(source_code: str) -> List[CheatSignal]:
    return _match_all(source_code, [
        ("String concatenation in SQL query",
         re.compile(r"(execute|executemany|query|raw_query)\s*\(\s*(f['\"]|['\"]\s*\+\s*|['\"].*\{|['\"].*%[sd])"), 0.85),
        ("SQL query with string concatenation",
         re.compile(r"SELECT.*FROM.*WHERE.*['\"]\s*\+\s*\w+\s*\+?\s*['\"]", re.IGNORECASE), 0.85),
        ("SQL query with f-string",
         re.compile(r"(f['\"]|f['\"]).*SELECT.*FROM(?!.*\?)", re.IGNORECASE | re.DOTALL), 0.8),
    ], "sql_injection")


# ---------------------------------------------------------------------------
# New detectors
# ---------------------------------------------------------------------------

def detect_ldap_injection(source_code: str) -> List[CheatSignal]:
    """Detect LDAP injection: user input concatenated into LDAP queries."""
    return _match_all(source_code, [
        ("String concatenation in LDAP query",
         re.compile(r"(search_s|search|search_st)\s*\(\s*['\"].*['\"]\s*\+\s*\w+", re.IGNORECASE), 0.8),
        ("LDAP filter with string formatting",
         re.compile(r"(ldap|ldap3)\..*search.*f['\"]", re.IGNORECASE), 0.75),
    ], "ldap_injection")


def detect_nosql_injection(source_code: str) -> List[CheatSignal]:
    """Detect NoSQL injection: unsanitized input in MongoDB queries."""
    return _match_all(source_code, [
        ("NoSQL query with direct user input",
         re.compile(r"(find|find_one|insert_one|update_one|delete_one)\s*\(\s*\{.*['\"]\s*\+\s*\w+", re.IGNORECASE), 0.8),
        ("NoSQL $where with user input",
         re.compile(r"\$where\s*:?\s*['\"].*\{|f['\"].*\$where", re.IGNORECASE), 0.85),
        ("NoSQL regex injection",
         re.compile(r"(re\.compile|re\.search)\s*\(\s*['\"].*['\"]\s*\+\s*\w+.*\$regex", re.IGNORECASE), 0.7),
    ], "nosql_injection")


def detect_template_injection(source_code: str) -> List[CheatSignal]:
    """Detect Server-Side Template Injection (SSTI)."""
    return _match_all(source_code, [
        ("Template string with user input (SSTI risk)",
         re.compile(r"(render_template_string|Template|template\.render)\s*\(\s*f['\"]", re.IGNORECASE), 0.8),
        ("Jinja2 template with unsanitized input",
         re.compile(r"Jinja2.*\{.*\{.*(?:request\.|input|form)", re.IGNORECASE), 0.7),
        ("Mako template from string",
         re.compile(r"(mako|Template).*from\s+string.*render", re.IGNORECASE), 0.65),
    ], "template_injection")


def detect_hardcoded_crypto_keys(source_code: str) -> List[CheatSignal]:
    """Detect hardcoded cryptographic keys and secrets."""
    return _match_all(source_code, [
        ("Hardcoded AES/DES key",
         re.compile(r"(key|aes_key|secret_key|encryption_key)\s*=\s*['\"][A-Za-z0-9+/=]{16,}['\"]", re.IGNORECASE), 0.75),
        ("Hardcoded JWT secret",
         re.compile(r"(jwt_secret|SECRET_KEY|JWT_SECRET)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), 0.7),
        ("Hardcoded API token in code",
         re.compile(r"(api_key|api_token|access_token|app_secret)\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE), 0.8),
    ], "hardcoded_crypto_key")


def detect_insecure_deserialization(source_code: str) -> List[CheatSignal]:
    """Detect insecure deserialization patterns."""
    return _match_all(source_code, [
        ("pickle.load() on untrusted data",
         re.compile(r"pickle\.loads?\s*\(", re.IGNORECASE), 0.85),
        ("yaml.load() without SafeLoader",
         re.compile(r"yaml\.load\s*\(.*(?!SafeLoader|FullLoader)", re.IGNORECASE), 0.8),
        ("marshal.load() deserialization",
         re.compile(r"marshal\.loads?\s*\(", re.IGNORECASE), 0.75),
    ], "insecure_deserialization")


def detect_path_traversal(source_code: str) -> List[CheatSignal]:
    """Detect path traversal in file operations."""
    return _match_all(source_code, [
        ("open() with user-controlled path",
         re.compile(r"(open|codecs\.open|io\.open)\s*\(\s*\w+\s*\+\s*['\"/]", re.IGNORECASE), 0.75),
        ("os.path.join with .. traversal",
         re.compile(r"os\.path\.join.*\.\.(?:\/|\\\\\\)", re.IGNORECASE), 0.7),
        ("send_file with unsanitized path",
         re.compile(r"(send_file|send_from_directory)\s*\(\s*f['\"]", re.IGNORECASE), 0.8),
    ], "path_traversal")


def detect_command_injection_in_wrappers(source_code: str) -> List[CheatSignal]:
    """Detect command injection in shell wrapper patterns."""
    return _match_all(source_code, [
        ("shell=True in subprocess",
         re.compile(r"subprocess\.(run|Popen|check_output)\s*\(.*shell\s*=\s*True", re.IGNORECASE), 0.85),
        ("os.system with user input",
         re.compile(r"os\.system\s*\(\s*f['\"]", re.IGNORECASE), 0.85),
        ("shlex not used on user input in shell command",
         re.compile(r"(run|Popen)\(\s*f['\"].*\{", re.IGNORECASE), 0.75),
    ], "command_injection")
