"""
Tests for evaluation metrics.

Tests are structured as plain unit tests that exercise the metric functions
in isolation (without a live Docker daemon).  The sandbox result is mocked
so that we can verify metric logic independently.
"""

from __future__ import annotations

import json
import pytest

from eval_engine.config import TaskConfig, EvaluationConfig, MetricRule
from eval_engine.runner import SandboxResult
from eval_engine.metrics import (
    metric_functional_pass,
    metric_security_pass,
    metric_cheat_score,
    evaluate_all,
    EvaluationResults,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_task() -> TaskConfig:
    """A minimal TaskConfig for testing."""
    return TaskConfig(
        id="test-task-001",
        title="Test Task",
        type="code",
        difficulty="easy",
        source="test",
        languages=["python"],
        test_cases_path="/app/test_cases.json",
        evaluation=EvaluationConfig(
            metrics=[
                MetricRule(name="functional_pass", enabled=True),
                MetricRule(name="security_pass", enabled=True),
                MetricRule(name="cheat_score", enabled=True),
            ],
            timeout_seconds=30,
            memory_mb=256,
        ),
        tags=["test"],
        reward_virtual=10,
    )


@pytest.fixture
def success_sandbox() -> SandboxResult:
    """A sandbox result where tests passed."""
    return SandboxResult(
        stdout="All tests passed!\n",
        stderr="",
        exit_code=0,
        timed_out=False,
        wall_time_ms=120,
    )


@pytest.fixture
def failure_sandbox() -> SandboxResult:
    """A sandbox result where tests failed."""
    return SandboxResult(
        stdout="FAIL: test_addition\n",
        stderr="AssertionError: 2 + 2 != 5\n",
        exit_code=1,
        timed_out=False,
        wall_time_ms=80,
    )


@pytest.fixture
def timeout_sandbox() -> SandboxResult:
    """A sandbox result that timed out."""
    return SandboxResult(
        stdout="",
        stderr="Execution timed out after 30s",
        exit_code=-1,
        timed_out=True,
        wall_time_ms=30000,
    )


# ---------------------------------------------------------------------------
# functional_pass
# ---------------------------------------------------------------------------


class TestFunctionalPass:
    def test_passes_when_exit_zero(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        result = metric_functional_pass("print('ok')", sample_task, success_sandbox)
        assert result.passed is True
        assert result.score == 1.0
        assert result.name == "functional_pass"

    def test_fails_when_exit_nonzero(self, sample_task: TaskConfig, failure_sandbox: SandboxResult) -> None:
        result = metric_functional_pass("print('ok')", sample_task, failure_sandbox)
        assert result.passed is False
        assert result.score == 0.0

    def test_fails_when_timed_out(self, sample_task: TaskConfig, timeout_sandbox: SandboxResult) -> None:
        result = metric_functional_pass("print('ok')", sample_task, timeout_sandbox)
        assert result.passed is False
        assert result.score == 0.0
        assert "timed out" in result.details.lower()


# ---------------------------------------------------------------------------
# security_pass
# ---------------------------------------------------------------------------


class TestSecurityPass:
    def test_clean_code_passes(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = """
def add(a, b):
    return a + b

result = add(2, 2)
print(result)
"""
        result = metric_security_pass(code, sample_task, success_sandbox)
        assert result.passed is True
        assert result.score == 1.0

    def test_hardcoded_admin_bypass(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = 'is_admin = True\nif user == "admin":\n    print("bypass")'
        result = metric_security_pass(code, sample_task, success_sandbox)
        assert result.passed is False
        assert result.score < 1.0

    def test_dangerous_system_call(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = "import os\nos.system('rm -rf /')"
        result = metric_security_pass(code, sample_task, success_sandbox)
        assert result.passed is False
        assert result.score < 1.0

    def test_eval_detected(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = 'result = eval(user_input)'
        result = metric_security_pass(code, sample_task, success_sandbox)
        assert result.passed is False

    def test_sql_concat_detected(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = """query = "SELECT * FROM users WHERE id = " + user_id"""
        result = metric_security_pass(code, sample_task, success_sandbox)
        assert result.passed is False
        assert "SQL injection" in result.details


# ---------------------------------------------------------------------------
# cheat_score
# ---------------------------------------------------------------------------


class TestCheatScore:
    def test_clean_code_low_score(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = "x = 1\ny = 2\nprint(x + y)"
        result = metric_cheat_score(code, sample_task, success_sandbox)
        assert result.score < 0.3
        assert result.passed is True

    def test_cheating_code_high_score(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = """
# expected: 42
is_admin = True
expected_output = "the answer is 42"
print(expected_output)
"""
        result = metric_cheat_score(code, sample_task, success_sandbox)
        assert result.score > 0
        assert result.passed is False or result.score >= 0.3


# ---------------------------------------------------------------------------
# evaluate_all (integration)
# ---------------------------------------------------------------------------


class TestEvaluateAll:
    def test_all_metrics_run(self, sample_task: TaskConfig, success_sandbox: SandboxResult) -> None:
        code = "print('hello world')"
        results = evaluate_all(code, sample_task, success_sandbox)
        assert isinstance(results, EvaluationResults)
        assert results.task_id == "test-task-001"
        assert len(results.metrics) == 3
        # clean code → functional pass, security pass, cheat_score pass
        assert results.overall_passed is True

    def test_cheating_code_flagged(self, sample_task: TaskConfig, failure_sandbox: SandboxResult) -> None:
        code = """
os.system('cat /etc/passwd')
eval(input())
# expected: secret_flag
exec("malicious_code")
"""
        results = evaluate_all(code, sample_task, failure_sandbox)
        assert results.malicious_code_found is True
        assert results.cheat_score > 0.5
        # security pass should fail
        sec = [m for m in results.metrics if m.name == "security_pass"]
        assert len(sec) == 1
        assert sec[0].passed is False

    def test_unknown_metric_returns_failure(self, success_sandbox: SandboxResult) -> None:
        """A metric with no handler should produce a failed result, not crash."""
        task = TaskConfig(
            id="unknown-metric",
            title="Test",
            type="code",
            difficulty="easy",
            source="test",
            languages=["python"],
            test_cases_path="nope",
            evaluation=EvaluationConfig(
                metrics=[MetricRule(name="nonexistent_metric", enabled=True)],
            ),
        )
        results = evaluate_all("print(1)", task, success_sandbox)
        assert len(results.metrics) == 1
        assert results.metrics[0].passed is False
        assert "No handler" in results.metrics[0].details
