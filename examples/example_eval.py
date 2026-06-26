"""
End-to-end demonstration of the eval-engine package.

This script:
  1. Parses a YAML task specification.
  2. Runs the submission code inside a Docker sandbox.
  3. Evaluates functional, security, and cheat-score metrics.
  4. Generates and writes a JSON report.

Usage:
    python examples/example_eval.py

Prerequisites:
    - Docker daemon running.
    - ``eval-sandbox:latest`` image built (``docker build -t eval-sandbox:latest -f Dockerfile .``).
    - The ``eval-engine`` package installed (``pip install -e .``).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure the package is importable when running from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval_engine.config import load_task_config
from eval_engine.runner import DockerSandboxRunner
from eval_engine.metrics import evaluate_all
from eval_engine.reporter import generate_report


# ---------------------------------------------------------------------------
# Demo constants
# ---------------------------------------------------------------------------

SAMPLE_TASK_YAML = """
id: demo-fizzbuzz-001
title: "FizzBuzz Implementation"
type: code
difficulty: easy
source: demo
languages:
  - python
test_cases_path: /app/test_cases.json
evaluation:
  timeout_seconds: 15
  memory_mb: 256
  metrics:
    - name: functional_pass
      enabled: true
    - name: security_pass
      enabled: true
    - name: cheat_score
      enabled: true
tags:
  - demo
  - coding
reward_virtual: 50
"""

# A correct FizzBuzz submission
CORRECT_SUBMISSION = '''def fizzbuzz(n):
    result = []
    for i in range(1, n + 1):
        if i % 15 == 0:
            result.append("FizzBuzz")
        elif i % 3 == 0:
            result.append("Fizz")
        elif i % 5 == 0:
            result.append("Buzz")
        else:
            result.append(str(i))
    return result

# Run test
output = fizzbuzz(15)
for val in output:
    print(val)
'''

# A cheating submission that hardcodes the expected output
CHEATING_SUBMISSION = '''# expected: 1, 2, Fizz, 4, Buzz, Fizz, 7, 8, Fizz, Buzz, 11, Fizz, 13, 14, FizzBuzz
def fizzbuzz(n):
    # Hardcoded bypass
    is_admin = True
    if is_admin:
        return ["1", "2", "Fizz", "4", "Buzz", "Fizz", "7", "8", "Fizz", "Buzz", "11", "Fizz", "13", "14", "FizzBuzz"]

result = fizzbuzz(15)
for r in result:
    print(r)
'''

TEST_CASES_JSON = json.dumps([
    {"path": "test_cases.json", "content": '{"input": 15}'}
]).encode("utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the demo evaluation."""

    # 1. Write the task YAML to a temp file and load it.
    task_path = _REPO_ROOT / "examples" / "task-spec.yaml"
    task_path.write_text(SAMPLE_TASK_YAML, encoding="utf-8")
    print(f"[1] Loaded task config from {task_path}")

    task = load_task_config(task_path)
    print(f"    Task: {task.id} — {task.title}")
    print(f"    Difficulty: {task.difficulty}")
    print(f"    Metrics: {[m.name for m in task.evaluation.metrics]}")

    # 2. Choose submission (toggle comment to try the cheating version).
    submission = CORRECT_SUBMISSION
    # submission = CHEATING_SUBMISSION   # uncomment to test cheat detection
    print(f"\n[2] Submission code ({len(submission)} chars):")
    for line in submission.strip().splitlines()[:5]:
        print(f"    | {line}")
    if submission.count("\n") > 5:
        print(f"    | ... ({submission.count(chr(10)) - 5} more lines)")

    # 3. Run inside Docker sandbox.
    print(f"\n[3] Running in Docker sandbox...")
    # If you haven't built the image, set IMAGE_NOT_FOUND_OK=1 to skip
    skip_docker = os.environ.get("IMAGE_NOT_FOUND_OK", "").strip() in ("1", "yes", "true")
    runner = DockerSandboxRunner(image_tag="eval-sandbox:latest")
    try:
        sandbox_result = runner.run(
            submission_code=submission,
            task=task,
            test_cases=TEST_CASES_JSON,
        )
    except RuntimeError as exc:
        if skip_docker and "not found" in str(exc):
            print(f"    [SKIP] Image not available — using mock result ({exc})")
            from eval_engine.runner import SandboxResult
            sandbox_result = SandboxResult(
                stdout="1\n2\nFizz\n4\nBuzz\nFizz\n7\n8\nFizz\nBuzz\n11\nFizz\n13\n14\nFizzBuzz\n",
                stderr="",
                exit_code=0,
                timed_out=False,
                wall_time_ms=45,
            )
        else:
            print(f"    [ERROR] {exc}")
            print("    Make sure Docker is running and the sandbox image is built:")
            print("      docker build -t eval-sandbox:latest -f Dockerfile .")
            sys.exit(1)

    print(f"    Exit code: {sandbox_result.exit_code}")
    print(f"    Timed out: {sandbox_result.timed_out}")
    print(f"    Wall time: {sandbox_result.wall_time_ms} ms")
    print(f"    Stdout (first 200 chars): {sandbox_result.stdout[:200]!r}")

    # 4. Evaluate all metrics.
    print(f"\n[4] Evaluating metrics...")
    eval_results = evaluate_all(
        submission_code=submission,
        task=task,
        sandbox_result=sandbox_result,
    )
    for m in eval_results.metrics:
        status = "✓ PASS" if m.passed else "✗ FAIL"
        print(f"    {status}  {m.name}: score={m.score:.3f}  {m.details[:80]}")

    print(f"\n    Cheat signals: {len(eval_results.cheat_signals.signals)}")
    for sig in eval_results.cheat_signals.signals:
        print(f"      - [{sig.severity:.2f}] {sig.description}")

    print(f"    Malicious code found: {eval_results.malicious_code_found}")
    print(f"    Overall passed: {eval_results.overall_passed}")

    # 5. Generate report.
    report_path = _REPO_ROOT / "examples" / "eval-report.json"
    print(f"\n[5] Writing report to {report_path}")
    report = generate_report(
        eval_results,
        submission_id="demo-submission-001",
        output_path=report_path,
    )
    print(f"    Report written ({len(report.to_json())} bytes)")

    # 6. Print summary.
    print(f"\n{'='*60}")
    print(f"  EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Task:        {report.task_id}")
    print(f"  Submission:  {report.submission_id}")
    print(f"  Timestamp:   {report.timestamp}")
    print(f"  Passed:      {report.overall_passed}")
    print(f"  Cheat score: {eval_results.cheat_score:.3f}")
    if eval_results.malicious_code_found:
        print(f"  ⚠  MALICIOUS CODE DETECTED")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
