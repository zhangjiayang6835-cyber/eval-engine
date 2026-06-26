"""
Docker sandbox executor.

Spins up a temporary container from a pre-built sandbox image, copies the
submission code and test cases, runs them under strict resource limits, and
returns stdout / stderr / exit code / timeout flag.

The caller is responsible for having the Docker engine available and the
sandbox image built (see ``Dockerfile`` in the project root).
"""

from __future__ import annotations

import io
import json
import os
import socket
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import docker
    from docker.errors import DockerException, ImageNotFound, APIError
except ImportError:  # pragma: no cover
    docker = None  # type: ignore[assignment]

from .config import TaskConfig


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxResult:
    """Outcome of a single sandboxed execution.

    Attributes:
        stdout: Standard output captured from the container.
        stderr: Standard error captured from the container.
        exit_code: Exit code of the main process (``-1`` if timed out).
        timed_out: ``True`` when the container was killed due to timeout.
        wall_time_ms: Wall-clock duration of the run in milliseconds.
    """

    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    wall_time_ms: int = 0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class DockerSandboxRunner:
    """Execute untrusted submission code inside a Docker container.

    Typical usage::

        runner = DockerSandboxRunner(image_tag="eval-sandbox:latest")
        result = runner.run(
            submission_code="print('hello')",
            task=task_config,
            test_cases=b"...",
        )
    """

    def __init__(
        self,
        image_tag: str = "eval-sandbox:latest",
        docker_sock: Optional[str] = None,
        network_disabled: bool = True,
        remove_on_exit: bool = True,
    ) -> None:
        """Initialise the runner.

        Args:
            image_tag: Name of the Docker image to use as sandbox.
            docker_sock: Path to the Docker daemon socket.  ``None`` uses
                the default (``unix:///var/run/docker.sock`` on Linux /
                ``npipe:////./pipe/docker_engine`` on Windows).
            network_disabled: When ``True`` the container gets ``--network none``.
            remove_on_exit: Automatically delete the container after execution.
        """
        if docker is None:  # pragma: no cover
            raise RuntimeError(
                "The 'docker' Python package is required. "
                "Install it with: pip install docker"
            )

        self.image_tag = image_tag
        self.network_disabled = network_disabled
        self.remove_on_exit = remove_on_exit

        # Docker client — honour DOCKER_HOST env-var if no explicit socket given.
        if docker_sock:
            self._client = docker.DockerClient(base_url=docker_sock)
        else:
            self._client = docker.from_env()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        submission_code: str,
        task: TaskConfig,
        test_cases: Optional[bytes] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """Execute *submission_code* in the sandbox.

        Args:
            submission_code: Source code to evaluate (e.g. a Python script).
            task: The parsed task configuration (used for timeouts, memory
                limits, and language info).
            test_cases: Optional gzipped or raw archive of test-case files
                that will be placed inside the working directory.
            environment: Optional extra environment variables for the container.

        Returns:
            A :class:`SandboxResult` with captured output and metadata.

        Raises:
            RuntimeError: If the Docker image is missing or the container
                could not be started.
        """
        self._ensure_image()

        # Prepare run script
        run_script, filename = self._build_run_script(submission_code, task.languages)
        start = time.monotonic()

        container = None
        try:
            container = self._client.containers.create(
                image=self.image_tag,
                command=["python", "-u", run_script],
                working_dir="/app",
                mem_limit=f"{task.evaluation.memory_mb}m",
                memswap_limit=f"{task.evaluation.memory_mb}m",  # no swap
                cpu_period=100000,
                cpu_quota=100000,  # 1 CPU core
                network_disabled=self.network_disabled,
                read_only=True,
                environment=environment or {},
                hostname="sandbox",
                detach=True,
            )

            # Copy submission script into the container
            self._put_file(container, run_script, submission_code.encode("utf-8"))

            # Copy test cases if provided
            if test_cases:
                for dest, content in self._unpack_test_cases(test_cases):
                    self._put_file(container, dest, content)

            # Start and wait with timeout
            container.start()
            exit_data = container.wait(timeout=task.evaluation.timeout_seconds)
            timed_out = False

        except docker.errors.ContainerError as exc:
            # Container exited with non-zero code — still capture output.
            exit_data = {"StatusCode": exc.exit_status}
            timed_out = False
        except docker.errors.APIError as exc:
            # Docker daemon error — still capture exit status.
            timed_out = False
            exit_data = {"StatusCode": exc.exit_status if hasattr(exc, 'exit_status') else -1}
        except socket.timeout:
            timed_out = True
            exit_data = {"StatusCode": -1}
        except Exception:
            # All other errors treated as timeout.
            timed_out = True
            exit_data = {"StatusCode": -1}

        finally:
            wall_ms = int((time.monotonic() - start) * 1000)

        # Fetch logs (best-effort if container was already removed).
        stdout = stderr = ""
        if container is not None:
            try:
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            except Exception:
                pass

        if container is not None and self.remove_on_exit:
            try:
                container.remove(force=True)
            except Exception:
                pass

        return SandboxResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_data.get("StatusCode", -1),
            timed_out=timed_out,
            wall_time_ms=wall_ms,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_image(self) -> None:
        """Verify the sandbox image exists locally; raise if not."""
        try:
            self._client.images.get(self.image_tag)
        except ImageNotFound:
            raise RuntimeError(
                f"Docker image '{self.image_tag}' not found. "
                f"Build it with: docker build -t {self.image_tag} -f Dockerfile ."
            )

    @staticmethod
    def _build_run_script(
        code: str, languages: List[str]
    ) -> Tuple[str, str]:
        """Wrap the submission code in a small runner script.

        Returns ``(script_name, script_content)``.
        """
        # Currently supports Python. Extend here for Node/Go/other languages.
        script = "runner.py"
        imports = "\n".join(
            "import sys, json, os, subprocess, time, math, random"
        )
        body = (
            f"{imports}\n\n"
            f"# === SUBMISSION CODE ===\n"
            f"{code}\n"
            f"# === END SUBMISSION CODE ===\n"
        )
        return script, body

    @staticmethod
    def _put_file(
        container: "docker.models.containers.Container",
        dest: str,
        content: bytes,
    ) -> None:
        """Write *content* as a file inside *container* via ``put_archive``."""
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            info = tarfile.TarInfo(name=dest)
            info.size = len(content)
            info.mtime = int(time.time())
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
        stream.seek(0)
        container.put_archive("/app", stream)

    @staticmethod
    def _unpack_test_cases(
        data: bytes,
    ) -> List[Tuple[str, bytes]]:
        """Convert raw test-case bytes into ``(path, content)`` pairs.

        If *data* looks like a JSON list of ``{path, content}`` objects it is
        decoded directly; otherwise the caller can pass any format and a single
        file ``test_cases.json`` is created.
        """
        # Try JSON array of {path, content}
        try:
            items = json.loads(data)
            if isinstance(items, list):
                result: List[Tuple[str, bytes]] = []
                for item in items:
                    p = item.get("path", f"test_{len(result)}.txt")
                    c = item.get("content", "")
                    result.append((p, c.encode("utf-8")))
                return result
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: single blob → one file
        return [("test_cases.json", data)]
