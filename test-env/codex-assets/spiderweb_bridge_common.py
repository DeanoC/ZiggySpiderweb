#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - non-unix fallback for completeness
    fcntl = None


class BridgeError(RuntimeError):
    pass


def env_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise BridgeError(f"missing required environment variable: {name}")
    return Path(value)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    content = json.dumps(payload, sort_keys=True) + "\n"
    write_text_without_truncate(path, content)


def write_text_without_truncate(path: Path, content: str) -> None:
    data = content.encode("utf-8")
    try:
        existing_size = path.stat().st_size
    except OSError:
        existing_size = len(data)

    # Mounted service control files do not reliably support local truncate semantics.
    # Overwrite from offset 0 and pad any leftover bytes with whitespace so server-side
    # JSON parsers see only the new payload after trim().
    padding_len = max(0, existing_size - len(data))
    padded = data + (b" " * padding_len)
    fd = os.open(path, os.O_WRONLY)
    try:
        total_written = 0
        while total_written < len(padded):
            written = os.write(fd, padded[total_written:])
            if written <= 0:
                raise BridgeError(f"short write while updating {path}")
            total_written += written
    finally:
        os.close(fd)


@contextmanager
def operation_lock(env_name: str):
    lock_value = os.environ.get(env_name, "").strip()
    if not lock_value or fcntl is None:
        yield
        return

    lock_path = Path(lock_value)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def decode_exec_output(result: dict) -> tuple[str, int]:
    import base64

    body = result.get("result") or {}
    data_b64 = body.get("data_b64", "")
    output = base64.b64decode(data_b64).decode("utf-8", errors="replace") if data_b64 else ""
    exit_code = int(body.get("exit_code", 0))
    return output, exit_code


def wait_for_terminal_result(
    expected_operation: str,
    expected_session_id: str | None,
    timeout_ms: int,
    min_updated_at_ms: int = 0,
) -> dict:
    status_path = env_path("SPIDERWEB_TERMINAL_STATUS_PATH")
    result_path = env_path("SPIDERWEB_TERMINAL_RESULT_PATH")
    deadline = time.time() + max(timeout_ms, 1000) / 1000.0

    while time.time() < deadline:
        try:
            status = read_json(status_path)
            result = read_json(result_path)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            time.sleep(0.05)
            continue

        if result.get("operation") != expected_operation:
            time.sleep(0.05)
            continue
        if expected_session_id is not None and result.get("session_id") != expected_session_id:
            time.sleep(0.05)
            continue
        updated_at_ms = int(status.get("updated_at_ms") or 0)
        if updated_at_ms < min_updated_at_ms:
            time.sleep(0.05)
            continue
        state = status.get("state")
        if state not in {"done", "failed"}:
            time.sleep(0.05)
            continue
        return result

    raise BridgeError(
        f"timed out waiting for terminal result operation={expected_operation} session_id={expected_session_id}"
    )


def invoke_terminal_exec(command: str, cwd: str | None, timeout_ms: int) -> tuple[str, int]:
    exec_path = env_path("SPIDERWEB_TERMINAL_EXEC_PATH")

    with operation_lock("SPIDERWEB_TERMINAL_LOCK_PATH"):
        status_path = env_path("SPIDERWEB_TERMINAL_STATUS_PATH")
        try:
            status = read_json(status_path)
            min_updated_at_ms = int(status.get("updated_at_ms") or 0) + 1
        except Exception:
            min_updated_at_ms = 0

        exec_payload = {"command": command, "timeout_ms": timeout_ms}
        if cwd:
            exec_payload["cwd"] = cwd
        write_json(exec_path, exec_payload)
        result = wait_for_terminal_result("exec", None, timeout_ms, min_updated_at_ms)
        if not result.get("ok", False):
            error = result.get("error") or {}
            message = error.get("message") or "terminal exec failed"
            raise BridgeError(message)
        return decode_exec_output(result)


def wait_for_git_result(expected_operation: str, timeout_ms: int, min_updated_at_ms: int) -> dict:
    status_path = env_path("SPIDERWEB_GIT_STATUS_PATH")
    result_path = env_path("SPIDERWEB_GIT_RESULT_PATH")
    deadline = time.time() + max(timeout_ms, 1000) / 1000.0

    while time.time() < deadline:
        try:
            status = read_json(status_path)
            result = read_json(result_path)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            time.sleep(0.05)
            continue

        if result.get("operation") != expected_operation:
            time.sleep(0.05)
            continue
        updated_at_ms = int(status.get("updated_at_ms") or 0)
        if updated_at_ms < min_updated_at_ms:
            time.sleep(0.05)
            continue
        if status.get("state") not in {"done", "failed"}:
            time.sleep(0.05)
            continue
        return result

    raise BridgeError(f"timed out waiting for git result operation={expected_operation}")


def invoke_git_operation(operation: str, payload: dict, timeout_ms: int) -> dict:
    with operation_lock("SPIDERWEB_GIT_LOCK_PATH"):
        control_path = env_path(f"SPIDERWEB_GIT_{operation.upper()}_PATH")
        status_path = env_path("SPIDERWEB_GIT_STATUS_PATH")
        try:
            status = read_json(status_path)
            min_updated_at_ms = int(status.get("updated_at_ms") or 0) + 1
        except Exception:
            min_updated_at_ms = 0

        write_json(control_path, payload)
        result = wait_for_git_result(operation, timeout_ms, min_updated_at_ms)
        if not result.get("ok", False):
            error = result.get("error") or {}
            message = error.get("message") or f"git {operation} failed"
            raise BridgeError(message)
        return result


def mount_workspace_root() -> Path:
    return env_path("SPIDERWEB_MOUNT_WORKSPACE_ROOT")


def namespace_workspace_root() -> str:
    value = os.environ.get("SPIDERWEB_NAMESPACE_WORKSPACE_ROOT", "").strip()
    if not value:
        raise BridgeError("missing required environment variable: SPIDERWEB_NAMESPACE_WORKSPACE_ROOT")
    return value


def map_mount_to_runtime_cwd(cwd: str) -> str:
    cwd_path = Path(cwd).resolve()
    mount_root = mount_workspace_root().resolve()
    try:
        rel = cwd_path.relative_to(mount_root)
    except ValueError:
        return cwd
    rel_text = rel.as_posix()
    base = namespace_workspace_root().rstrip("/")
    if not rel_text or rel_text == ".":
        return base
    return f"{base}/{rel_text}"


def map_mount_to_namespace_path(path: Path) -> str:
    rel = path.resolve().relative_to(mount_workspace_root().resolve())
    rel_text = rel.as_posix()
    base = namespace_workspace_root().rstrip("/")
    if not rel_text or rel_text == ".":
        return base
    return f"{base}/{rel_text}"


def find_git_top_level(start: Path) -> Path | None:
    mount_root = mount_workspace_root().resolve()
    current = start.resolve()
    while True:
        if (current / ".git").exists():
            return current
        if current == mount_root:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def git_not_repo() -> int:
    sys.stderr.write("fatal: not a git repository (or any of the parent directories): .git\n")
    return 128
