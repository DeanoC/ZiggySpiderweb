#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
from pathlib import Path

from spiderweb_bridge_common import (
    BridgeError,
    find_git_top_level,
    git_not_repo,
    invoke_git_operation,
    map_mount_to_namespace_path,
)


def split_range(token: str) -> tuple[str, str, bool]:
    if "..." in token:
        base_ref, head_ref = token.split("...", 1)
        return base_ref, head_ref, True
    if ".." in token:
        base_ref, head_ref = token.split("..", 1)
        return base_ref, head_ref, False
    raise BridgeError(f"unsupported git diff range: {token}")


def parse_cwd_and_args(argv: list[str]) -> tuple[Path, list[str]]:
    args = list(argv)
    cwd = Path.cwd()
    while len(args) >= 2 and args[0] == "-C":
        cwd = (cwd / args[1]).resolve() if not Path(args[1]).is_absolute() else Path(args[1]).resolve()
        args = args[2:]
    return cwd, args


def handle_rev_parse(repo_root: Path, args: list[str]) -> int:
    if not args:
        raise BridgeError("unsupported git rev-parse invocation")
    if args == ["--show-toplevel"]:
        sys.stdout.write(str(repo_root) + "\n")
        return 0
    if args == ["--is-inside-work-tree"]:
        sys.stdout.write("true\n")
        return 0
    raise BridgeError(f"unsupported git rev-parse invocation: {' '.join(args)}")


def handle_status(repo_root: Path, args: list[str]) -> int:
    payload = {
        "checkout_path": map_mount_to_namespace_path(repo_root),
        "timeout_ms": int(os.environ.get("SPIDERWEB_GIT_TIMEOUT_MS", "30000")),
    }
    result = invoke_git_operation("status", payload, payload["timeout_ms"])
    detail = result.get("result") or {}
    if "--short" in args or "--porcelain" in args or not args:
        text = detail.get("status_short", "")
        if text:
            sys.stdout.write(text)
            if not text.endswith("\n"):
                sys.stdout.write("\n")
        return 0
    raise BridgeError(f"unsupported git status invocation: {' '.join(args)}")


def handle_diff(repo_root: Path, args: list[str]) -> int:
    name_only = "--name-only" in args
    stat = "--stat" in args
    if not name_only and not stat:
        raise BridgeError(f"unsupported git diff invocation: {' '.join(args)}")
    range_token = next((item for item in args if ".." in item), None)
    if not range_token:
        raise BridgeError(f"unsupported git diff invocation without explicit range: {' '.join(args)}")
    base_ref, head_ref, symmetric = split_range(range_token)
    payload = {
        "checkout_path": map_mount_to_namespace_path(repo_root),
        "base_ref": base_ref,
        "head_ref": head_ref,
        "symmetric": symmetric,
        "timeout_ms": int(os.environ.get("SPIDERWEB_GIT_TIMEOUT_MS", "30000")),
    }
    result = invoke_git_operation("diff_range", payload, payload["timeout_ms"])
    detail = result.get("result") or {}
    if name_only:
        changed_files = detail.get("changed_files") or []
        if changed_files:
            sys.stdout.write("\n".join(str(item) for item in changed_files) + "\n")
        return 0
    diff_stat = detail.get("diff_stat", "")
    if diff_stat:
        sys.stdout.write(diff_stat)
        if not diff_stat.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def main() -> int:
    try:
        cwd, args = parse_cwd_and_args(sys.argv[1:])
        if not args:
            raise BridgeError("interactive git bridge mode is not supported")
        repo_root = find_git_top_level(cwd)
        if repo_root is None:
            return git_not_repo()

        command = args[0]
        subargs = args[1:]
        if command == "rev-parse":
            return handle_rev_parse(repo_root, subargs)
        if command == "status":
            return handle_status(repo_root, subargs)
        if command == "diff":
            return handle_diff(repo_root, subargs)
        raise BridgeError(f"unsupported git command: {command}")
    except BridgeError as exc:
        sys.stderr.write(f"spiderweb git shim: {exc}\n")
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
