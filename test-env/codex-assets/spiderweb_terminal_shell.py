#!/usr/bin/env python3

from __future__ import annotations

import os
import sys

from spiderweb_bridge_common import BridgeError, invoke_terminal_exec, map_mount_to_runtime_cwd


def extract_command(argv: list[str]) -> str:
    args = list(argv)
    while args:
        token = args.pop(0)
        if token == "-c":
            if not args:
                raise BridgeError("shell bridge expected a command after -c")
            return args.pop(0)
        if token.startswith("-") and "c" in token:
            if not args:
                raise BridgeError(f"shell bridge expected a command after {token}")
            return args.pop(0)
        if token.startswith("-"):
            continue
        return " ".join([token] + args)
    raise BridgeError("interactive shell bridge mode is not supported")


def main() -> int:
    try:
        command = extract_command(sys.argv[1:])
        timeout_ms = int(os.environ.get("SPIDERWEB_TERMINAL_TIMEOUT_MS", "120000"))
        cwd = map_mount_to_runtime_cwd(os.getcwd())
        output, exit_code = invoke_terminal_exec(command, cwd, timeout_ms)
        if output:
            sys.stdout.write(output)
            sys.stdout.flush()
        return exit_code
    except BridgeError as exc:
        sys.stderr.write(f"spiderweb terminal bridge: {exc}\n")
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
