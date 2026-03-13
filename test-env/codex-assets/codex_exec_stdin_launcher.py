#!/usr/bin/env python3

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: codex_exec_stdin_launcher.py <prompt_file> <command>\n")
        return 2

    prompt_file = sys.argv[1]
    command = sys.argv[2]
    if not command.strip():
        sys.stderr.write("codex stdin launcher: empty command\n")
        return 2
    shell = os.environ.get("SHELL", "").strip() or "/bin/sh"
    argv = [shell, "-lc", command]

    with open(prompt_file, "rb", buffering=0) as handle:
        os.dup2(handle.fileno(), 0)
        os.execvpe(argv[0], argv, os.environ.copy())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
