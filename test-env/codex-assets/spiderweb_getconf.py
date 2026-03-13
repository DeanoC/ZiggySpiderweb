#!/usr/bin/env python3

from __future__ import annotations

import os
import sys


VALUES = {
    "LONG_BIT": "64",
    "PAGESIZE": str(os.sysconf("SC_PAGE_SIZE")),
    "PAGE_SIZE": str(os.sysconf("SC_PAGE_SIZE")),
}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write("spiderweb getconf wrapper: expected exactly one variable name\n")
        return 2
    key = argv[0]
    value = VALUES.get(key)
    if value is None:
        sys.stderr.write(f"spiderweb getconf wrapper: unsupported variable {key}\n")
        return 2
    sys.stdout.write(value + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
