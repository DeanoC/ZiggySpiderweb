#!/usr/bin/env python3

from __future__ import annotations

import sys


INFO = {
    "Distributor ID": "Spiderweb Linux",
    "Description": "Spiderweb Linux",
    "Release": "rolling",
    "Codename": "namespace",
}


def print_value(flag: str) -> int:
    if flag in {"-i", "--id"}:
        sys.stdout.write(f"{INFO['Distributor ID']}\n")
        return 0
    if flag in {"-d", "--description"}:
        sys.stdout.write(f"{INFO['Description']}\n")
        return 0
    if flag in {"-r", "--release"}:
        sys.stdout.write(f"{INFO['Release']}\n")
        return 0
    if flag in {"-c", "--codename"}:
        sys.stdout.write(f"{INFO['Codename']}\n")
        return 0
    if flag in {"-s", "--short"}:
        sys.stdout.write(f"{INFO['Description']}\n")
        return 0
    return 2


def main(argv: list[str]) -> int:
    if not argv or argv == ["-a"] or argv == ["--all"]:
        for key in ("Distributor ID", "Description", "Release", "Codename"):
            sys.stdout.write(f"{key}:\t{INFO[key]}\n")
        return 0
    if len(argv) == 1:
        code = print_value(argv[0])
        if code == 0:
            return 0
    sys.stderr.write("spiderweb lsb_release wrapper: unsupported arguments\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
