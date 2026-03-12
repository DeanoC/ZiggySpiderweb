#!/usr/bin/env python3

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_CASES = [
    "v0.110.0-json-no-pty",
    "v0.111.0-json-no-pty",
    "v0.111.0-json-pty",
    "v0.112.0-json-no-pty",
]

CASE_FILES = [
    "case_summary.json",
    "codex_exec_summary.json",
    "codex_prompt.txt",
    "codex_usage_report.json",
    "codex_usage_report.md",
    "game_validation.json",
]

CASE_SUBTREE_FILES = [
    "codex_handoff/README.md",
    "codex_handoff/codex_runtime.json",
    "snapshots/codex_runtime.json",
    "snapshots/mounted_services.json",
    "snapshots/protocol.json",
    "snapshots/venom_packages.json",
    "snapshots/workspace_status.json",
    "logs/codex.stdout.log",
    "logs/codex.stderr.log",
    "logs/codex.pty.log",
]


def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def copy_if_exists(source: Path, destination: Path):
    if not source.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


def find_case_dir(source_dirs, case_name):
    candidates = []
    for source_dir in source_dirs:
        candidate = source_dir / case_name
        if candidate.is_dir() and (candidate / "case_summary.json").exists():
            candidates.append(candidate)
    if not candidates:
        return None
    return max(candidates, key=lambda path: (path / "case_summary.json").stat().st_mtime_ns)


def summarize_case(case_summary, exec_summary):
    return {
        "case_name": case_summary.get("case_name"),
        "codex_cli_version": case_summary.get("resolved_codex_version") or case_summary.get("codex_cli_version"),
        "use_pty": case_summary.get("use_pty"),
        "json_events": case_summary.get("json_events"),
        "disable_collaboration_modes": case_summary.get("disable_collaboration_modes"),
        "handoff_reason": case_summary.get("handoff_reason"),
        "harness_exit_code": case_summary.get("harness_exit_code"),
        "stall_stage": case_summary.get("stall_stage"),
        "last_event_type": case_summary.get("last_event_type"),
        "last_completed_item_type": case_summary.get("last_completed_item_type"),
        "last_agent_message": case_summary.get("last_agent_message"),
        "event_count": case_summary.get("event_count"),
        "turn_completed": case_summary.get("turn_completed"),
        "selected_auth_mode": case_summary.get("selected_auth_mode"),
        "json_events_detected": case_summary.get("json_events_detected"),
        "last_started_item_type": ((exec_summary or {}).get("last_event") or {}).get("item_type"),
    }


def build_bug_report(bundle_dir: Path, repo_root: Path, system_info: dict, cases: list[dict], missing_cases: list[str]) -> str:
    lines = [
        "# External Codex `exec` Stall Repro",
        "",
        "## Summary",
        "",
        "Codex `exec` stalls during a real Spiderweb-mounted workspace flow before it writes any deliverables.",
        "Across the included cases, Codex never reaches `turn.completed`, never emits the final write step, and never creates the expected game files under the writable mounted workspace.",
        "",
        "## Environment",
        "",
        f"- Repo root: `{repo_root}`",
        f"- Git commit: `{system_info.get('git_commit') or 'unknown'}`",
        f"- Git status dirty: `{system_info.get('git_dirty')}`",
        f"- Host platform: `{system_info.get('platform')}`",
        f"- Python: `{system_info.get('python_version')}`",
        f"- Node: `{system_info.get('node_version') or 'unavailable'}`",
        f"- npm: `{system_info.get('npm_version') or 'unavailable'}`",
        f"- Captured at: `{system_info.get('captured_at')}`",
        "",
        "## Scenario",
        "",
        "- Linux host installs Spiderweb with the repo-local installer.",
        "- Spiderweb starts with a separate runtime root.",
        "- A clean local `spiderweb-fs-node` is mounted at `/nodes/local/fs`.",
        "- A second standalone node is mounted at `/shared_data`.",
        "- Codex runs via `codex exec` against the mounted workspace with `--skip-git-repo-check`, `--dangerously-bypass-approvals-and-sandbox`, `--ephemeral`, and `--json`.",
        "- The prompt asks Codex to read mounted metadata, consume the shared seed files, and generate `game.py`, `game_manifest.json`, `walkthrough.txt`, and `README.md` under `/nodes/local/fs`.",
        "",
        "## Expected",
        "",
        "- Codex completes the turn, writes the deliverables, and the validator passes.",
        "",
        "## Actual",
        "",
        "- Codex emits some early discovery/progress events, then stops.",
        "- No case reaches `turn.completed`.",
        "- No case creates the required game files in the writable mounted workspace.",
        "",
        "## Case Matrix",
        "",
        "| Case | Version | PTY | JSON | Exit | Handoff | Stall | Last Event | Last Item |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for case in cases:
        lines.append(
            "| {case_name} | {version} | {pty} | {json_events} | {exit_code} | {handoff} | {stall} | {last_event} | {last_item} |".format(
                case_name=case.get("case_name", ""),
                version=case.get("codex_cli_version", ""),
                pty="yes" if case.get("use_pty") else "no",
                json_events="yes" if case.get("json_events") else "no",
                exit_code=case.get("harness_exit_code"),
                handoff=case.get("handoff_reason") or "",
                stall=case.get("stall_stage") or "",
                last_event=case.get("last_event_type") or "",
                last_item=case.get("last_completed_item_type") or "",
            )
        )

    lines.extend([
        "",
        "## Shared Invariants",
        "",
        "- All included cases stop before any final write step is visible in the JSON event stream.",
        "- The writable mounted project tree stays at the seeded state only.",
        "- The failure is not limited to a single Codex CLI version.",
        "- PTY wrapping changes the visible stopping point, but does not fix the problem.",
        "",
        "## Per-Case Notes",
        "",
    ])

    for case in cases:
        lines.extend([
            f"### `{case.get('case_name')}`",
            "",
            f"- Codex version: `{case.get('codex_cli_version')}`",
            f"- PTY: `{'yes' if case.get('use_pty') else 'no'}`",
            f"- Handoff reason: `{case.get('handoff_reason')}`",
            f"- Stall stage: `{case.get('stall_stage')}`",
            f"- Event count: `{case.get('event_count')}`",
            f"- Last event type: `{case.get('last_event_type')}`",
            f"- Last completed item type: `{case.get('last_completed_item_type')}`",
        ])
        if case.get("last_started_item_type") and case.get("last_started_item_type") != case.get("last_completed_item_type"):
            lines.append(f"- Last started item type: `{case.get('last_started_item_type')}`")
        if case.get("last_agent_message"):
            lines.append(f"- Last agent message: {case.get('last_agent_message')}")
        lines.append("")

    if missing_cases:
        lines.extend([
            "## Missing Cases",
            "",
            "These requested/default cases were not found in the provided source directories:",
        ])
        for case_name in missing_cases:
            lines.append(f"- `{case_name}`")
        lines.append("")

    lines.extend([
        "## Included Artifacts",
        "",
        "- `cases/<case>/codex_prompt.txt`",
        "- `cases/<case>/codex_exec_summary.json`",
        "- `cases/<case>/case_summary.json`",
        "- `cases/<case>/logs/codex.stdout.log`",
        "- `cases/<case>/logs/codex.stderr.log`",
        "- `cases/<case>/logs/codex.pty.log` when PTY mode was used",
        "- `cases/<case>/snapshots/*.json` for mounted metadata and Codex runtime snapshot",
        "- `source_summaries/*.json` and `source_summaries/*.md` from the matrix runs",
        "",
        "Review host-specific absolute paths before sharing the bundle outside the team.",
        "",
    ])

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--source-dir", action="append", default=[])
    parser.add_argument("--case-name", action="append", default=[])
    parser.add_argument("--include-strace", action="store_true")
    args = parser.parse_args()

    bundle_dir = Path(args.output_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    source_dirs = [Path(item).resolve() for item in args.source_dir if Path(item).exists()]
    case_names = args.case_name or DEFAULT_CASES

    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "cases").mkdir(exist_ok=True)
    (bundle_dir / "source_summaries").mkdir(exist_ok=True)

    system_info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "node_version": run_command(["node", "--version"]),
        "npm_version": run_command(["npm", "--version"]),
        "git_commit": run_command(["git", "rev-parse", "HEAD"], cwd=repo_root),
        "git_status": run_command(["git", "status", "--short"], cwd=repo_root) or "",
        "captured_at": run_command(["date", "--iso-8601=seconds"]) or "",
    }
    system_info["git_dirty"] = bool(system_info["git_status"])

    copied_source_summaries = []
    for source_dir in source_dirs:
        for name in ("matrix_summary.json", "matrix_summary.md"):
            source_file = source_dir / name
            if source_file.exists():
                destination = bundle_dir / "source_summaries" / f"{source_dir.name}-{name}"
                copy_if_exists(source_file, destination)
                copied_source_summaries.append(str(destination.relative_to(bundle_dir)))

    included_cases = []
    missing_cases = []

    for case_name in case_names:
        source_case_dir = find_case_dir(source_dirs, case_name)
        if source_case_dir is None:
            missing_cases.append(case_name)
            continue

        destination_case_dir = bundle_dir / "cases" / case_name
        destination_case_dir.mkdir(parents=True, exist_ok=True)

        for relative_path in CASE_FILES + CASE_SUBTREE_FILES:
            copy_if_exists(source_case_dir / relative_path, destination_case_dir / relative_path)

        if args.include_strace and (source_case_dir / "logs").is_dir():
            for trace_file in sorted((source_case_dir / "logs").glob("codex.strace*")):
                copy_if_exists(trace_file, destination_case_dir / "logs" / trace_file.name)

        case_summary = read_json(source_case_dir / "case_summary.json") or {}
        exec_summary = read_json(source_case_dir / "codex_exec_summary.json") or {}
        included_cases.append(summarize_case(case_summary, exec_summary))

    included_cases.sort(key=lambda item: item.get("case_name") or "")

    manifest = {
        "repo_root": str(repo_root),
        "bundle_dir": str(bundle_dir),
        "source_dirs": [str(item) for item in source_dirs],
        "requested_case_names": case_names,
        "included_case_names": [item.get("case_name") for item in included_cases],
        "missing_case_names": missing_cases,
        "include_strace": args.include_strace,
        "source_summaries": copied_source_summaries,
        "system_info": system_info,
        "cases": included_cases,
    }

    (bundle_dir / "repro_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    readme_lines = [
        "# External Codex Repro Bundle",
        "",
        "This bundle packages the most relevant artifacts from real Spiderweb-mounted Codex CLI runs.",
        "",
        f"- Included cases: {', '.join(manifest['included_case_names']) or 'none'}",
        f"- Missing requested cases: {', '.join(missing_cases) or 'none'}",
        f"- Source directories: {', '.join(manifest['source_dirs']) or 'none'}",
        f"- Include strace: {args.include_strace}",
        "",
        "Primary files:",
        "",
        "- `BUG_REPORT.md`",
        "- `repro_manifest.json`",
        "- `source_summaries/`",
        "- `cases/`",
        "",
    ]
    (bundle_dir / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8")

    bug_report = build_bug_report(bundle_dir, repo_root, system_info, included_cases, missing_cases)
    (bundle_dir / "BUG_REPORT.md").write_text(bug_report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
