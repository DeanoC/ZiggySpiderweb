#!/usr/bin/env python3

import argparse
import glob
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


SYSTEM_PREFIXES = (
    "/bin",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var/lib",
)
WRITE_SYSCALLS = {
    "creat",
    "mkdir",
    "mkdirat",
    "rename",
    "renameat",
    "renameat2",
    "unlink",
    "unlinkat",
    "rmdir",
    "symlink",
    "symlinkat",
    "link",
    "linkat",
    "truncate",
    "ftruncate",
}
PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
SYSCALL_RE = re.compile(r"^(?P<syscall>[a-zA-Z0-9_]+)\(")
HOME_TOKENS = ("/.config/", "/.codex/", "/.ssh/", "/.netrc")
CODEX_RUNTIME_TOKENS = ("/@openai/codex/", "/node_modules/@openai/codex/", "/bin/codex", "/bin/node", "/bin/nodejs")
ALLOWED_SPECIAL_WRITES = {"/dev/null", "/dev/tty", "/dev/ptmx"}


def parse_json_file(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def extract_service_names(entries):
    names = []
    for item in entries or []:
        if isinstance(item, dict):
            venom_id = item.get("venom_id")
            path = item.get("path")
            if venom_id:
                names.append(str(venom_id))
            elif path and isinstance(path, str) and path.startswith("/services/"):
                names.append(path.removeprefix("/services/").split("/", 1)[0])
    return sorted(dict.fromkeys(names))


def extract_package_names(entries):
    names = []
    for item in entries or []:
        if isinstance(item, dict) and item.get("venom_id"):
            names.append(str(item["venom_id"]))
    return sorted(dict.fromkeys(names))


def path_within_root(path: str, root: str) -> bool:
    if not root:
        return False
    normalized_root = root.rstrip("/")
    return path == normalized_root or path.startswith(normalized_root + "/")


def path_within_any_root(path: str, roots: list[Path]) -> bool:
    return any(path_within_root(path, str(root)) for root in roots)


def classify_path(raw_path: str, workspace_root: Path, mount_root: Path, artifact_root: Path, allowed_runtime_roots: list[Path]):
    path = raw_path
    if not path.startswith("/"):
        path = str((workspace_root / path).resolve())

    mount_root_str = str(mount_root)
    artifact_root_str = str(artifact_root)
    shared_root = str((mount_root / "shared_data").resolve())

    if path_within_root(path, shared_root):
        return "mounted_remote_node", path
    if path_within_root(path, mount_root_str):
        return "mounted_workspace", path
    if path_within_root(path, artifact_root_str):
        return "artifact_runtime", path
    for root in allowed_runtime_roots:
        if path_within_root(path, str(root)):
            return "allowed_local_runtime", path
    if any(path_within_root(path, prefix) for prefix in SYSTEM_PREFIXES):
        return "system_runtime", path
    return "host_local", path


def is_write(syscall: str, line: str) -> bool:
    if syscall in WRITE_SYSCALLS:
        return True
    if syscall in {"open", "openat", "openat2"}:
        return any(flag in line for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
    return False


def relevant_raw_path(syscall: str, line: str) -> str | None:
    matches = PATH_RE.findall(line)
    if not matches:
        return None

    if syscall in {"rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"}:
        return matches[-1]
    return matches[0]


def append_unique(items: list[str], value: str):
    if value not in items:
        items.append(value)


def service_reason(service: str, mounted_services: list[str], present_reason: str, missing_reason: str):
    if service in mounted_services:
        return present_reason, True
    return missing_reason, False


def add_gap(candidate_gaps: list[dict], seen_gap_ids: set[str], venom_id: str, reason: str, observed_paths: list[str], service_available: bool | None):
    if venom_id in seen_gap_ids:
        return
    seen_gap_ids.add(venom_id)
    candidate_gaps.append(
        {
            "venom_id": venom_id,
            "reason": reason,
            "observed_paths": observed_paths[:5],
            "service_available": service_available,
        }
    )


def markdown_report(payload: dict) -> str:
    lines = [
        "# Codex Usage Report",
        "",
        f"- Reliability: {'ok' if payload.get('reliability_ok') else 'issue'}",
        f"- Machine Independence: {'ok' if payload.get('machine_independence_ok') else 'issue'}",
        f"- Project ID: {payload.get('project_id')}",
        f"- Mode: {payload.get('mode')}",
    ]
    if payload.get("skipped_reason"):
        lines.append(f"- Skipped Reason: {payload['skipped_reason']}")

    lines.extend(["", "## Access Summary"])
    for key in ("mounted_workspace", "mounted_remote_node", "allowed_local_runtime", "host_local", "system_runtime"):
        section = payload["access_summary"].get(key, {})
        lines.append(f"- {key}: {section.get('count', 0)} accesses")
        samples = section.get("samples", [])
        if samples:
            lines.append(f"  samples: {', '.join(samples[:3])}")

    lines.extend(["", "## Executed Commands"])
    if payload.get("executed_commands"):
        for item in payload["executed_commands"][:10]:
            lines.append(f"- {item}")
    else:
        lines.append("- none recorded")

    lines.extend(["", "## Candidate Venom Gaps"])
    if payload.get("candidate_venom_gaps"):
        for gap in payload["candidate_venom_gaps"]:
            lines.append(f"- {gap['venom_id']}: {gap['reason']}")
    else:
        lines.append("- none inferred")

    if payload.get("allowed_host_writes"):
        lines.extend(["", "## Temporarily Allowed Host Writes"])
        for item in payload["allowed_host_writes"][:10]:
            lines.append(f"- {item}")

    if payload.get("disallowed_writes"):
        lines.extend(["", "## Disallowed Writes"])
        for item in payload["disallowed_writes"][:10]:
            lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strace-prefix", required=True)
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--mount-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--mounted-services", required=True)
    parser.add_argument("--venom-packages", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--allowed-runtime-root", action="append", default=[])
    parser.add_argument("--allowed-host-write-prefix", action="append", default=[])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    parser.add_argument("--skipped-reason")
    args = parser.parse_args()

    json_output = Path(args.json_output)
    markdown_output = Path(args.markdown_output)

    workspace_root = Path(args.workspace_root).resolve()
    mount_root = Path(args.mount_root).resolve()
    artifact_root = Path(args.artifact_root).resolve()
    repo_root = Path(args.repo_root).resolve()
    allowed_runtime_roots = [Path(value).resolve() for value in args.allowed_runtime_root]
    allowed_host_write_prefixes = [Path(value).resolve() for value in args.allowed_host_write_prefix]
    mounted_services = extract_service_names(parse_json_file(Path(args.mounted_services)))
    venom_packages = extract_package_names(parse_json_file(Path(args.venom_packages)))

    counts = Counter()
    samples = defaultdict(list)
    disallowed_writes = []
    allowed_host_writes = []
    executed_commands = []
    host_local_paths = []
    search_code_paths = []
    git_like_paths = []
    home_state_paths = []
    codex_runtime_paths = []
    terminal_runtime_commands = []
    git_runtime_commands = []

    for trace_path in sorted(glob.glob(args.strace_prefix + "*")):
        for raw_line in Path(trace_path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("---") or line.startswith("+++"):
                continue
            syscall_match = SYSCALL_RE.match(line)
            if not syscall_match:
                continue
            syscall = syscall_match.group("syscall")
            raw_path = relevant_raw_path(syscall, line)
            if raw_path is None:
                continue

            raw_path = bytes(raw_path, "utf-8").decode("unicode_escape")
            category, normalized_path = classify_path(raw_path, workspace_root, mount_root, artifact_root, allowed_runtime_roots)
            if category == "artifact_runtime":
                continue

            counts[category] += 1
            append_unique(samples[category], normalized_path)

            if syscall == "execve":
                append_unique(executed_commands, normalized_path)
                command_name = Path(normalized_path).name
                if command_name in {"codex", "node", "nodejs"} or any(token in normalized_path for token in CODEX_RUNTIME_TOKENS):
                    append_unique(codex_runtime_paths, normalized_path)
                elif command_name == "git":
                    append_unique(git_runtime_commands, normalized_path)
                    append_unique(terminal_runtime_commands, normalized_path)
                else:
                    append_unique(terminal_runtime_commands, normalized_path)

            if category == "host_local":
                append_unique(host_local_paths, normalized_path)
                if path_within_root(normalized_path, str(repo_root)):
                    append_unique(search_code_paths, normalized_path)
                if "/.git" in normalized_path or normalized_path.endswith(".git"):
                    append_unique(git_like_paths, normalized_path)
                if any(token in normalized_path for token in HOME_TOKENS):
                    append_unique(home_state_paths, normalized_path)

            if category in {"system_runtime", "allowed_local_runtime"}:
                if any(token in normalized_path for token in CODEX_RUNTIME_TOKENS):
                    append_unique(codex_runtime_paths, normalized_path)

            if is_write(syscall, line) and normalized_path not in ALLOWED_SPECIAL_WRITES and category not in {"mounted_workspace", "mounted_remote_node", "artifact_runtime", "allowed_local_runtime"}:
                if category == "host_local" and path_within_any_root(normalized_path, allowed_host_write_prefixes):
                    append_unique(allowed_host_writes, normalized_path)
                else:
                    append_unique(disallowed_writes, normalized_path)

    candidate_gaps = []
    seen_gap_ids = set()

    if codex_runtime_paths:
        add_gap(
            candidate_gaps,
            seen_gap_ids,
            "codex_runtime",
            "Plain Codex CLI and/or Node runtime executed locally instead of coming from the mounted Spiderweb environment.",
            codex_runtime_paths,
            None,
        )

    if home_state_paths:
        reason, service_available = service_reason(
            "home",
            mounted_services,
            "Codex touched host home/config paths even though a home surface was mounted.",
            "Codex touched host home/config paths and no mounted home surface was available.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "codex_home", reason, home_state_paths, service_available)

    if terminal_runtime_commands:
        reason, service_available = service_reason(
            "terminal",
            mounted_services,
            "Codex executed host shell/coreutils commands even though a terminal surface was mounted.",
            "Codex executed host shell/coreutils commands and no mounted terminal surface was available.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "terminal_runtime", reason, terminal_runtime_commands, service_available)

    git_observations = git_runtime_commands + [path for path in git_like_paths if path not in git_runtime_commands]
    if git_observations:
        reason, service_available = service_reason(
            "git",
            mounted_services,
            "Codex used host-local git commands or metadata even though a git surface was mounted.",
            "Codex used host-local git commands or metadata and no mounted git surface was available.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "git_runtime", reason, git_observations, service_available)

    if search_code_paths:
        reason, service_available = service_reason(
            "search_code",
            mounted_services,
            "Codex read repo content from the host checkout even though a search_code surface was mounted.",
            "Codex read repo content from the host checkout and no mounted search_code surface was available.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "search_code_bridge", reason, search_code_paths, service_available)

    reliability_ok = len(disallowed_writes) == 0 and not args.skipped_reason
    machine_independence_ok = not args.skipped_reason and len(candidate_gaps) == 0

    payload = {
        "ok": reliability_ok,
        "reliability_ok": reliability_ok,
        "machine_independence_ok": machine_independence_ok,
        "mode": args.mode,
        "project_id": args.project_id,
        "skipped_reason": args.skipped_reason,
        "mounted_services": mounted_services,
        "venom_packages": venom_packages,
        "access_summary": {
            key: {
                "count": counts.get(key, 0),
                "samples": samples.get(key, [])[:10],
            }
            for key in ("mounted_workspace", "mounted_remote_node", "allowed_local_runtime", "host_local", "system_runtime")
        },
        "executed_commands": executed_commands[:50],
        "allowed_host_write_prefixes": [str(value) for value in allowed_host_write_prefixes],
        "allowed_host_writes": allowed_host_writes[:50],
        "disallowed_writes": disallowed_writes[:50],
        "writes_outside_mount": disallowed_writes[:50],
        "candidate_venom_gaps": candidate_gaps,
    }

    json_output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_output.write_text(markdown_report(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
