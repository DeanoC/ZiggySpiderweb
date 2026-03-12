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


def service_name_from_entry(item: dict) -> str | None:
    venom_id = item.get("venom_id")
    if venom_id:
        return str(venom_id)
    path = item.get("path")
    if path and isinstance(path, str) and path.startswith("/services/"):
        return path.removeprefix("/services/").split("/", 1)[0]
    return None


def extract_service_views(entries):
    project_bound = []
    namespace_visible = []
    for item in entries or []:
        if not isinstance(item, dict):
            continue
        service_name = service_name_from_entry(item)
        path = item.get("path")
        if service_name is None:
            continue
        append_unique(namespace_visible, service_name)
        if path and isinstance(path, str) and path.startswith("/services/"):
            append_unique(project_bound, service_name)
    return sorted(project_bound), sorted(namespace_visible)


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


def service_reason(
    service: str,
    project_bound_services: list[str],
    namespace_visible_services: list[str],
    bound_reason: str,
    namespace_reason: str,
    missing_reason: str,
):
    if service in project_bound_services:
        return bound_reason, "project_bound"
    if service in namespace_visible_services:
        return namespace_reason, "namespace_visible_only"
    return missing_reason, "missing"


def add_gap(
    candidate_gaps: list[dict],
    seen_gap_ids: set[str],
    venom_id: str,
    reason: str,
    observed_paths: list[str],
    service_state: str | None,
    resolution_hint: str,
):
    if venom_id in seen_gap_ids:
        return
    seen_gap_ids.add(venom_id)
    candidate_gaps.append(
        {
            "venom_id": venom_id,
            "reason": reason,
            "observed_paths": observed_paths[:5],
            "service_state": service_state,
            "resolution_hint": resolution_hint,
        }
    )


def markdown_report(payload: dict) -> str:
    lines = [
        "# Codex Usage Report",
        "",
        f"- Reliability: {'ok' if payload.get('reliability_ok') else 'issue'}",
        f"- Workspace Bootstrap: {'ok' if payload.get('workspace_bootstrap_ok') else 'issue'}",
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

    if payload.get("external_prereqs_observed"):
        lines.extend(["", "## External Prereqs"])
        for key, values in payload["external_prereqs_observed"].items():
            lines.append(f"- {key}: {', '.join(values[:5])}")

    if payload.get("bootstrap_provenance"):
        provenance = payload["bootstrap_provenance"]
        lines.extend(["", "## Bootstrap Provenance"])
        lines.append(f"- required reads complete: {provenance.get('required_reads_complete')}")
        lines.append(f"- agent bootstrap actions: {len(provenance.get('agent_bootstrap_actions_after_mount', []))}")
        for item in provenance.get("agent_bootstrap_actions_after_mount", [])[:8]:
            lines.append(f"- {item['action']}: {item['path']}")

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
    mounted_service_entries = parse_json_file(Path(args.mounted_services))
    project_bound_services, namespace_visible_services = extract_service_views(mounted_service_entries)
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
    bootstrap_reads = []
    bootstrap_actions = []
    persistent_changes = []
    ephemeral_changes = []
    required_bootstrap_paths = [
        str((mount_root / "meta" / "protocol.json").resolve()),
        str((mount_root / "projects" / args.project_id / "meta" / "mounted_services.json").resolve()),
        str((mount_root / "projects" / args.project_id / "meta" / "workspace_status.json").resolve()),
        str((mount_root / "projects" / args.project_id / "meta" / "venom_packages.json").resolve()),
        str((mount_root / "projects" / args.project_id / "meta" / "agent_bootstrap.json").resolve()),
    ]

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

            if normalized_path in required_bootstrap_paths:
                append_unique(bootstrap_reads, normalized_path)

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

            if category == "mounted_workspace" and is_write(syscall, line):
                action = None
                change_scope = None
                if normalized_path.endswith("/services/home/control/ensure.json"):
                    action = "home_ensure"
                    change_scope = "persistent"
                elif normalized_path.endswith("/services/mounts/control/bind.json"):
                    action = "mounts_bind"
                    change_scope = "persistent"
                elif normalized_path.endswith("/services/mounts/control/unbind.json"):
                    action = "mounts_unbind"
                    change_scope = "persistent"
                elif normalized_path.endswith("/services/mounts/control/mount.json"):
                    action = "mounts_mount"
                    change_scope = "persistent"
                elif normalized_path.endswith("/services/mounts/control/unmount.json"):
                    action = "mounts_unmount"
                    change_scope = "persistent"
                elif normalized_path.endswith("/services/workers/control/register.json"):
                    action = "workers_register"
                    change_scope = "ephemeral"
                elif normalized_path.endswith("/services/workers/control/heartbeat.json"):
                    action = "workers_heartbeat"
                    change_scope = "ephemeral"
                elif normalized_path.endswith("/services/workers/control/detach.json"):
                    action = "workers_detach"
                    change_scope = "ephemeral"
                if action:
                    event = {"action": action, "path": normalized_path}
                    if event not in bootstrap_actions:
                        bootstrap_actions.append(event)
                    if change_scope == "persistent":
                        append_unique(persistent_changes, action)
                    elif change_scope == "ephemeral":
                        append_unique(ephemeral_changes, action)

            if is_write(syscall, line) and normalized_path not in ALLOWED_SPECIAL_WRITES and category not in {"mounted_workspace", "mounted_remote_node", "artifact_runtime", "allowed_local_runtime"}:
                if category == "host_local" and path_within_any_root(normalized_path, allowed_host_write_prefixes):
                    append_unique(allowed_host_writes, normalized_path)
                else:
                    append_unique(disallowed_writes, normalized_path)

    candidate_gaps = []
    seen_gap_ids = set()

    external_prereqs_observed = {}
    if codex_runtime_paths:
        external_prereqs_observed["codex_runtime"] = codex_runtime_paths[:10]

    if home_state_paths:
        reason, service_state = service_reason(
            "home",
            project_bound_services,
            namespace_visible_services,
            "Codex touched host home/config paths even though /services/home was bound.",
            "Codex touched host home/config paths and home was only namespace-visible, not project-bound under /services.",
            "Codex touched host home/config paths and no home surface was visible in the namespace.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "codex_home", reason, home_state_paths, service_state, "blocked_until_agent_runtime_support")

    if terminal_runtime_commands:
        reason, service_state = service_reason(
            "terminal",
            project_bound_services,
            namespace_visible_services,
            "Codex executed host shell/coreutils commands even though /services/terminal was bound.",
            "Codex executed host shell/coreutils commands and terminal was only namespace-visible, not project-bound under /services.",
            "Codex executed host shell/coreutils commands and no terminal surface was visible in the namespace.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "terminal_runtime", reason, terminal_runtime_commands, service_state, "blocked_until_agent_runtime_support")

    git_observations = git_runtime_commands + [path for path in git_like_paths if path not in git_runtime_commands]
    if git_observations:
        reason, service_state = service_reason(
            "git",
            project_bound_services,
            namespace_visible_services,
            "Codex used host-local git commands or metadata even though /services/git was bound.",
            "Codex used host-local git commands or metadata and git was only namespace-visible, not project-bound under /services.",
            "Codex used host-local git commands or metadata and no git surface was visible in the namespace.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "git_runtime", reason, git_observations, service_state, "blocked_until_agent_runtime_support")

    if search_code_paths:
        reason, service_state = service_reason(
            "search_code",
            project_bound_services,
            namespace_visible_services,
            "Codex read repo content from the host checkout even though /services/search_code was bound.",
            "Codex read repo content from the host checkout and search_code was only namespace-visible, not project-bound under /services.",
            "Codex read repo content from the host checkout and no search_code surface was visible in the namespace.",
        )
        add_gap(candidate_gaps, seen_gap_ids, "search_code_bridge", reason, search_code_paths, service_state, "workspace_or_launch_isolation_fixable")

    reliability_ok = len(disallowed_writes) == 0 and not args.skipped_reason
    required_reads_complete = all(path in bootstrap_reads for path in required_bootstrap_paths)
    home_bootstrap_done = any(item["action"] == "home_ensure" for item in bootstrap_actions)
    workspace_bootstrap_ok = not args.skipped_reason and required_reads_complete and home_bootstrap_done
    machine_independence_ok = not args.skipped_reason and len(candidate_gaps) == 0

    payload = {
        "ok": reliability_ok,
        "reliability_ok": reliability_ok,
        "workspace_bootstrap_ok": workspace_bootstrap_ok,
        "machine_independence_ok": machine_independence_ok,
        "mode": args.mode,
        "project_id": args.project_id,
        "skipped_reason": args.skipped_reason,
        "project_bound_services": project_bound_services,
        "namespace_visible_services": namespace_visible_services,
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
        "external_prereqs_observed": external_prereqs_observed,
        "candidate_venom_gaps": candidate_gaps,
        "bootstrap_provenance": {
            "required_reads": required_bootstrap_paths,
            "required_reads_seen": bootstrap_reads,
            "required_reads_complete": required_reads_complete,
            "agent_bootstrap_actions_after_mount": bootstrap_actions,
            "persistent_workspace_changes": persistent_changes,
            "ephemeral_agent_changes": ephemeral_changes,
        },
    }

    json_output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_output.write_text(markdown_report(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
