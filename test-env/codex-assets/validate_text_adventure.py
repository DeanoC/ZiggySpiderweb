#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path


REQUIRED_SHARED_INPUTS = [
    "/shared_data/world_seed.json",
    "/shared_data/items_seed.json",
    "/shared_data/puzzle_seed.json",
]
EXPECTED_VICTORY = "VICTORY: Lantern of Nine Paths recovered"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def emit(output_path: Path | None, payload: dict) -> int:
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if output_path is not None:
        output_path.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if payload.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--shared-data", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    shared_data = Path(args.shared_data).resolve()
    output_path = Path(args.output).resolve() if args.output else None

    game_path = workspace / "game.py"
    manifest_path = workspace / "game_manifest.json"
    walkthrough_path = workspace / "walkthrough.txt"

    checks: list[dict] = []

    for label, path in (
        ("game.py", game_path),
        ("game_manifest.json", manifest_path),
        ("walkthrough.txt", walkthrough_path),
    ):
        checks.append(
            {
                "check": f"{label}_exists",
                "ok": path.is_file(),
                "detail": str(path),
            }
        )

    if not all(item["ok"] for item in checks):
        return emit(
            output_path,
            {
                "ok": False,
                "checks": checks,
                "error": "missing required output files",
            },
        )

    manifest = load_json(manifest_path)
    world_seed = load_json(shared_data / "world_seed.json")
    items_seed = load_json(shared_data / "items_seed.json")
    puzzle_seed = load_json(shared_data / "puzzle_seed.json")

    actual_location_names = [item.get("name") for item in manifest.get("locations", [])]
    actual_item_names = [item.get("name") for item in manifest.get("items", [])]
    actual_puzzle_ids = {item.get("id") for item in manifest.get("puzzles", [])}

    expected_location_names = [item["name"] for item in world_seed["locations"]]
    expected_item_names = [item["name"] for item in items_seed["items"]]
    expected_puzzle_ids = {item["id"] for item in puzzle_seed["puzzles"]}

    checks.extend(
        [
            {
                "check": "location_count",
                "ok": len(actual_location_names) == 10,
                "detail": len(actual_location_names),
            },
            {
                "check": "item_count",
                "ok": len(actual_item_names) == 10,
                "detail": len(actual_item_names),
            },
            {
                "check": "locations_match_seed",
                "ok": actual_location_names == expected_location_names,
                "detail": actual_location_names,
            },
            {
                "check": "items_match_seed",
                "ok": actual_item_names == expected_item_names,
                "detail": actual_item_names,
            },
            {
                "check": "required_puzzles_present",
                "ok": expected_puzzle_ids.issubset(actual_puzzle_ids),
                "detail": sorted(actual_puzzle_ids),
            },
            {
                "check": "shared_data_inputs",
                "ok": manifest.get("shared_data_inputs") == REQUIRED_SHARED_INPUTS,
                "detail": manifest.get("shared_data_inputs"),
            },
            {
                "check": "victory_text",
                "ok": manifest.get("victory_text") == EXPECTED_VICTORY,
                "detail": manifest.get("victory_text"),
            },
            {
                "check": "entrypoint",
                "ok": manifest.get("entrypoint") == "game.py",
                "detail": manifest.get("entrypoint"),
            },
            {
                "check": "walkthrough_pointer",
                "ok": manifest.get("walkthrough") == "walkthrough.txt",
                "detail": manifest.get("walkthrough"),
            },
        ]
    )

    walkthrough = walkthrough_path.read_text(encoding="utf-8")
    run = subprocess.run(
        [sys.executable, str(game_path)],
        input=walkthrough,
        text=True,
        capture_output=True,
        cwd=workspace,
        timeout=30,
        check=False,
    )

    combined_output = (run.stdout or "") + ("\n" + run.stderr if run.stderr else "")
    checks.extend(
        [
            {
                "check": "game_exit_code",
                "ok": run.returncode == 0,
                "detail": run.returncode,
            },
            {
                "check": "victory_seen_in_output",
                "ok": EXPECTED_VICTORY in combined_output,
                "detail": combined_output[-4000:],
            },
        ]
    )

    return emit(
        output_path,
        {
            "ok": all(item["ok"] for item in checks),
            "checks": checks,
            "stdout": run.stdout,
            "stderr": run.stderr,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
