#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from pathlib import Path


def read_lines(path: Path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def stat_payload(path: Path):
    if not path.exists():
        return {"exists": False, "bytes": 0, "updated_at_epoch_ms": None}
    stat = path.stat()
    return {
        "exists": True,
        "bytes": stat.st_size,
        "updated_at_epoch_ms": int(stat.st_mtime_ns / 1_000_000),
    }


def text_from_item(item):
    if not isinstance(item, dict):
        return None

    for key in ("text", "message", "content"):
        value = item.get(key)
        if isinstance(value, str):
            return value

    content = item.get("content")
    if isinstance(content, list):
        parts = []
        for entry in content:
            if isinstance(entry, dict):
                text = entry.get("text") or entry.get("message")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "\n".join(parts)

    return None


def summarize_event(event):
    payload = {"type": event.get("type")}
    item = event.get("item")
    if isinstance(item, dict):
        payload["item_type"] = item.get("type")
        payload["item_id"] = item.get("id")
        text = text_from_item(item)
        if text:
            payload["text"] = text[:500]
    usage = event.get("usage")
    if isinstance(usage, dict):
        payload["usage"] = usage
    thread_id = event.get("thread_id")
    if isinstance(thread_id, str):
        payload["thread_id"] = thread_id
    return payload


def infer_stall_stage(last_event, last_completed_item):
    if not last_event:
        return "no_events"

    event_type = last_event.get("type")
    item_type = None
    if isinstance(last_completed_item, dict):
        item_type = last_completed_item.get("type")

    if event_type == "turn.completed":
        return "after_turn_completed"
    if event_type == "turn.started":
        return "after_turn_started"
    if event_type == "thread.started":
        return "after_thread_started"
    if item_type in {"agent_message", "message"}:
        return "after_agent_message"
    if item_type and ("function" in item_type or "tool" in item_type or "command" in item_type):
        return "after_tool_result"
    if event_type == "item.completed":
        return "after_item_completed"
    if event_type == "item.started":
        return "during_item"
    return "in_turn"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events-log", required=True)
    parser.add_argument("--stderr-log", required=True)
    parser.add_argument("--transcript-log", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    events_log = Path(args.events_log)
    stderr_log = Path(args.stderr_log)
    transcript_log = Path(args.transcript_log)
    output = Path(args.output)

    event_lines = read_lines(events_log)
    stderr_lines = [line for line in read_lines(stderr_log) if line.strip()]
    parse_errors = []
    events = []
    event_types = Counter()
    item_types = Counter()
    last_completed_item = None
    last_agent_message = None
    last_usage = None
    thread_id = None
    turn_started = 0
    turn_completed = 0

    for index, raw_line in enumerate(event_lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            parse_errors.append({"line": index, "error": str(exc), "sample": stripped[:200]})
            continue

        if not isinstance(event, dict):
            parse_errors.append({"line": index, "error": "event is not an object", "sample": stripped[:200]})
            continue

        events.append(event)
        event_type = event.get("type")
        if isinstance(event_type, str):
            event_types[event_type] += 1
        if event_type == "thread.started" and isinstance(event.get("thread_id"), str):
            thread_id = event["thread_id"]
        if event_type == "turn.started":
            turn_started += 1
        if event_type == "turn.completed":
            turn_completed += 1
            if isinstance(event.get("usage"), dict):
                last_usage = event["usage"]

        item = event.get("item")
        if isinstance(item, dict):
            item_type = item.get("type")
            if isinstance(item_type, str):
                item_types[item_type] += 1
            if event_type == "item.completed":
                last_completed_item = {
                    "type": item_type,
                    "id": item.get("id"),
                    "text": (text_from_item(item) or "")[:500] or None,
                }
                if item_type in {"agent_message", "message"}:
                    last_agent_message = text_from_item(item)

    last_event = summarize_event(events[-1]) if events else None
    summary = {
        "json_events_detected": any(event_types),
        "event_count": len(events),
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors[:10],
        "thread_id": thread_id,
        "turn_started": turn_started,
        "turn_completed": turn_completed,
        "event_types": dict(event_types),
        "item_types": dict(item_types),
        "last_event": last_event,
        "last_completed_item": last_completed_item,
        "last_agent_message": last_agent_message,
        "last_usage": last_usage,
        "stall_stage": infer_stall_stage(last_event, last_completed_item),
        "events_log": stat_payload(events_log),
        "stderr_log": stat_payload(stderr_log),
        "transcript_log": stat_payload(transcript_log),
        "stderr_tail": stderr_lines[-20:],
    }

    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
