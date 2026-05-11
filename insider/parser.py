"""JSONL parser for activity logs.

Schema (one event per line):
  {"ts": "2025-01-13T14:32:11+00:00", "user_id": "alice",
   "event_type": "file_access", "attrs": {"path": "...", "op": "read", "bytes": 1234}}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Tuple

from .events import EventType, UserActivity, UserEvent


def _parse_ts(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_event(record: dict) -> UserEvent:
    if not isinstance(record, dict):
        raise ValueError("event must be a dict")
    if "user_id" not in record or "event_type" not in record or "ts" not in record:
        raise ValueError("event missing required fields")
    et_raw = str(record["event_type"]).strip()
    try:
        et = EventType(et_raw)
    except ValueError as exc:
        raise ValueError(f"unknown event_type {et_raw!r}") from exc
    ts = _parse_ts(str(record["ts"]))
    attrs = record.get("attrs") or {}
    if not isinstance(attrs, dict):
        attrs = {"raw": attrs}
    return UserEvent(
        timestamp=ts,
        user_id=str(record["user_id"]),
        event_type=et,
        attrs=attrs,
    )


def parse_activity_lines(lines: Iterable[str]) -> List[UserActivity]:
    """Group events into per-(user, day) ``UserActivity`` objects."""

    groups: Dict[Tuple[str, str], UserActivity] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            ev = _coerce_event(rec)
        except (ValueError, KeyError, TypeError):
            continue
        key = (ev.user_id, ev.date_key)
        if key not in groups:
            groups[key] = UserActivity(user_id=ev.user_id, date_key=ev.date_key)
        groups[key].add(ev)
    return list(groups.values())


def parse_activity_jsonl(path: str) -> List[UserActivity]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_activity_lines(fh)
