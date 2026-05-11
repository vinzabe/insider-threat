"""Event datamodel for insider-threat detection.

We normalise five operationally-collectable signal sources into a
single ``UserEvent`` schema:

  * login        -- workstation / VPN sign-in (success or failure)
  * file_access  -- read / write / delete on a path
  * email_send   -- outbound email with destination + size + attach count
  * usb          -- USB attach / write event with bytes transferred
  * web          -- HTTP(S) request to a host with bytes transferred
  * dlp_alert    -- a DLP system already flagged the user

Per-user, per-day rollups produce the feature vectors the detector
consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class EventType(str, Enum):
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    EMAIL_SEND = "email_send"
    USB = "usb"
    WEB = "web"
    DLP_ALERT = "dlp_alert"


@dataclass(frozen=True)
class UserEvent:
    """One observed user activity event.

    ``timestamp`` is a tz-aware datetime (UTC).  Subschema-specific
    payloads live in ``attrs`` so the event datamodel stays small but
    the parser/feature layer can pick out the dimensions it needs.
    """

    timestamp: datetime
    user_id: str
    event_type: EventType
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def hour(self) -> int:
        return self.timestamp.hour

    @property
    def date_key(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "event_type": self.event_type.value,
            "attrs": dict(self.attrs),
        }


@dataclass
class UserActivity:
    """All events for one (user, day)."""

    user_id: str
    date_key: str
    events: List[UserEvent] = field(default_factory=list)
    role: Optional[str] = None
    label: Optional[str] = None

    def add(self, ev: UserEvent) -> None:
        if ev.user_id != self.user_id:
            raise ValueError(
                f"event user_id {ev.user_id!r} != activity user_id {self.user_id!r}"
            )
        if ev.date_key != self.date_key:
            raise ValueError(
                f"event date {ev.date_key!r} != activity date {self.date_key!r}"
            )
        self.events.append(ev)


@dataclass
class ActivityCorpus:
    """Labelled collection of per-user-day activities."""

    activities: List[UserActivity] = field(default_factory=list)

    def add(self, a: UserActivity) -> None:
        self.activities.append(a)

    def extend(self, items: Iterable[UserActivity]) -> None:
        for a in items:
            self.add(a)

    def labels(self) -> List[str]:
        return [a.label or "unknown" for a in self.activities]

    def by_user(self) -> Dict[str, List[UserActivity]]:
        out: Dict[str, List[UserActivity]] = {}
        for a in self.activities:
            out.setdefault(a.user_id, []).append(a)
        return out

    def __len__(self) -> int:
        return len(self.activities)

    def __iter__(self):
        return iter(self.activities)
