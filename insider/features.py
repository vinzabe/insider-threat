"""Feature extraction for per-user-day activity.

The detector operates on a fixed-width vector per ``UserActivity``.
Five families:

  * volume        -- counts per event type
  * temporal      -- off-hours fraction, weekend flag, hour-bucket spread
  * file          -- sensitive-path hit count, write fraction, total bytes
  * comms         -- email size & attach count, personal-domain fraction,
                     external-host count
  * exfil hints   -- USB write bytes, cloud-storage host hits, DLP alerts

The schema is fixed; ``feature_names()`` is the contract the persisted
detector verifies on load.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Sequence

import numpy as np

from .events import EventType, UserActivity
from .synth import CLOUD_HOSTS, INTERNAL_DOMAINS, PERSONAL_DOMAINS

SENSITIVE_PREFIXES = (
    "/finance/", "/payroll/", "/strategy/", "/board/", "/hr/",
    "/etc/shadow", "/customer", "_pii", "credentials",
)


def feature_names() -> List[str]:
    return [
        # volume
        "vol_login_count",
        "vol_login_failed",
        "vol_file_access",
        "vol_file_write",
        "vol_email_count",
        "vol_email_total_bytes",
        "vol_email_total_attach",
        "vol_usb_count",
        "vol_usb_total_bytes",
        "vol_web_count",
        "vol_web_total_bytes",
        "vol_dlp_alerts",
        # temporal
        "temp_off_hours_frac",
        "temp_active_hour_count",
        "temp_late_night_events",
        "temp_event_hour_entropy",
        # file
        "file_sensitive_hits",
        "file_unique_paths",
        "file_write_frac",
        # comms
        "comms_personal_domain_frac",
        "comms_external_recipient_count",
        "comms_max_email_size",
        "comms_mean_email_attach",
        # exfil hints
        "exfil_cloud_host_hits",
        "exfil_usb_write_bytes",
        "exfil_max_email_to_personal",
        "exfil_personal_self_email",
    ]


FEATURE_NAMES: List[str] = feature_names()


def _entropy(counts) -> float:
    counts = [c for c in counts if c > 0]
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts)


def _is_off_hours(hour: int) -> bool:
    return hour < 7 or hour >= 20


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.rsplit("@", 1)[-1].lower()
    return addr.lower()


def extract_user_day_features(activity: UserActivity) -> np.ndarray:
    events = activity.events

    # volume
    n_login = sum(1 for e in events if e.event_type == EventType.LOGIN)
    n_login_fail = sum(
        1 for e in events
        if e.event_type == EventType.LOGIN and e.attrs.get("success") is False
    )
    n_file = sum(1 for e in events if e.event_type == EventType.FILE_ACCESS)
    n_file_write = sum(
        1 for e in events
        if e.event_type == EventType.FILE_ACCESS and e.attrs.get("op") == "write"
    )
    n_email = sum(1 for e in events if e.event_type == EventType.EMAIL_SEND)
    email_bytes = sum(
        int(e.attrs.get("size_bytes", 0))
        for e in events if e.event_type == EventType.EMAIL_SEND
    )
    email_attach = sum(
        int(e.attrs.get("attachment_count", 0))
        for e in events if e.event_type == EventType.EMAIL_SEND
    )
    n_usb = sum(1 for e in events if e.event_type == EventType.USB)
    usb_bytes = sum(
        int(e.attrs.get("bytes", 0))
        for e in events if e.event_type == EventType.USB and e.attrs.get("op") == "write"
    )
    n_web = sum(1 for e in events if e.event_type == EventType.WEB)
    web_bytes = sum(
        int(e.attrs.get("bytes", 0))
        for e in events if e.event_type == EventType.WEB
    )
    n_dlp = sum(1 for e in events if e.event_type == EventType.DLP_ALERT)

    # temporal
    hours = [e.hour for e in events]
    off_hours_count = sum(1 for h in hours if _is_off_hours(h))
    off_hours_frac = (off_hours_count / max(1, len(hours)))
    active_hours = len(set(hours))
    late_night = sum(1 for h in hours if 1 <= h <= 5)
    hour_entropy = _entropy(Counter(hours).values())

    # file
    paths = [
        str(e.attrs.get("path", ""))
        for e in events if e.event_type == EventType.FILE_ACCESS
    ]
    sensitive_hits = sum(1 for p in paths if any(s in p.lower() for s in SENSITIVE_PREFIXES))
    unique_paths = len(set(paths))
    file_write_frac = (n_file_write / n_file) if n_file else 0.0

    # comms
    email_recipients = [
        str(e.attrs.get("to", ""))
        for e in events if e.event_type == EventType.EMAIL_SEND
    ]
    personal = [r for r in email_recipients if _domain_of(r) in PERSONAL_DOMAINS]
    external = [r for r in email_recipients if _domain_of(r) not in INTERNAL_DOMAINS]
    personal_frac = (len(personal) / len(email_recipients)) if email_recipients else 0.0
    max_email_size = max(
        (int(e.attrs.get("size_bytes", 0))
         for e in events if e.event_type == EventType.EMAIL_SEND),
        default=0,
    )
    mean_attach = (email_attach / n_email) if n_email else 0.0

    # exfil hints
    web_hosts = [
        str(e.attrs.get("host", "")) for e in events if e.event_type == EventType.WEB
    ]
    cloud_hits = sum(1 for h in web_hosts if h in CLOUD_HOSTS)
    self_email = sum(
        1 for e in events
        if e.event_type == EventType.EMAIL_SEND
        and activity.user_id in str(e.attrs.get("to", "")).lower()
        and _domain_of(str(e.attrs.get("to", ""))) in PERSONAL_DOMAINS
    )
    max_email_personal = max(
        (
            int(e.attrs.get("size_bytes", 0))
            for e in events
            if e.event_type == EventType.EMAIL_SEND
            and _domain_of(str(e.attrs.get("to", ""))) in PERSONAL_DOMAINS
        ),
        default=0,
    )

    vec = [
        float(n_login), float(n_login_fail),
        float(n_file), float(n_file_write),
        float(n_email), float(email_bytes), float(email_attach),
        float(n_usb), float(usb_bytes),
        float(n_web), float(web_bytes),
        float(n_dlp),
        float(off_hours_frac), float(active_hours), float(late_night), float(hour_entropy),
        float(sensitive_hits), float(unique_paths), float(file_write_frac),
        float(personal_frac), float(len(set(external))),
        float(max_email_size), float(mean_attach),
        float(cloud_hits), float(usb_bytes),
        float(max_email_personal), float(self_email),
    ]
    assert len(vec) == len(FEATURE_NAMES), (len(vec), len(FEATURE_NAMES))
    return np.asarray(vec, dtype=np.float64)


class UserFeatureExtractor:
    def __init__(self) -> None:
        self.names = list(FEATURE_NAMES)

    def transform(self, activities: Sequence[UserActivity]) -> np.ndarray:
        if not activities:
            return np.zeros((0, len(self.names)), dtype=np.float64)
        rows = [extract_user_day_features(a) for a in activities]
        return np.vstack(rows)

    def feature_names(self) -> List[str]:
        return list(self.names)
