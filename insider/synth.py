"""Synthetic activity generator.

Real insider-threat datasets (CMU CERT r4.2, etc.) are hard to obtain
and licensed.  We ship a profile-driven generator that mimics the
*statistical shape* of common workforce patterns:

  * developers spend the day in a code-host browser tab, log in
    9-18, sometimes check email at night
  * sales spend the day sending email, occasionally with attachments,
    log in across regional working hours
  * finance read sensitive files in /finance/* during business hours
  * admins authenticate to many hosts, unusual hours expected
  * execs access strategy docs sparingly, send fewer larger emails

Insider scenarios overlay statistical *anomalies* on a benign baseline:

  * data_hoarder    -- spike in file_access to sensitive paths
  * off_hours       -- activity at 02:00-05:00 on a normally-9-to-5 user
  * departing_emp   -- spike in USB writes + personal-email targets
  * privilege_esc   -- failed logins to admin systems then a success
  * exfil_email     -- spike in outbound email size + external domains
  * pii_browser     -- spike in web hits to personal cloud-storage hosts
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence

from .events import EventType, UserActivity, UserEvent

INTERNAL_DOMAINS = ("acmecorp.example", "acme.example")
PERSONAL_DOMAINS = ("gmail.example", "protonmail.example", "outlook.example")
CLOUD_HOSTS = (
    "drive.google.example", "dropbox.example", "wetransfer.example",
    "anonfiles.example", "0bin.example", "mega.example",
)
WORK_HOSTS = (
    "github.acmecorp.example", "wiki.acmecorp.example",
    "jira.acmecorp.example", "docs.acmecorp.example",
)


@dataclass
class UserProfile:
    user_id: str
    role: str  # developer | sales | finance | admin | exec
    work_hours: Sequence[int] = field(default_factory=lambda: tuple(range(9, 19)))
    expected_logins_per_day: int = 4
    expected_file_access_per_day: int = 30
    expected_email_per_day: int = 6
    expected_web_per_day: int = 80
    expected_usb_per_day: int = 0
    sensitive_path_prefixes: Sequence[str] = field(default_factory=tuple)


BENIGN_PROFILES: List[UserProfile] = [
    UserProfile(
        user_id="dev_alice", role="developer",
        work_hours=tuple(range(9, 20)),
        expected_logins_per_day=3, expected_file_access_per_day=60,
        expected_email_per_day=4, expected_web_per_day=140,
        sensitive_path_prefixes=("/repo/",),
    ),
    UserProfile(
        user_id="sales_bob", role="sales",
        work_hours=tuple(range(8, 19)),
        expected_logins_per_day=4, expected_file_access_per_day=20,
        expected_email_per_day=18, expected_web_per_day=80,
        sensitive_path_prefixes=("/crm/",),
    ),
    UserProfile(
        user_id="fin_carol", role="finance",
        work_hours=tuple(range(9, 18)),
        expected_logins_per_day=3, expected_file_access_per_day=40,
        expected_email_per_day=8, expected_web_per_day=50,
        sensitive_path_prefixes=("/finance/", "/payroll/"),
    ),
    UserProfile(
        user_id="adm_dave", role="admin",
        work_hours=tuple(range(7, 22)),
        expected_logins_per_day=10, expected_file_access_per_day=20,
        expected_email_per_day=4, expected_web_per_day=40,
        sensitive_path_prefixes=("/etc/", "/var/log/"),
    ),
    UserProfile(
        user_id="exec_eve", role="exec",
        work_hours=tuple(range(7, 22)),
        expected_logins_per_day=3, expected_file_access_per_day=15,
        expected_email_per_day=12, expected_web_per_day=70,
        sensitive_path_prefixes=("/strategy/", "/board/"),
    ),
]


def _sample_hour(profile: UserProfile, rng: random.Random) -> int:
    # 90% inside work hours, 10% jitter (lunch back-from-laptop, etc.)
    if rng.random() < 0.9:
        return rng.choice(list(profile.work_hours))
    return rng.randint(0, 23)


def _make_ts(date: datetime, hour: int, rng: random.Random) -> datetime:
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    return date.replace(hour=hour, minute=minute, second=second, microsecond=0, tzinfo=timezone.utc)


def _scale(n: int, jitter: float, rng: random.Random) -> int:
    return max(0, int(round(n * (1.0 + rng.uniform(-jitter, jitter)))))


def _normal_paths(profile: UserProfile, rng: random.Random) -> str:
    if rng.random() < 0.4 and profile.sensitive_path_prefixes:
        prefix = rng.choice(list(profile.sensitive_path_prefixes))
        return f"{prefix}{rng.choice(['report', 'doc', 'sheet', 'note'])}_{rng.randint(1, 99)}.txt"
    return rng.choice([
        f"/home/{profile.user_id}/notes_{rng.randint(1, 50)}.md",
        f"/tmp/build_{rng.randint(1, 9999)}.log",
        f"/srv/share/team/{rng.choice(['plan', 'demo', 'status'])}.md",
    ])


def _gen_baseline_day(
    profile: UserProfile, date: datetime, rng: random.Random
) -> UserActivity:
    activity = UserActivity(
        user_id=profile.user_id,
        date_key=date.strftime("%Y-%m-%d"),
        role=profile.role,
        label="benign",
    )

    # logins
    for _ in range(_scale(profile.expected_logins_per_day, 0.3, rng)):
        ts = _make_ts(date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.LOGIN,
            attrs={"host": rng.choice(["ws-1", "ws-2", "vpn-edge"]), "success": True},
        ))

    # file accesses
    for _ in range(_scale(profile.expected_file_access_per_day, 0.3, rng)):
        ts = _make_ts(date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.FILE_ACCESS,
            attrs={
                "path": _normal_paths(profile, rng),
                "op": rng.choice(["read", "read", "read", "write"]),
                "bytes": int(rng.lognormvariate(8.0, 1.0)),
            },
        ))

    # email
    for _ in range(_scale(profile.expected_email_per_day, 0.4, rng)):
        ts = _make_ts(date, _sample_hour(profile, rng), rng)
        is_internal = rng.random() < 0.85
        domain = rng.choice(list(INTERNAL_DOMAINS if is_internal else PERSONAL_DOMAINS))
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.EMAIL_SEND,
            attrs={
                "to": f"colleague_{rng.randint(1, 80)}@{domain}",
                "size_bytes": int(rng.lognormvariate(7.5, 1.2)),
                "attachment_count": rng.choices([0, 0, 0, 1, 1, 2], k=1)[0],
            },
        ))

    # web
    for _ in range(_scale(profile.expected_web_per_day, 0.3, rng)):
        ts = _make_ts(date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.WEB,
            attrs={
                "host": rng.choice(list(WORK_HOSTS)) if rng.random() < 0.85 else rng.choice([
                    "news.example", "stackoverflow.example", "google.example",
                ]),
                "bytes": int(rng.lognormvariate(9.0, 1.2)),
            },
        ))

    # usb (rare for non-admin)
    for _ in range(_scale(profile.expected_usb_per_day, 1.0, rng)):
        ts = _make_ts(date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.USB,
            attrs={"bytes": int(rng.lognormvariate(12.0, 1.0)),
                   "op": rng.choice(["attach", "write"])},
        ))
    return activity


# ----- insider-threat overlays -----


@dataclass
class InsiderScenario:
    name: str
    description: str
    apply: callable  # (activity, profile, rng) -> activity (mutated)


def _overlay_data_hoarder(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    """Spike in sensitive file-access count."""
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    sensitive = list(profile.sensitive_path_prefixes) or ["/finance/", "/strategy/"]
    for _ in range(120):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        prefix = rng.choice(sensitive)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.FILE_ACCESS,
            attrs={
                "path": f"{prefix}q{rng.randint(1, 4)}/customer_pii_{rng.randint(1, 999)}.csv",
                "op": "read",
                "bytes": int(rng.lognormvariate(10.0, 0.6)),
            },
        ))
    activity.label = "insider:data_hoarder"
    return activity


def _overlay_off_hours(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    for _ in range(40):
        hour = rng.choice([1, 2, 3, 4, 5, 23])
        ts = _make_ts(base_date, hour, rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.FILE_ACCESS,
            attrs={
                "path": _normal_paths(profile, rng),
                "op": "read",
                "bytes": int(rng.lognormvariate(9.0, 1.0)),
            },
        ))
    for _ in range(5):
        hour = rng.choice([2, 3, 4])
        ts = _make_ts(base_date, hour, rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.LOGIN,
            attrs={"host": "vpn-edge", "success": True},
        ))
    activity.label = "insider:off_hours"
    return activity


def _overlay_departing_employee(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    for _ in range(8):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.USB,
            attrs={"bytes": int(rng.lognormvariate(15.0, 0.4)), "op": "write"},
        ))
    for _ in range(15):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        domain = rng.choice(list(PERSONAL_DOMAINS))
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.EMAIL_SEND,
            attrs={
                "to": f"{profile.user_id}@{domain}",
                "size_bytes": int(rng.lognormvariate(13.0, 0.6)),
                "attachment_count": rng.randint(2, 5),
            },
        ))
    activity.label = "insider:departing_employee"
    return activity


def _overlay_privilege_escalator(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    for _ in range(20):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.LOGIN,
            attrs={
                "host": f"prod-db-{rng.randint(1, 6)}",
                "success": rng.random() < 0.2,
            },
        ))
    activity.label = "insider:privilege_escalator"
    return activity


def _overlay_exfil_email(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    for _ in range(30):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        domain = rng.choice(list(PERSONAL_DOMAINS))
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.EMAIL_SEND,
            attrs={
                "to": f"recipient_{rng.randint(1, 99)}@{domain}",
                "size_bytes": int(rng.lognormvariate(14.0, 0.6)),
                "attachment_count": rng.randint(1, 6),
            },
        ))
    activity.add(UserEvent(
        timestamp=_make_ts(base_date, 14, rng),
        user_id=profile.user_id, event_type=EventType.DLP_ALERT,
        attrs={"rule": "EMAIL_BULK_TO_PERSONAL", "severity": "high"},
    ))
    activity.label = "insider:exfil_email"
    return activity


def _overlay_pii_browser(
    activity: UserActivity, profile: UserProfile, rng: random.Random
) -> UserActivity:
    base_date = datetime.fromisoformat(activity.date_key + "T00:00:00+00:00")
    for _ in range(40):
        ts = _make_ts(base_date, _sample_hour(profile, rng), rng)
        host = rng.choice(list(CLOUD_HOSTS))
        activity.add(UserEvent(
            timestamp=ts, user_id=profile.user_id, event_type=EventType.WEB,
            attrs={"host": host, "bytes": int(rng.lognormvariate(13.0, 0.7))},
        ))
    activity.label = "insider:pii_browser"
    return activity


INSIDER_SCENARIOS: List[InsiderScenario] = [
    InsiderScenario("data_hoarder", "spike in sensitive file-access count", _overlay_data_hoarder),
    InsiderScenario("off_hours", "activity in 01-05 on a 9-to-5 user", _overlay_off_hours),
    InsiderScenario("departing_employee", "USB write + personal-email surge", _overlay_departing_employee),
    InsiderScenario("privilege_escalator", "many failed logins to admin hosts", _overlay_privilege_escalator),
    InsiderScenario("exfil_email", "bulk personal-domain email + DLP hit", _overlay_exfil_email),
    InsiderScenario("pii_browser", "many large posts to personal cloud-storage hosts", _overlay_pii_browser),
]


@dataclass
class SyntheticActivityGenerator:
    profiles: Sequence[UserProfile] = field(default_factory=lambda: list(BENIGN_PROFILES))
    seed: Optional[int] = None
    base_date: datetime = field(
        default_factory=lambda: datetime(2025, 1, 6, tzinfo=timezone.utc)
    )

    def _rng(self) -> random.Random:
        return random.Random(self.seed)

    def generate_baseline(
        self, n_days: int = 14, n_per_profile_per_day: int = 1
    ) -> List[UserActivity]:
        rng = self._rng()
        out: List[UserActivity] = []
        for d in range(n_days):
            date = self.base_date + timedelta(days=d)
            for prof in self.profiles:
                for _ in range(n_per_profile_per_day):
                    out.append(_gen_baseline_day(prof, date, rng))
        return out

    def generate_insider_day(
        self, user_id: str, scenario: str, day_offset: int = 14, seed: Optional[int] = None
    ) -> UserActivity:
        prof = next((p for p in self.profiles if p.user_id == user_id), None)
        if prof is None:
            raise KeyError(f"unknown user {user_id!r}")
        scen = next((s for s in INSIDER_SCENARIOS if s.name == scenario), None)
        if scen is None:
            raise KeyError(f"unknown scenario {scenario!r}")
        rng = random.Random(seed if seed is not None else self.seed)
        date = self.base_date + timedelta(days=day_offset)
        baseline = _gen_baseline_day(prof, date, rng)
        return scen.apply(baseline, prof, rng)
