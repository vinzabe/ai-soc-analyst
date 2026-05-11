"""Event and alert data model."""
from __future__ import annotations
import datetime as dt
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, s: str) -> "AlertSeverity":
        s = (s or "").lower().strip()
        for sev in cls:
            if sev.value == s:
                return sev
        return cls.INFO


@dataclass
class Event:
    """One raw security event (login, syscall, request, etc.)."""
    id: str
    timestamp: dt.datetime
    source: str                       # e.g. "linux-auth", "wazuh", "suricata"
    event_type: str                   # e.g. "ssh_failed_login"
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    process: str = ""
    cmdline: str = ""
    message: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Event":
        ts = d.get("timestamp")
        if isinstance(ts, str):
            ts = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            ts = dt.datetime.now(dt.timezone.utc)
        return cls(
            id=str(d.get("id", "")),
            timestamp=ts,
            source=d.get("source", ""),
            event_type=d.get("event_type", ""),
            host=d.get("host", ""),
            user=d.get("user", ""),
            src_ip=d.get("src_ip", ""),
            dst_ip=d.get("dst_ip", ""),
            dst_port=int(d.get("dst_port") or 0),
            process=d.get("process", ""),
            cmdline=d.get("cmdline", ""),
            message=d.get("message", ""),
            fields=d.get("fields", {}) or {},
        )


@dataclass
class Alert:
    """A correlated alert produced by a SIEM rule."""
    id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    timestamp: dt.datetime
    description: str = ""
    related_event_ids: List[str] = field(default_factory=list)
    host: str = ""
    user: str = ""
    src_ip: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Alert":
        ts = d.get("timestamp")
        if isinstance(ts, str):
            ts = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            ts = dt.datetime.now(dt.timezone.utc)
        sev = AlertSeverity.from_str(d.get("severity", "info"))
        return cls(
            id=str(d.get("id", "")),
            rule_id=str(d.get("rule_id", "")),
            rule_name=str(d.get("rule_name", "")),
            severity=sev,
            timestamp=ts,
            description=d.get("description", ""),
            related_event_ids=list(d.get("related_event_ids") or []),
            host=d.get("host", ""),
            user=d.get("user", ""),
            src_ip=d.get("src_ip", ""),
            mitre_techniques=list(d.get("mitre_techniques") or []),
            fields=d.get("fields", {}) or {},
        )
