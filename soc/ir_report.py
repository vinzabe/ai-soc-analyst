"""Generate an Incident Response report from a cluster of alerts/events."""
from __future__ import annotations
import datetime as dt
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence

from .events import Alert, Event
from .triage import TriageVerdict


SYSTEM_PROMPT = """You are an incident-response lead writing a concise but
thorough IR report in Markdown. Sections (in this order):

  1. # Executive Summary
  2. ## Timeline
  3. ## Indicators of Compromise (IOCs)
  4. ## Affected Assets
  5. ## MITRE ATT&CK techniques
  6. ## Root cause hypothesis
  7. ## Containment recommendations
  8. ## Eradication & Recovery steps
  9. ## Lessons learned

Be specific, cite exact timestamps and IPs/hosts. Output ONLY the
Markdown report (no JSON, no extra prose)."""


@dataclass
class IRReport:
    incident_id: str
    generated_at: dt.datetime
    title: str
    markdown: str
    alerts: List[Alert] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    verdicts: List[TriageVerdict] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "title": self.title,
            "markdown": self.markdown,
            "n_alerts": len(self.alerts),
            "n_events": len(self.events),
            "error": self.error,
        }


class IRReportGenerator:
    def __init__(self, llm_client, *, model: str = "glm-5.1",
                  temperature: float = 0.1, max_tokens: int = 2200,
                  max_events: int = 30, max_alerts: int = 20):
        self.client = llm_client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_events = max_events
        self.max_alerts = max_alerts

    def generate(self, *, incident_id: str, title: str,
                  alerts: Sequence[Alert],
                  events: Sequence[Event] = (),
                  verdicts: Sequence[TriageVerdict] = ()) -> IRReport:
        alerts = list(alerts)[: self.max_alerts]
        events = list(events)[: self.max_events]
        verdicts = list(verdicts)
        user_msg = (
            f"Incident: {title} (id={incident_id})\n\n"
            f"Alerts ({len(alerts)}):\n"
            + json.dumps([a.to_dict() for a in alerts], indent=2, default=str)
            + f"\n\nEvents ({len(events)}):\n"
            + json.dumps([e.to_dict() for e in events], indent=2, default=str)
            + f"\n\nTriage verdicts ({len(verdicts)}):\n"
            + json.dumps([v.to_dict() for v in verdicts], indent=2,
                            default=str)
            + "\n\nWrite the IR report now."
        )
        try:
            resp = self.client.chat(
                [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user_msg}],
                model=self.model, temperature=self.temperature,
                max_tokens=self.max_tokens)
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as e:
            return IRReport(incident_id=incident_id,
                              generated_at=dt.datetime.now(dt.timezone.utc),
                              title=title, markdown="",
                              alerts=alerts, events=events, verdicts=verdicts,
                              error=f"LLM error: {e}")
        # If the model wrapped the output in code fences, unwrap once.
        cf = re.match(r"^\s*```(?:markdown|md)?\s*(.*?)```\s*$",
                       raw, re.DOTALL | re.IGNORECASE)
        markdown = cf.group(1).strip() if cf else raw.strip()
        return IRReport(
            incident_id=incident_id,
            generated_at=dt.datetime.now(dt.timezone.utc),
            title=title,
            markdown=markdown,
            alerts=alerts,
            events=events,
            verdicts=verdicts,
        )
