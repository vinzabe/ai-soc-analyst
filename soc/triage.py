"""Per-alert LLM triage."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence

from .events import Alert, Event


SYSTEM_PROMPT = """You are a senior SOC L2 analyst. You will receive an
alert and a small sample of related events. Decide:

  - is_true_positive (bool)
  - confidence       (float 0..1)
  - severity         ("low"|"medium"|"high"|"critical")
  - mitre_techniques (list of "T####" strings)
  - rationale        (<= 220 chars)
  - recommended_actions (list of <= 5 short strings)

Return STRICT JSON only, no prose."""


@dataclass
class TriageVerdict:
    alert_id: str
    is_true_positive: bool
    confidence: float
    severity: str
    mitre_techniques: List[str]
    rationale: str
    recommended_actions: List[str]
    raw: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d


_CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json(blob: str) -> Optional[Dict]:
    if not blob:
        return None
    m = _CODE_FENCE.search(blob)
    if m:
        blob = m.group(1)
    blob = blob.strip()
    if not blob.startswith("{"):
        s = blob.find("{")
        e = blob.rfind("}")
        if s == -1 or e == -1 or e <= s:
            return None
        blob = blob[s:e + 1]
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


class AlertTriager:
    def __init__(self, llm_client, *, model: str = "glm-5.1",
                  temperature: float = 0.0, max_tokens: int = 700,
                  events_per_alert: int = 8):
        self.client = llm_client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.events_per_alert = events_per_alert

    def triage(self, alert: Alert,
                related: Sequence[Event] = ()) -> TriageVerdict:
        related = list(related)[: self.events_per_alert]
        user_msg = ("Alert:\n"
                     + json.dumps(alert.to_dict(), indent=2, default=str)
                     + "\n\nRelated events (most recent first):\n"
                     + json.dumps([e.to_dict() for e in related],
                                    indent=2, default=str)
                     + "\n\nReturn the JSON verdict now.")
        try:
            resp = self.client.chat(
                [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user_msg}],
                model=self.model, temperature=self.temperature,
                max_tokens=self.max_tokens)
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as e:
            return TriageVerdict(
                alert_id=alert.id, is_true_positive=False, confidence=0.0,
                severity=alert.severity.value, mitre_techniques=[],
                rationale="LLM error", recommended_actions=[],
                error=f"LLM error: {e}")
        parsed = _extract_json(raw)
        if not parsed:
            return TriageVerdict(
                alert_id=alert.id, is_true_positive=False, confidence=0.0,
                severity=alert.severity.value, mitre_techniques=[],
                rationale="invalid JSON", recommended_actions=[],
                raw=raw, error="invalid JSON from model")
        try:
            conf = float(parsed.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        actions = parsed.get("recommended_actions") or []
        if isinstance(actions, str):
            actions = [actions]
        techs = parsed.get("mitre_techniques") or []
        if isinstance(techs, str):
            techs = [techs]
        return TriageVerdict(
            alert_id=alert.id,
            is_true_positive=bool(parsed.get("is_true_positive", False)),
            confidence=conf,
            severity=str(parsed.get("severity", alert.severity.value)),
            mitre_techniques=list(techs)[:10],
            rationale=str(parsed.get("rationale", ""))[:300],
            recommended_actions=[str(a)[:160] for a in actions][:6],
            raw=raw,
        )
