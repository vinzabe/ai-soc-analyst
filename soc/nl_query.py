"""Natural-language to LogQuery translation via LLM."""
from __future__ import annotations
import datetime as dt
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .events import Event
from .index import LogQuery


SYSTEM_PROMPT = """You are a SIEM query translator. Convert a security
analyst's English question into a STRICT JSON LogQuery.

LogQuery shape (return ONLY this JSON object, no prose):

  {
    "must":      [{"field":"<name>","op":"<op>","value":<v>}, ...],
    "must_not":  [{"field":"<name>","op":"<op>","value":<v>}, ...],
    "time_range":{"from":"<ISO8601>","to":"<ISO8601>"},   // optional
    "limit": <int 1..1000>,                                // optional, default 100
    "sort":  "timestamp_desc"|"timestamp_asc"
  }

Allowed ops: eq, neq, in, not_in, contains, regex, gt, gte, lt, lte.

Common fields: id, timestamp, source, event_type, host, user, src_ip,
dst_ip, dst_port, process, cmdline, message. Use `fields.<key>` for
custom fields.

Convert relative times like "past hour" / "last 24 hours" to absolute
ISO8601 UTC using the `now` value the user provides. Leave time_range
unset if the user doesn't ask for one.

Output ONLY JSON. Nothing else."""


@dataclass
class NLQueryResult:
    nl: str
    query: Optional[LogQuery]
    raw: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nl": self.nl,
            "query": self.query.to_dict() if self.query else None,
            "error": self.error,
        }


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


class NLQueryEngine:
    def __init__(self, llm_client, *, model: str = "glm-5.1",
                  temperature: float = 0.0, max_tokens: int = 600):
        self.client = llm_client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def translate(self, nl: str, *,
                    now: Optional[dt.datetime] = None) -> NLQueryResult:
        now = now or dt.datetime.now(dt.timezone.utc)
        user_msg = (f"now: {now.isoformat()}\n"
                    f"question: {nl}\n\n"
                    "Return the JSON LogQuery now.")
        try:
            resp = self.client.chat(
                [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user_msg}],
                model=self.model, temperature=self.temperature,
                max_tokens=self.max_tokens)
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as e:
            return NLQueryResult(nl=nl, query=None, raw="",
                                    error=f"LLM error: {e}")
        parsed = _extract_json(raw)
        if not parsed:
            return NLQueryResult(nl=nl, query=None, raw=raw,
                                    error="invalid JSON from model")
        try:
            q = LogQuery.from_dict(parsed)
        except Exception as e:
            return NLQueryResult(nl=nl, query=None, raw=raw,
                                    error=f"parse error: {e}")
        errs = q.validate()
        if errs:
            return NLQueryResult(nl=nl, query=None, raw=raw,
                                    error="; ".join(errs))
        return NLQueryResult(nl=nl, query=q, raw=raw)
