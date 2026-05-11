# AI SOC Analyst

LLM-augmented SOC analyst that ingests security events (JSONL or Elasticsearch), translates natural-language queries to structured `LogQuery` objects, triages alerts, and generates incident-response reports.

## Features

- **Local log index**: in-memory JSONL with 10 operators (eq/neq/in/not_in/contains/regex/gt/gte/lt/lte), dotted `fields.x` paths, time_range, sort, limit, aggregate_by
- **Elasticsearch translator**: same `LogQuery` interface, lazy ES client import
- **NL query engine**: LLM converts plain English to `LogQuery`; code-fence-aware JSON extraction with fallbacks
- **Alert triager**: severity + rationale + recommended actions per alert
- **IR report generator**: structured incident summary in markdown

## Quick Start

```bash
pip install -r requirements.txt

# Query bundled fixture events with natural language
python -m soc.cli query --events fixtures/events.jsonl "show me SSH brute force attempts"
```

## Testing

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/test_live_llm.py -v
```

## Architecture

```
soc/
  events.py     - Event, Alert, AlertSeverity
  index.py      - LocalLogIndex, ElasticsearchLogIndex, LogQuery
  nl_query.py   - NLQueryEngine
  triage.py     - AlertTriager, TriageVerdict
  ir_report.py  - IRReportGenerator
  cli.py
fixtures/
  events.jsonl  - 10 sample events (SSH brute force + lateral movement)
  alert.json    - sample alert
playbooks/      - response playbooks
```

## License

MIT
