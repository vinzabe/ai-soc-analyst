"""AI SOC Analyst — natural-language log search, alert triage, IR reports."""
__version__ = "0.1.0"

from .events import Event, Alert, AlertSeverity
from .index import LocalLogIndex, LogQuery
from .nl_query import NLQueryEngine, NLQueryResult
from .triage import AlertTriager, TriageVerdict
from .ir_report import IRReportGenerator, IRReport
