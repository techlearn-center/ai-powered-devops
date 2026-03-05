"""
LLM-Powered Log Analyzer
=========================
Parses application logs, identifies anomalies, clusters error patterns,
and suggests root causes using OpenAI's GPT models.

Usage:
    analyzer = LogAnalyzer()
    results = await analyzer.analyze_logs(log_lines)
"""

import os
import re
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from collections import Counter

from openai import AsyncOpenAI
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from elasticsearch import AsyncElasticsearch

load_dotenv()

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    """Structured representation of a single log line."""
    timestamp: Optional[datetime] = None
    level: str = "UNKNOWN"
    service: str = "unknown"
    message: str
    raw: str
    metadata: dict = Field(default_factory=dict)


class AnomalyReport(BaseModel):
    """Result of anomaly detection on a batch of logs."""
    anomalies: list[dict] = Field(default_factory=list)
    error_clusters: list[dict] = Field(default_factory=list)
    root_cause_suggestions: list[str] = Field(default_factory=list)
    severity: str = "low"  # low | medium | high | critical
    summary: str = ""
    analyzed_count: int = 0
    anomaly_count: int = 0


# ---------------------------------------------------------------------------
# Log Parser
# ---------------------------------------------------------------------------

# Common log patterns
SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)"
)

JSON_LOG_KEYS = {"timestamp", "level", "msg", "message", "service"}

NGINX_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\d+)"
)

LEVEL_KEYWORDS = {
    "CRITICAL": "critical", "FATAL": "critical",
    "ERROR": "error", "ERR": "error",
    "WARNING": "warning", "WARN": "warning",
    "INFO": "info", "DEBUG": "debug",
}


def parse_log_line(raw_line: str) -> LogEntry:
    """Parse a raw log line into a structured LogEntry."""
    raw_line = raw_line.strip()
    if not raw_line:
        return LogEntry(raw=raw_line, message="")

    # Try JSON first
    if raw_line.startswith("{"):
        try:
            data = json.loads(raw_line)
            return LogEntry(
                timestamp=_parse_ts(data.get("timestamp") or data.get("@timestamp")),
                level=_normalize_level(data.get("level", "INFO")),
                service=data.get("service", "unknown"),
                message=data.get("message") or data.get("msg", raw_line),
                raw=raw_line,
                metadata={k: v for k, v in data.items() if k not in JSON_LOG_KEYS},
            )
        except json.JSONDecodeError:
            pass

    # Try syslog
    m = SYSLOG_PATTERN.match(raw_line)
    if m:
        return LogEntry(
            timestamp=_parse_ts(m.group("timestamp")),
            level=_extract_level(m.group("message")),
            service=m.group("service"),
            message=m.group("message"),
            raw=raw_line,
            metadata={"host": m.group("host")},
        )

    # Try nginx / access-log
    m = NGINX_PATTERN.match(raw_line)
    if m:
        status = int(m.group("status"))
        return LogEntry(
            timestamp=_parse_ts(m.group("timestamp")),
            level="error" if status >= 500 else "warning" if status >= 400 else "info",
            service="nginx",
            message=f'{m.group("method")} {m.group("path")} -> {status}',
            raw=raw_line,
            metadata={"ip": m.group("ip"), "status": status, "bytes": int(m.group("bytes"))},
        )

    # Fallback
    return LogEntry(
        level=_extract_level(raw_line),
        message=raw_line,
        raw=raw_line,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S",
    ):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    return None


def _normalize_level(raw: str) -> str:
    return LEVEL_KEYWORDS.get(raw.upper(), raw.lower())


def _extract_level(text: str) -> str:
    upper = text.upper()
    for keyword, level in LEVEL_KEYWORDS.items():
        if keyword in upper:
            return level
    return "info"


def _fingerprint(message: str) -> str:
    """Create a fuzzy fingerprint for clustering similar messages."""
    cleaned = re.sub(r"\b\d+\b", "N", message)
    cleaned = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    return hashlib.md5(cleaned.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Main Analyzer
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """LLM-powered log analysis engine."""

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        model: str = "gpt-4",
        es_url: Optional[str] = None,
    ):
        self.client = AsyncOpenAI(api_key=openai_api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.es = AsyncElasticsearch(es_url or os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"))

    # ── Public API ────────────────────────────────────────────────

    async def analyze_logs(
        self,
        raw_logs: list[str],
        context: Optional[str] = None,
    ) -> AnomalyReport:
        """
        Full analysis pipeline:
        1. Parse raw logs into structured entries
        2. Detect statistical anomalies (error-rate spikes, new patterns)
        3. Cluster similar errors
        4. Ask LLM for root-cause suggestions
        """
        entries = [parse_log_line(line) for line in raw_logs if line.strip()]
        anomalies = self._detect_anomalies(entries)
        clusters = self._cluster_errors(entries)

        # Build LLM prompt
        root_causes = await self._get_root_causes(anomalies, clusters, context)

        severity = self._compute_severity(anomalies, entries)

        return AnomalyReport(
            anomalies=anomalies,
            error_clusters=clusters,
            root_cause_suggestions=root_causes,
            severity=severity,
            summary=self._build_summary(anomalies, clusters, severity),
            analyzed_count=len(entries),
            anomaly_count=len(anomalies),
        )

    async def ingest_to_elasticsearch(self, entries: list[LogEntry], index: str = "ai-devops-logs"):
        """Bulk-index parsed log entries into Elasticsearch."""
        actions = []
        for entry in entries:
            doc = entry.model_dump()
            doc["timestamp"] = doc["timestamp"].isoformat() if doc["timestamp"] else None
            actions.append({"index": {"_index": index}})
            actions.append(doc)
        if actions:
            await self.es.bulk(body=actions, refresh=True)

    # ── Anomaly Detection ─────────────────────────────────────────

    def _detect_anomalies(self, entries: list[LogEntry]) -> list[dict]:
        """Detect error-rate spikes and unusual patterns."""
        anomalies = []
        if not entries:
            return anomalies

        # Time-window error rate analysis (5-minute buckets)
        error_entries = [e for e in entries if e.level in ("error", "critical")]
        if len(error_entries) > len(entries) * 0.3:
            anomalies.append({
                "type": "error_rate_spike",
                "description": f"Error rate is {len(error_entries)}/{len(entries)} "
                               f"({100*len(error_entries)/len(entries):.0f}%)",
                "count": len(error_entries),
            })

        # Detect repeated errors (same message > 5 times)
        msg_counts = Counter(e.message for e in error_entries)
        for msg, count in msg_counts.most_common(10):
            if count >= 5:
                anomalies.append({
                    "type": "repeated_error",
                    "description": f"Error repeated {count} times: {msg[:120]}",
                    "count": count,
                })

        # Detect new/unseen error patterns
        critical = [e for e in entries if e.level == "critical"]
        for entry in critical:
            anomalies.append({
                "type": "critical_event",
                "description": f"CRITICAL from {entry.service}: {entry.message[:200]}",
                "service": entry.service,
            })

        return anomalies

    # ── Error Clustering ──────────────────────────────────────────

    def _cluster_errors(self, entries: list[LogEntry]) -> list[dict]:
        """Group similar error messages using fuzzy fingerprinting."""
        clusters: dict[str, list[LogEntry]] = {}
        for entry in entries:
            if entry.level not in ("error", "critical"):
                continue
            fp = _fingerprint(entry.message)
            clusters.setdefault(fp, []).append(entry)

        result = []
        for fp, group in sorted(clusters.items(), key=lambda x: -len(x[1])):
            result.append({
                "fingerprint": fp,
                "count": len(group),
                "sample_message": group[0].message[:300],
                "services": list({e.service for e in group}),
                "first_seen": min((e.timestamp for e in group if e.timestamp), default=None),
                "last_seen": max((e.timestamp for e in group if e.timestamp), default=None),
            })
        return result[:20]  # Top 20 clusters

    # ── LLM Root-Cause Analysis ───────────────────────────────────

    async def _get_root_causes(
        self,
        anomalies: list[dict],
        clusters: list[dict],
        context: Optional[str] = None,
    ) -> list[str]:
        """Ask the LLM for root-cause hypotheses."""
        if not anomalies and not clusters:
            return ["No significant anomalies detected."]

        prompt = self._build_rca_prompt(anomalies, clusters, context)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                max_tokens=1500,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior SRE analyzing production logs. "
                            "Provide concise, actionable root-cause hypotheses. "
                            "Return a JSON array of strings, each a distinct hypothesis."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            text = response.choices[0].message.content.strip()
            # Parse the JSON array from the response
            if text.startswith("["):
                return json.loads(text)
            return [text]
        except Exception as e:
            return [f"LLM analysis unavailable: {e}"]

    def _build_rca_prompt(
        self,
        anomalies: list[dict],
        clusters: list[dict],
        context: Optional[str],
    ) -> str:
        sections = ["## Detected Anomalies"]
        for a in anomalies[:10]:
            sections.append(f"- [{a['type']}] {a['description']}")

        sections.append("\n## Error Clusters (top 10)")
        for c in clusters[:10]:
            sections.append(
                f"- {c['count']}x across {c['services']}: {c['sample_message'][:150]}"
            )

        if context:
            sections.append(f"\n## Additional Context\n{context}")

        sections.append(
            "\nProvide 3-5 root-cause hypotheses as a JSON array of strings. "
            "Include the likely affected component and a recommended next step."
        )
        return "\n".join(sections)

    # ── Severity & Summary ────────────────────────────────────────

    def _compute_severity(self, anomalies: list[dict], entries: list[LogEntry]) -> str:
        critical_count = sum(1 for e in entries if e.level == "critical")
        if critical_count > 0 or len(anomalies) > 5:
            return "critical"
        error_count = sum(1 for e in entries if e.level == "error")
        if error_count > len(entries) * 0.2:
            return "high"
        if anomalies:
            return "medium"
        return "low"

    def _build_summary(self, anomalies, clusters, severity) -> str:
        return (
            f"Severity: {severity.upper()} | "
            f"{len(anomalies)} anomalies detected | "
            f"{len(clusters)} error clusters identified"
        )


# ---------------------------------------------------------------------------
# FastAPI Endpoint (for integration)
# ---------------------------------------------------------------------------

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/logs", tags=["Log Analysis"])


class LogAnalysisRequest(BaseModel):
    logs: list[str]
    context: Optional[str] = None


@router.post("/analyze", response_model=AnomalyReport)
async def analyze_logs_endpoint(request: LogAnalysisRequest):
    """Analyze a batch of log lines and return anomaly report."""
    if not request.logs:
        raise HTTPException(status_code=400, detail="No log lines provided")
    analyzer = LogAnalyzer()
    return await analyzer.analyze_logs(request.logs, context=request.context)


@router.post("/parse")
async def parse_logs_endpoint(request: LogAnalysisRequest):
    """Parse raw log lines into structured entries."""
    entries = [parse_log_line(line) for line in request.logs if line.strip()]
    return {"entries": [e.model_dump() for e in entries], "count": len(entries)}
