"""
Automated Incident Triage Engine
=================================
Classifies incident severity, suggests runbooks, identifies affected services,
and routes incidents to the appropriate on-call team using LLM intelligence.

Usage:
    triage = IncidentTriageEngine()
    result = await triage.triage_incident(alert_payload)
"""

import os
import json
from datetime import datetime
from enum import Enum
from typing import Optional

from openai import AsyncOpenAI
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    SEV1 = "SEV1"  # Total outage, customer-facing
    SEV2 = "SEV2"  # Partial outage, degraded service
    SEV3 = "SEV3"  # Minor issue, limited impact
    SEV4 = "SEV4"  # Informational, no impact
    SEV5 = "SEV5"  # Cosmetic / low priority


class IncidentAlert(BaseModel):
    """Incoming alert from monitoring systems."""
    alert_name: str
    source: str = "prometheus"  # prometheus | datadog | cloudwatch | pagerduty
    description: str = ""
    labels: dict = Field(default_factory=dict)
    annotations: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_payload: dict = Field(default_factory=dict)


class RunbookSuggestion(BaseModel):
    """A suggested runbook for handling the incident."""
    title: str
    url: Optional[str] = None
    steps: list[str] = Field(default_factory=list)
    confidence: float = 0.0  # 0.0 - 1.0


class TriageResult(BaseModel):
    """Complete triage output for an incident."""
    incident_id: str
    severity: Severity
    title: str
    summary: str
    affected_services: list[str] = Field(default_factory=list)
    probable_cause: str = ""
    suggested_runbooks: list[RunbookSuggestion] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    escalation_team: str = ""
    is_duplicate: bool = False
    related_incidents: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    auto_resolve_eligible: bool = False
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Runbook Knowledge Base
# ---------------------------------------------------------------------------

RUNBOOK_CATALOG = {
    "high_cpu": RunbookSuggestion(
        title="High CPU Utilization Runbook",
        url="https://wiki.internal/runbooks/high-cpu",
        steps=[
            "Check top processes: `top -bn1 | head -20`",
            "Identify offending service from process list",
            "Check for recent deployments in the last 2 hours",
            "If caused by a known service, restart it: `systemctl restart <service>`",
            "If CPU > 95% for 10+ minutes, scale horizontally",
            "Escalate to platform team if root cause unclear",
        ],
        confidence=0.9,
    ),
    "high_memory": RunbookSuggestion(
        title="Memory Exhaustion Runbook",
        url="https://wiki.internal/runbooks/high-memory",
        steps=[
            "Check memory usage by process: `ps aux --sort=-%mem | head -20`",
            "Look for memory leaks in application logs",
            "Check OOM killer logs: `dmesg | grep -i oom`",
            "If a single process, restart it gracefully",
            "If system-wide, check for noisy-neighbor workloads",
        ],
        confidence=0.85,
    ),
    "disk_full": RunbookSuggestion(
        title="Disk Space Critical Runbook",
        url="https://wiki.internal/runbooks/disk-full",
        steps=[
            "Check disk usage: `df -h`",
            "Find large files: `du -sh /var/log/* | sort -rh | head -10`",
            "Rotate and compress old logs",
            "Clean Docker images: `docker system prune -a`",
            "If /tmp is full, clear stale temp files",
        ],
        confidence=0.92,
    ),
    "service_down": RunbookSuggestion(
        title="Service Health Check Failure Runbook",
        url="https://wiki.internal/runbooks/service-down",
        steps=[
            "Verify service status: `systemctl status <service>`",
            "Check application logs for crash reason",
            "Verify network connectivity and DNS resolution",
            "Check dependency health (database, cache, queue)",
            "Attempt graceful restart, then hard restart if needed",
            "Engage on-call SRE if service does not recover in 5 minutes",
        ],
        confidence=0.88,
    ),
    "high_error_rate": RunbookSuggestion(
        title="Elevated Error Rate Runbook",
        url="https://wiki.internal/runbooks/high-error-rate",
        steps=[
            "Check error rate dashboard in Grafana",
            "Identify the most common error codes (5xx vs 4xx)",
            "Correlate with recent deployments or config changes",
            "Check upstream dependencies for failures",
            "If caused by a bad deploy, initiate rollback",
        ],
        confidence=0.85,
    ),
    "latency_spike": RunbookSuggestion(
        title="Latency Spike Investigation Runbook",
        url="https://wiki.internal/runbooks/latency-spike",
        steps=[
            "Check P99/P95 latency in monitoring dashboards",
            "Identify slow endpoints from access logs",
            "Check database query performance and slow query logs",
            "Verify cache hit rates (Redis/Memcached)",
            "Check for resource contention (CPU, I/O, network)",
        ],
        confidence=0.82,
    ),
}

# Service dependency map for blast-radius analysis
SERVICE_DEPENDENCIES = {
    "api-gateway": ["auth-service", "user-service", "order-service"],
    "auth-service": ["user-db", "redis-cache"],
    "user-service": ["user-db", "redis-cache"],
    "order-service": ["order-db", "payment-service", "inventory-service"],
    "payment-service": ["payment-gateway-external", "order-db"],
    "inventory-service": ["inventory-db", "warehouse-api"],
    "notification-service": ["email-provider", "sms-provider", "redis-cache"],
}

TEAM_ROUTING = {
    "api-gateway": "platform-team",
    "auth-service": "identity-team",
    "user-service": "identity-team",
    "order-service": "commerce-team",
    "payment-service": "payments-team",
    "inventory-service": "commerce-team",
    "notification-service": "platform-team",
    "infrastructure": "sre-team",
    "database": "dba-team",
    "unknown": "sre-team",
}


# ---------------------------------------------------------------------------
# Triage Engine
# ---------------------------------------------------------------------------

class IncidentTriageEngine:
    """LLM-enhanced incident triage automation."""

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        model: str = "gpt-4",
    ):
        self.client = AsyncOpenAI(api_key=openai_api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self._recent_incidents: list[TriageResult] = []

    # ── Public API ────────────────────────────────────────────────

    async def triage_incident(self, alert: IncidentAlert) -> TriageResult:
        """
        Full triage pipeline:
        1. Extract key signals from alert
        2. Classify severity using rules + LLM
        3. Identify affected services and blast radius
        4. Match runbooks
        5. Check for duplicates
        6. Generate recommended actions
        """
        # Step 1: Extract context
        context = self._extract_context(alert)

        # Step 2: LLM-powered classification
        llm_analysis = await self._llm_classify(alert, context)

        # Step 3: Determine severity
        severity = self._classify_severity(alert, llm_analysis)

        # Step 4: Identify affected services
        affected = self._identify_affected_services(alert, llm_analysis)

        # Step 5: Match runbooks
        runbooks = self._match_runbooks(alert, llm_analysis)

        # Step 6: Check duplicates
        is_dup, related = self._check_duplicates(alert)

        # Step 7: Build result
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        escalation_team = self._route_to_team(affected)

        result = TriageResult(
            incident_id=incident_id,
            severity=severity,
            title=llm_analysis.get("title", alert.alert_name),
            summary=llm_analysis.get("summary", alert.description),
            affected_services=affected,
            probable_cause=llm_analysis.get("probable_cause", "Under investigation"),
            suggested_runbooks=runbooks,
            recommended_actions=llm_analysis.get("recommended_actions", []),
            escalation_team=escalation_team,
            is_duplicate=is_dup,
            related_incidents=related,
            confidence_score=llm_analysis.get("confidence", 0.7),
            auto_resolve_eligible=severity in (Severity.SEV4, Severity.SEV5),
            tags=llm_analysis.get("tags", []),
        )

        self._recent_incidents.append(result)
        return result

    # ── Context Extraction ────────────────────────────────────────

    def _extract_context(self, alert: IncidentAlert) -> dict:
        """Pull structured context from alert labels and annotations."""
        return {
            "alert_name": alert.alert_name,
            "source": alert.source,
            "service": alert.labels.get("service", "unknown"),
            "namespace": alert.labels.get("namespace", "default"),
            "cluster": alert.labels.get("cluster", "unknown"),
            "description": alert.description or alert.annotations.get("description", ""),
            "summary": alert.annotations.get("summary", ""),
        }

    # ── LLM Classification ────────────────────────────────────────

    async def _llm_classify(self, alert: IncidentAlert, context: dict) -> dict:
        """Use LLM to classify and enrich the incident."""
        prompt = f"""Analyze this production alert and provide triage information.

Alert: {alert.alert_name}
Source: {alert.source}
Description: {alert.description}
Labels: {json.dumps(alert.labels, indent=2)}
Annotations: {json.dumps(alert.annotations, indent=2)}

Respond with a JSON object containing:
- "title": concise incident title (max 80 chars)
- "summary": 2-3 sentence summary of the issue
- "severity_suggestion": one of SEV1, SEV2, SEV3, SEV4, SEV5
- "probable_cause": most likely root cause
- "affected_services": list of service names likely affected
- "recommended_actions": list of 3-5 immediate actions to take
- "tags": list of relevant tags (e.g., "database", "network", "deployment")
- "confidence": float 0.0-1.0 indicating confidence in the analysis
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=0.1,
                max_tokens=1000,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert SRE performing incident triage. "
                            "Respond only with valid JSON. Be specific and actionable."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            text = response.choices[0].message.content.strip()
            # Strip markdown code fences if present
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            return json.loads(text)
        except Exception as e:
            return {
                "title": alert.alert_name,
                "summary": alert.description,
                "severity_suggestion": "SEV3",
                "probable_cause": f"LLM classification failed: {e}",
                "affected_services": [alert.labels.get("service", "unknown")],
                "recommended_actions": ["Investigate manually", "Check monitoring dashboards"],
                "tags": [],
                "confidence": 0.3,
            }

    # ── Severity Classification ───────────────────────────────────

    def _classify_severity(self, alert: IncidentAlert, llm_analysis: dict) -> Severity:
        """Combine rule-based and LLM severity signals."""
        # Rule-based overrides
        name_lower = alert.alert_name.lower()
        desc_lower = alert.description.lower()

        if any(kw in name_lower or kw in desc_lower for kw in ("outage", "down", "critical", "data loss")):
            return Severity.SEV1
        if any(kw in name_lower or kw in desc_lower for kw in ("degraded", "high error", "timeout")):
            return Severity.SEV2

        # Use LLM suggestion
        llm_sev = llm_analysis.get("severity_suggestion", "SEV3")
        try:
            return Severity(llm_sev)
        except ValueError:
            return Severity.SEV3

    # ── Service Impact Analysis ───────────────────────────────────

    def _identify_affected_services(self, alert: IncidentAlert, llm_analysis: dict) -> list[str]:
        """Determine blast radius using dependency map + LLM suggestions."""
        primary = alert.labels.get("service", "unknown")
        affected = {primary}

        # Add LLM-suggested services
        for svc in llm_analysis.get("affected_services", []):
            affected.add(svc)

        # Expand via dependency map (one level deep)
        for svc in list(affected):
            for parent, deps in SERVICE_DEPENDENCIES.items():
                if svc in deps:
                    affected.add(parent)

        return sorted(affected)

    # ── Runbook Matching ──────────────────────────────────────────

    def _match_runbooks(self, alert: IncidentAlert, llm_analysis: dict) -> list[RunbookSuggestion]:
        """Match the alert to known runbooks using keyword heuristics."""
        matches = []
        searchable = f"{alert.alert_name} {alert.description}".lower()
        tags = [t.lower() for t in llm_analysis.get("tags", [])]

        keyword_map = {
            "high_cpu": ["cpu", "processor", "compute"],
            "high_memory": ["memory", "oom", "heap", "ram"],
            "disk_full": ["disk", "storage", "filesystem", "inode"],
            "service_down": ["down", "unavailable", "health", "crash", "restart"],
            "high_error_rate": ["error rate", "5xx", "500", "errors"],
            "latency_spike": ["latency", "slow", "timeout", "p99", "response time"],
        }

        for runbook_key, keywords in keyword_map.items():
            if any(kw in searchable or kw in " ".join(tags) for kw in keywords):
                matches.append(RUNBOOK_CATALOG[runbook_key])

        return matches if matches else [RUNBOOK_CATALOG["service_down"]]  # default

    # ── Duplicate Detection ───────────────────────────────────────

    def _check_duplicates(self, alert: IncidentAlert) -> tuple[bool, list[str]]:
        """Check if this alert is a duplicate of a recent incident."""
        related = []
        for inc in self._recent_incidents[-50:]:
            if alert.alert_name.lower() in inc.title.lower():
                related.append(inc.incident_id)

        is_dup = len(related) > 0
        return is_dup, related

    # ── Team Routing ──────────────────────────────────────────────

    def _route_to_team(self, affected_services: list[str]) -> str:
        """Route incident to the responsible team."""
        for svc in affected_services:
            if svc in TEAM_ROUTING:
                return TEAM_ROUTING[svc]
        return TEAM_ROUTING["unknown"]


# ---------------------------------------------------------------------------
# FastAPI Endpoint
# ---------------------------------------------------------------------------

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/incidents", tags=["Incident Triage"])

_engine = IncidentTriageEngine()


@router.post("/triage", response_model=TriageResult)
async def triage_incident_endpoint(alert: IncidentAlert):
    """Triage an incoming alert and return classification + recommendations."""
    return await _engine.triage_incident(alert)


@router.get("/recent")
async def recent_incidents():
    """List recent triaged incidents."""
    return {"incidents": [r.model_dump() for r in _engine._recent_incidents[-20:]]}
