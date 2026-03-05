# Module 10: Production AI-DevOps Platform

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Advanced |
| **Prerequisites** | Modules 01-09 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Combine all AI-DevOps components into a unified production platform
- Implement safety guardrails for LLM-in-the-loop systems
- Design the end-to-end event flow from alert to remediation to notification
- Add observability (logging, metrics, tracing) to the AI pipeline itself
- Handle LLM failures gracefully with fallback strategies

---

## Concepts

### Production Architecture

```
                    +-----------------------------------------+
                    |         AI-DevOps Platform (FastAPI)     |
                    |                                         |
  Alerts In        |  +-------------+    +----------------+  |      Actions Out
  +----------+     |  | Log Analyzer|    | Incident Triage|  |     +-----------+
  |Prometheus|---->|  | (Module 02) |--->| (Module 04)    |--|--->| PagerDuty |
  |AlertMgr  |     |  +-------------+    +----------------+  |    +-----------+
  +----------+     |         |                   |            |    +-----------+
                   |         v                   v            |--->| Slack     |
  Logs In          |  +-------------+    +----------------+   |    +-----------+
  +----------+     |  | Anomaly Det.|    | Auto-Remediate |   |    +-----------+
  |Filebeat  |---->|  | (Module 03) |    | (Module 06)    |---|--->| Jira      |
  |Fluentd   |     |  +-------------+    +----------------+   |    +-----------+
  +----------+     |         |                   |            |
                   |         v                   v            |
  User Queries     |  +-------------+    +----------------+   |
  +----------+     |  | ChatOps Bot |    | Knowledge Mgmt |   |
  |  Slack   |---->|  | (Module 05) |    | (Module 09)    |   |
  +----------+     |  +-------------+    +----------------+   |
                   |                                          |
                   |  +--------------------------------------+|
                   |  | Safety Layer                         ||
                   |  | - Circuit breaker  - Rate limiter    ||
                   |  | - Approval gates   - Audit log       ||
                   |  | - LLM fallbacks    - Dry-run mode    ||
                   |  +--------------------------------------+|
                   +-----------------------------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Safety Guardrail** | A mechanism that prevents AI automation from causing harm (circuit breaker, rate limit, approval) |
| **LLM Fallback** | A predefined response or action used when the LLM is unavailable or returns invalid output |
| **Audit Log** | Immutable record of every automated action taken, for compliance and debugging |
| **Observability** | Monitoring the AI pipeline itself -- LLM latency, token usage, error rates, cache hit rates |
| **Human-in-the-Loop** | Design pattern where critical decisions require human approval before execution |

---

## Hands-On Lab

### Step 1: Unified FastAPI Application

```python
"""
main.py - Production entry point combining all modules
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest
from starlette.responses import Response

from src.log_analysis.log_analyzer import router as log_router
from src.incident.auto_triage import router as incident_router
from src.chatops.slack_bot import router as chatops_router
from src.remediation.auto_remediate import router as remediation_router

app = FastAPI(title="AI-Powered DevOps Platform", version="1.0.0")

# Metrics for observing the AI pipeline itself
LLM_REQUESTS = Counter("llm_requests_total", "Total LLM API calls", ["endpoint", "model"])
LLM_LATENCY = Histogram("llm_request_duration_seconds", "LLM call duration", ["endpoint"])
LLM_ERRORS = Counter("llm_errors_total", "LLM API errors", ["endpoint", "error_type"])

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(log_router)
app.include_router(incident_router)
app.include_router(chatops_router)
app.include_router(remediation_router)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ai-devops-platform"}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain")
```

### Step 2: LLM Fallback Strategy

```python
"""
llm_fallback.py - Handle LLM failures gracefully
"""
import asyncio
from openai import AsyncOpenAI


class ResilientLLMClient:
    """LLM client with retries, timeout, and fallback responses."""

    def __init__(self, client: AsyncOpenAI, max_retries: int = 3, timeout: float = 30.0):
        self.client = client
        self.max_retries = max_retries
        self.timeout = timeout

    async def complete(self, messages: list[dict], fallback: str = "") -> str:
        """Call the LLM with retries and a fallback response."""
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.wait_for(
                    self.client.chat.completions.create(
                        model="gpt-4", temperature=0.2, max_tokens=1000,
                        messages=messages,
                    ),
                    timeout=self.timeout,
                )
                return response.choices[0].message.content.strip()
            except asyncio.TimeoutError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
            except Exception as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                break

        # All retries exhausted -- return fallback
        return fallback or "LLM unavailable. Please investigate manually."
```

### Step 3: Audit Logging

```python
"""
audit_log.py - Immutable audit trail for all automated actions
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel


class AuditEntry(BaseModel):
    timestamp: str
    action_type: str       # triage | remediation | notification | deployment
    actor: str             # system | user_id
    target: str            # service or resource affected
    details: dict
    outcome: str           # success | failure | escalated | dry_run
    approved_by: str = ""


class AuditLogger:
    def __init__(self, log_dir: str = "/app/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("audit")
        handler = logging.FileHandler(self.log_dir / "audit.jsonl")
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log(self, entry: AuditEntry):
        self.logger.info(entry.model_dump_json())

    def search(self, action_type: str = None, target: str = None, limit: int = 50) -> list[dict]:
        results = []
        audit_file = self.log_dir / "audit.jsonl"
        if not audit_file.exists():
            return results

        with open(audit_file) as f:
            for line in f:
                entry = json.loads(line.strip())
                if action_type and entry.get("action_type") != action_type:
                    continue
                if target and entry.get("target") != target:
                    continue
                results.append(entry)

        return results[-limit:]


# Usage
audit = AuditLogger()
audit.log(AuditEntry(
    timestamp=datetime.utcnow().isoformat(),
    action_type="remediation",
    actor="system",
    target="order-service",
    details={"plan_id": "REM-001", "pattern": "high_cpu", "actions_executed": 3},
    outcome="dry_run",
))
```

### Step 4: End-to-End Event Flow

```python
"""
event_pipeline.py - Wire everything together
"""
import asyncio
from src.log_analysis.log_analyzer import LogAnalyzer
from src.incident.auto_triage import IncidentTriageEngine, IncidentAlert
from src.remediation.auto_remediate import RemediationEngine, IncidentContext
from src.chatops.slack_bot import DevOpsBot


async def handle_alert_event(raw_logs: list[str], alert: IncidentAlert):
    """Complete event flow: logs -> analysis -> triage -> remediate -> notify."""

    # Step 1: Analyze logs
    analyzer = LogAnalyzer()
    report = await analyzer.analyze_logs(raw_logs)

    # Step 2: Triage the incident
    triage = IncidentTriageEngine()
    triage_result = await triage.triage_incident(alert)

    # Step 3: Attempt remediation
    remediation = RemediationEngine(dry_run=True)
    incident_ctx = IncidentContext(
        incident_id=triage_result.incident_id,
        alert_name=alert.alert_name,
        severity=triage_result.severity.value,
        service=alert.labels.get("service", "unknown"),
        description=triage_result.summary,
    )
    plan = await remediation.evaluate_and_remediate(incident_ctx)

    # Step 4: Notify via Slack
    bot = DevOpsBot()
    summary = (
        f"*Incident {triage_result.incident_id}*\n"
        f"Severity: {triage_result.severity.value}\n"
        f"Service: {', '.join(triage_result.affected_services)}\n"
        f"Cause: {triage_result.probable_cause}\n"
        f"Remediation: {plan.status.value}"
    )
    response = await bot.handle_message(f"Incident update: {summary}")

    return {
        "log_analysis": report.model_dump(),
        "triage": triage_result.model_dump(),
        "remediation": plan.model_dump(),
        "notification": response.text,
    }
```

### Step 5: Docker Compose Deployment

```bash
# Start the full stack
docker compose up -d

# Verify all services
curl http://localhost:8000/health    # FastAPI app
curl http://localhost:9200/_cluster/health  # Elasticsearch
curl http://localhost:9090/-/healthy  # Prometheus
curl http://localhost:3000/api/health  # Grafana

# View platform metrics
curl http://localhost:8000/metrics
```

---

## Key Takeaways

1. Every LLM call must have a fallback -- the system must work (degraded) even when the LLM is down.
2. Audit logging is non-negotiable for production AI systems. Every automated action must be traceable.
3. Observability of the AI pipeline itself (LLM latency, error rates, token costs) is as important as observing the services it monitors.
4. The safety layer (circuit breaker + rate limiter + approval gates + dry-run) is what makes this production-ready.
5. Start with dry-run mode for everything. Graduate to live execution only after extensive testing and approval workflows.

---

## Validation

```bash
bash modules/10-production-ai-devops/validation/validate.sh
```

---

**Next: [Capstone Project ->](../../capstone/)**
