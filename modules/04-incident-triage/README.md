# Module 04: Automated Incident Triage

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Intermediate |
| **Prerequisites** | Module 03 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Classify incident severity using a hybrid rule-based + LLM approach
- Map service dependencies to calculate blast radius
- Match incidents to runbooks using keyword heuristics and LLM enrichment
- Detect duplicate and related incidents to reduce noise
- Route incidents to the correct on-call team

---

## Concepts

### The Triage Pipeline

```
Alert Sources               Triage Pipeline                  Outputs
+--------------+     +------------------------+       +------------------+
| Prometheus   |---->| 1. Context Extraction  |       | TriageResult     |
| PagerDuty    |---->| 2. LLM Classification  |------>|  - severity      |
| Datadog      |---->| 3. Severity Rules      |       |  - runbooks      |
| CloudWatch   |     | 4. Blast Radius Calc   |       |  - team routing  |
+--------------+     | 5. Runbook Matching    |       |  - actions       |
                     | 6. Dedup Check         |       +------------------+
                     +------------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **SEV1** | Total outage, customer-facing impact, all-hands response |
| **SEV2** | Partial outage, degraded service for a subset of users |
| **SEV3** | Minor issue with limited impact, can wait for business hours |
| **Blast Radius** | The set of services and users affected by a failure |
| **Runbook** | Step-by-step guide for diagnosing and resolving a specific type of incident |
| **Deduplication** | Detecting that a new alert is the same incident already being tracked |

---

## Hands-On Lab

### Step 1: Understanding the Data Models

```python
from src.incident.auto_triage import (
    IncidentAlert, Severity, SERVICE_DEPENDENCIES, TEAM_ROUTING,
)

alert = IncidentAlert(
    alert_name="HighErrorRate",
    source="prometheus",
    description="Error rate for order-service exceeded 5% for 10 minutes",
    labels={"service": "order-service", "namespace": "production"},
    annotations={"summary": "Order service error rate is 8.3%"},
)

print(f"Alert: {alert.alert_name}")
print(f"Service: {alert.labels.get('service')}")

# Service dependency map
for parent, deps in SERVICE_DEPENDENCIES.items():
    print(f"  {parent} depends on {deps}")

# Team routing
for svc, team in TEAM_ROUTING.items():
    print(f"  {svc} -> {team}")
```

### Step 2: Running the Full Triage Pipeline

```python
"""
triage_pipeline_lab.py - Triage a database connection failure
"""
import asyncio
from src.incident.auto_triage import IncidentTriageEngine, IncidentAlert

async def main():
    engine = IncidentTriageEngine()

    alert = IncidentAlert(
        alert_name="DatabaseConnectionFailure",
        source="prometheus",
        description="order-db connection pool exhausted, all connections in use",
        labels={"service": "order-service", "instance": "order-db-primary"},
    )

    result = await engine.triage_incident(alert)

    print(f"Incident: {result.incident_id}")
    print(f"Severity: {result.severity.value}")
    print(f"Title: {result.title}")
    print(f"Affected: {result.affected_services}")
    print(f"Team: {result.escalation_team}")
    print(f"Confidence: {result.confidence_score}")

    for rb in result.suggested_runbooks:
        print(f"\nRunbook: {rb.title}")
        for step in rb.steps[:3]:
            print(f"  - {step}")

    for action in result.recommended_actions:
        print(f"Action: {action}")

asyncio.run(main())
```

### Step 3: Blast Radius Calculation

```python
"""
blast_radius_lab.py - Calculate downstream impact of a service failure
"""
from src.incident.auto_triage import SERVICE_DEPENDENCIES


def calculate_blast_radius(failed_service: str) -> dict:
    directly_affected = set()
    indirectly_affected = set()

    for parent, deps in SERVICE_DEPENDENCIES.items():
        if failed_service in deps:
            directly_affected.add(parent)

    for parent, deps in SERVICE_DEPENDENCIES.items():
        for affected in directly_affected:
            if affected in deps:
                indirectly_affected.add(parent)

    return {
        "failed_service": failed_service,
        "directly_affected": sorted(directly_affected),
        "indirectly_affected": sorted(indirectly_affected - directly_affected),
        "total_impact": len(directly_affected) + len(indirectly_affected),
    }


# What happens when user-db goes down?
impact = calculate_blast_radius("user-db")
print(f"Failed: {impact['failed_service']}")
print(f"Direct impact: {impact['directly_affected']}")
print(f"Indirect impact: {impact['indirectly_affected']}")
```

### Step 4: Severity Classification Deep Dive

```python
"""
severity_lab.py - Test severity classification with different alerts
"""
import asyncio
from src.incident.auto_triage import IncidentTriageEngine, IncidentAlert

async def main():
    engine = IncidentTriageEngine()

    test_cases = [
        ("Total Outage", IncidentAlert(
            alert_name="ServiceOutage",
            description="Complete outage - API returning 503 for all requests",
            labels={"service": "api-gateway"})),
        ("Degraded", IncidentAlert(
            alert_name="HighLatency",
            description="Degraded response times, P99 latency at 5 seconds",
            labels={"service": "order-service"})),
        ("Minor", IncidentAlert(
            alert_name="LogParsingError",
            description="Log aggregator unable to parse 2% of incoming logs",
            labels={"service": "log-collector"})),
    ]

    for name, alert in test_cases:
        result = await engine.triage_incident(alert)
        print(f"[{result.severity.value}] {name}: {result.title}")

asyncio.run(main())
```

### Step 5: REST API Usage

```bash
curl -X POST http://localhost:8000/api/incidents/triage \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "HighMemoryUsage",
    "source": "prometheus",
    "description": "Memory at 95% on order-service pods",
    "labels": {"service": "order-service", "namespace": "production"}
  }'

# View recent triaged incidents
curl http://localhost:8000/api/incidents/recent
```

---

## Key Takeaways

1. Hybrid severity classification (rules + LLM) catches edge cases that pure rules miss while maintaining determinism for obvious scenarios.
2. Service dependency maps are critical for blast-radius analysis -- a single database failure may bring down five upstream services.
3. Runbook matching reduces MTTR by giving responders immediate, actionable steps.
4. Duplicate detection prevents alert fatigue and ensures related incidents are tracked together.
5. Team routing based on service ownership ensures the right people are paged.

---

## Validation

```bash
bash modules/04-incident-triage/validation/validate.sh
```

---

**Next: [Module 05 ->](../05-chatops-integration/)**
