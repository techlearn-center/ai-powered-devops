# Module 09: Knowledge Management and Deployment Intelligence

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Advanced |
| **Prerequisites** | Module 08 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Auto-generate runbooks from incident resolution data using LLMs
- Build a deployment risk scoring system that learns from historical deployments
- Generate post-mortem documents automatically from incident timelines
- Create a knowledge base that turns tribal knowledge into searchable documentation
- Implement rollback recommendation logic based on deployment metrics

---

## Concepts

### Knowledge Management Architecture

```
Incident Resolution Data        LLM Processing            Knowledge Outputs
+---------------------+     +--------------------+     +---------------------+
| Incident timelines  |---->| Runbook Generator  |---->| Auto-generated      |
| Resolution steps    |     +--------------------+     | runbooks            |
| Chat transcripts    |                                +---------------------+
+---------------------+     +--------------------+     +---------------------+
| Deployment history  |---->| Risk Scorer        |---->| Deploy risk reports |
| Rollback events     |     +--------------------+     +---------------------+
+---------------------+     +--------------------+     +---------------------+
| Post-mortem data    |---->| Doc Generator      |---->| Post-mortem docs    |
+---------------------+     +--------------------+     +---------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Runbook** | Step-by-step instructions for diagnosing and resolving a specific type of incident |
| **Post-Mortem** | A blameless document analyzing what went wrong, why, and how to prevent recurrence |
| **Deployment Risk Score** | A 0-100 rating predicting the likelihood a deployment will cause an incident |
| **Rollback Recommendation** | An automated suggestion to revert a deployment based on post-deploy metrics |
| **Knowledge Base** | Searchable repository of operational knowledge extracted from incidents |

---

## Hands-On Lab

### Step 1: Auto-Generate Runbooks from Incidents

```python
"""
runbook_generator.py - Create runbooks from incident resolution data
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def generate_runbook(incident_data: dict) -> str:
    """Generate a runbook from how an incident was actually resolved."""
    prompt = f"""Based on this incident resolution, create a reusable runbook.

Incident: {incident_data['title']}
Service: {incident_data['service']}
Root Cause: {incident_data['root_cause']}
Resolution Steps Taken:
{json.dumps(incident_data['resolution_steps'], indent=2)}
Time to Resolve: {incident_data['time_to_resolve']}

Generate a production-ready runbook in markdown with:
1. Quick Assessment (30 seconds) - first checks
2. Diagnosis Commands - exact commands to run
3. Resolution Steps - ordered by safety (least risky first)
4. Verification - how to confirm the fix worked
5. Prevention - what to change to prevent recurrence
6. Escalation Criteria - when to wake up more people

Use code blocks for all commands. Be specific and actionable."""

    response = client.chat.completions.create(
        model="gpt-4", temperature=0.2, max_tokens=2000,
        messages=[
            {"role": "system", "content": "You are a senior SRE writing runbooks."},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


# Example: Generate a runbook from a past database connection incident
runbook = generate_runbook({
    "title": "Database Connection Pool Exhaustion",
    "service": "order-service",
    "root_cause": "Long-running queries holding connections during traffic spike",
    "resolution_steps": [
        "Identified 47 idle connections held by order-service",
        "Ran: SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state='idle' AND state_change < now()-interval '10 min'",
        "Restarted order-service to reset connection pool",
        "Added query timeout of 30s to prevent future long-running queries",
    ],
    "time_to_resolve": "23 minutes",
})
print(runbook)
```

### Step 2: Deployment Risk Scoring from History

```python
"""
deploy_risk.py - Score deployment risk using historical data
"""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DeploymentRecord:
    service: str
    version: str
    timestamp: datetime
    files_changed: int
    lines_changed: int
    caused_incident: bool
    rollback: bool
    deploy_duration_seconds: int


def calculate_deploy_risk(
    current_deploy: dict,
    history: list[DeploymentRecord],
) -> dict:
    """Score deployment risk based on historical patterns."""
    score = 0
    factors = []

    # Factor 1: Service incident rate
    service_deploys = [d for d in history if d.service == current_deploy["service"]]
    if service_deploys:
        incident_rate = sum(1 for d in service_deploys if d.caused_incident) / len(service_deploys)
        if incident_rate > 0.2:
            score += 25
            factors.append(f"Service has {incident_rate:.0%} incident rate from deploys")

    # Factor 2: Change size compared to service average
    if service_deploys:
        avg_lines = sum(d.lines_changed for d in service_deploys) / len(service_deploys)
        if current_deploy["lines_changed"] > avg_lines * 3:
            score += 20
            factors.append(f"Change is 3x larger than average for this service")

    # Factor 3: Time of day
    hour = datetime.utcnow().hour
    if hour < 6 or hour > 20:
        score += 15
        factors.append("Deploying outside business hours")

    # Factor 4: Friday deploy
    if datetime.utcnow().weekday() == 4:
        score += 15
        factors.append("Friday deployment (limited weekend support)")

    # Factor 5: Recent rollbacks on this service
    recent_rollbacks = sum(1 for d in service_deploys[-10:] if d.rollback)
    if recent_rollbacks >= 2:
        score += 20
        factors.append(f"{recent_rollbacks} rollbacks in last 10 deploys")

    score = min(score, 100)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"

    return {"score": score, "level": level, "factors": factors}
```

### Step 3: Auto-Generate Post-Mortems

```python
"""
postmortem_generator.py - Generate post-mortem documents from incident data
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def generate_postmortem(incident: dict) -> str:
    prompt = f"""Write a blameless post-mortem for this incident.

Title: {incident['title']}
Duration: {incident['duration']}
Severity: {incident['severity']}
Services Affected: {incident['affected_services']}
Customer Impact: {incident['customer_impact']}

Timeline:
{json.dumps(incident['timeline'], indent=2)}

Root Cause: {incident['root_cause']}
Resolution: {incident['resolution']}

Write a professional post-mortem with these sections:
1. Summary (3 sentences)
2. Impact (users affected, revenue impact if applicable)
3. Timeline (formatted as a table)
4. Root Cause Analysis (5 Whys technique)
5. Action Items (with owners and deadlines)
6. Lessons Learned
7. What Went Well / What Could Be Improved

Use markdown formatting. Be blameless -- focus on systems, not people."""

    response = client.chat.completions.create(
        model="gpt-4", temperature=0.3, max_tokens=2500,
        messages=[
            {"role": "system", "content": "You write blameless post-mortems following SRE best practices."},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()
```

### Step 4: Rollback Recommendation Engine

```python
"""
rollback_recommender.py - Analyze post-deploy metrics and recommend rollback
"""
from dataclasses import dataclass


@dataclass
class PostDeployMetrics:
    error_rate_before: float
    error_rate_after: float
    latency_p99_before: float
    latency_p99_after: float
    cpu_usage_before: float
    cpu_usage_after: float


def should_rollback(metrics: PostDeployMetrics) -> dict:
    """Decide whether to recommend a rollback based on metric changes."""
    reasons = []

    error_increase = metrics.error_rate_after - metrics.error_rate_before
    if error_increase > 2.0:
        reasons.append(f"Error rate increased by {error_increase:.1f}%")

    latency_ratio = metrics.latency_p99_after / max(metrics.latency_p99_before, 1)
    if latency_ratio > 2.0:
        reasons.append(f"P99 latency increased {latency_ratio:.1f}x")

    cpu_increase = metrics.cpu_usage_after - metrics.cpu_usage_before
    if cpu_increase > 30:
        reasons.append(f"CPU usage jumped by {cpu_increase:.0f}%")

    should_roll = len(reasons) >= 2 or any("Error rate" in r for r in reasons if "increased by" in r and float(r.split("by ")[1].rstrip("%")) > 5)

    return {
        "recommend_rollback": should_roll,
        "confidence": min(len(reasons) * 0.3, 0.95),
        "reasons": reasons,
        "action": "ROLLBACK IMMEDIATELY" if should_roll else "MONITOR",
    }


result = should_rollback(PostDeployMetrics(
    error_rate_before=0.5, error_rate_after=8.2,
    latency_p99_before=120, latency_p99_after=350,
    cpu_usage_before=45, cpu_usage_after=78,
))
print(f"Rollback: {result['recommend_rollback']}")
print(f"Reasons: {result['reasons']}")
```

---

## Key Takeaways

1. Auto-generated runbooks capture tribal knowledge that would otherwise exist only in engineers' heads.
2. Historical deployment data makes risk scoring more accurate over time -- learn from every deploy.
3. Blameless post-mortems should focus on systems and processes, not individuals.
4. Rollback decisions should be data-driven: error rate, latency, and resource usage are the key signals.
5. A searchable knowledge base turns every incident into a learning opportunity for the whole team.

---

## Validation

```bash
bash modules/09-infrastructure-optimization/validation/validate.sh
```

---

**Next: [Module 10 ->](../10-production-ai-devops/)**
