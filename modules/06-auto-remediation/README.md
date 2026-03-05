# Module 06: Auto-Remediation Workflows

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Intermediate |
| **Prerequisites** | Module 05 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Build an auto-remediation engine that matches incidents to known fix patterns
- Implement safety guardrails: dry-run mode, approval workflows, circuit breakers, and rate limiting
- Use LLMs to suggest remediation steps for unknown failure patterns
- Execute multi-step remediation plans with rollback capability
- Understand human-in-the-loop design for production safety

---

## Concepts

### The Remediation Pipeline

```
Incident Alert
      |
      v
+---------------------+
| Pattern Matcher     |  <-- Known patterns: high CPU, disk full, crash loop, etc.
| (keyword + labels)  |
+---------------------+
      |
      +-- Match found -----> Use predefined actions
      |
      +-- No match --------> LLM suggests actions
      |
      v
+---------------------+
| Safety Checks       |
| - Circuit breaker   |
| - Rate limiter      |
| - Confidence check  |
+---------------------+
      |
      v
+---------------------+     +---------------------+
| Dry Run / Execute   |---->| Approval Workflow    |
| (per-action)        |     | (for high-risk ops)  |
+---------------------+     +---------------------+
      |
      v
+---------------------+
| Results + Rollback  |
+---------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Dry Run** | Simulating remediation actions without executing them; logs what would happen |
| **Circuit Breaker** | Stops all auto-remediation after 3+ consecutive failures to prevent cascading damage |
| **Rate Limiter** | Caps remediation executions to N per hour to prevent runaway automation |
| **Human-in-the-Loop** | Requiring human approval before executing high-risk actions |
| **Rollback Command** | A pre-defined command to undo a remediation step if it makes things worse |
| **Confidence Score** | 0.0-1.0 rating of how certain the engine is about the remediation; below 0.5 escalates to humans |

---

## Hands-On Lab

### Step 1: Understanding Remediation Patterns

```python
"""
patterns_lab.py - Explore the built-in remediation patterns
"""
from src.remediation.auto_remediate import REMEDIATION_PATTERNS

for name, pattern in REMEDIATION_PATTERNS.items():
    print(f"\n=== {name} ===")
    print(f"  Description: {pattern['description']}")
    print(f"  Keywords: {pattern['match_keywords']}")
    print(f"  Confidence: {pattern['confidence']}")
    print(f"  Actions:")
    for action in pattern['actions']:
        risk = f" [RISK: {action.risk_level}]" if action.risk_level != "low" else ""
        approval = " [NEEDS APPROVAL]" if action.requires_approval else ""
        print(f"    - {action.name}: {action.description}{risk}{approval}")
        if action.command:
            print(f"      Command: {action.command}")
        if action.rollback_command:
            print(f"      Rollback: {action.rollback_command}")
```

### Step 2: Dry Run Mode

```python
"""
dry_run_lab.py - Test remediation without executing anything
"""
import asyncio
from src.remediation.auto_remediate import RemediationEngine, IncidentContext

async def main():
    engine = RemediationEngine(dry_run=True)  # SAFE: dry run mode

    incident = IncidentContext(
        incident_id="INC-20240115-001",
        alert_name="DiskSpaceCritical",
        severity="SEV2",
        service="order-service",
        description="Disk usage at 97% on /var/log partition",
        labels={"metric": "disk_usage_percent"},
        metrics={"disk_percent": 97},
    )

    plan = await engine.evaluate_and_remediate(incident)

    print(f"Plan ID: {plan.plan_id}")
    print(f"Pattern: {plan.pattern_matched}")
    print(f"Status: {plan.status.value}")
    print(f"Confidence: {plan.confidence_score}")

    print(f"\nActions ({len(plan.results)} steps):")
    for r in plan.results:
        print(f"  [{r['status']}] {r['action']}: {r['message']}")

asyncio.run(main())
```

### Step 3: Safety Guardrails

```python
"""
safety_guardrails_lab.py - Test circuit breaker and rate limiter
"""
import asyncio
from src.remediation.auto_remediate import RemediationEngine, IncidentContext

async def main():
    engine = RemediationEngine(dry_run=True, max_auto_remediations_per_hour=3)

    # Simulate hitting the rate limit
    for i in range(5):
        incident = IncidentContext(
            incident_id=f"INC-{i}",
            alert_name="HighCPU",
            severity="SEV3",
            service="test-service",
            description="CPU spike detected",
            labels={},
            metrics={"cpu_percent": 95},
        )
        plan = await engine.evaluate_and_remediate(incident)
        print(f"Attempt {i+1}: status={plan.status.value}")

    # Check stats
    stats = engine.get_stats()
    print(f"\nStats: {stats}")

asyncio.run(main())
```

### Step 4: LLM-Suggested Remediation for Unknown Patterns

```python
"""
llm_suggestion_lab.py - Handle incidents the engine hasn't seen before
"""
import asyncio
from src.remediation.auto_remediate import RemediationEngine, IncidentContext

async def main():
    engine = RemediationEngine(dry_run=True)

    # An unusual incident that doesn't match predefined patterns
    incident = IncidentContext(
        incident_id="INC-NOVEL-001",
        alert_name="UnusualTrafficPattern",
        severity="SEV2",
        service="api-gateway",
        description="Request rate dropped 80% suddenly with no deployment changes. "
                    "Upstream DNS resolver returning SERVFAIL for 30% of queries.",
        labels={"region": "us-east-1"},
        metrics={"request_rate": 250, "normal_rate": 1200},
    )

    plan = await engine.evaluate_and_remediate(incident)
    print(f"Pattern matched: {plan.pattern_matched}")
    print(f"Confidence: {plan.confidence_score}")
    print(f"Status: {plan.status.value}")

    for action in plan.actions:
        print(f"\nSuggested: {action.name}")
        print(f"  {action.description}")
        if action.command:
            print(f"  Command: {action.command}")
        print(f"  Risk: {action.risk_level} | Approval: {action.requires_approval}")

asyncio.run(main())
```

### Step 5: REST API Usage

```bash
# Evaluate a remediation plan
curl -X POST http://localhost:8000/api/remediation/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-001",
    "alert_name": "HighCPU",
    "severity": "SEV2",
    "service": "order-service",
    "description": "CPU at 95%",
    "metrics": {"cpu_percent": 95}
  }'

# View history
curl http://localhost:8000/api/remediation/history

# Check stats
curl http://localhost:8000/api/remediation/stats
```

---

## Key Takeaways

1. Always start with dry-run mode enabled. Switch to live execution only after thorough testing.
2. The circuit breaker prevents cascading damage -- if three remediations fail in 30 minutes, all automation pauses.
3. Rate limiting (N per hour) prevents runaway automation loops.
4. High-risk actions (restarts, rollbacks, connection termination) must require human approval in production.
5. LLM suggestions for unknown patterns are marked with lower confidence and default to escalation.
6. Every action should have a rollback command so damage can be reversed.

---

## Validation

```bash
bash modules/06-auto-remediation/validation/validate.sh
```

---

**Next: [Module 07 ->](../07-intelligent-monitoring/)**
