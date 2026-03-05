# Module 07: Intelligent Monitoring and Alerting

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Advanced |
| **Prerequisites** | Module 06 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Build an LLM-enhanced alerting system that reduces noise and groups related alerts
- Implement alert deduplication and suppression using semantic similarity
- Use LLMs to generate human-readable alert summaries from raw metric data
- Build dynamic thresholds that adapt to traffic patterns (day/night, weekday/weekend)
- Create intelligent on-call escalation policies

---

## Concepts

### The Intelligent Monitoring Pipeline

```
Raw Alerts              Noise Reduction              Enriched Output
+-------------+     +---------------------+     +---------------------+
| Prometheus  |---->| Deduplication       |     | Grouped Alert       |
| AlertManager|---->| (fingerprint match) |     |  - summary text     |
| CloudWatch  |     +---------------------+     |  - affected services|
+-------------+            |                    |  - runbook link     |
                           v                    |  - severity         |
                    +---------------------+     |  - on-call owner    |
                    | Semantic Grouping   |---->+---------------------+
                    | (LLM correlation)   |
                    +---------------------+
                           |
                           v
                    +---------------------+
                    | Dynamic Thresholds  |
                    | (time-of-day aware) |
                    +---------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Alert Fatigue** | When operators receive so many alerts that they start ignoring them |
| **Noise Ratio** | Percentage of alerts that do not require human action |
| **Semantic Grouping** | Using LLM understanding to group alerts that share a root cause |
| **Dynamic Threshold** | Alert thresholds that change based on time of day, day of week, or load patterns |
| **Suppression** | Silencing an alert during a known maintenance window or for a known issue |

---

## Hands-On Lab

### Step 1: Alert Deduplication Engine

```python
"""
alert_dedup.py - Deduplicate alerts using fingerprinting
"""
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field


@dataclass
class Alert:
    name: str
    service: str
    description: str
    severity: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


class AlertDeduplicator:
    def __init__(self, window_minutes: int = 30):
        self.window = timedelta(minutes=window_minutes)
        self._seen: dict[str, datetime] = {}

    def _fingerprint(self, alert: Alert) -> str:
        key = f"{alert.name}:{alert.service}:{alert.severity}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def is_duplicate(self, alert: Alert) -> bool:
        fp = self._fingerprint(alert)
        now = datetime.utcnow()

        # Clean expired entries
        self._seen = {k: v for k, v in self._seen.items() if now - v < self.window}

        if fp in self._seen:
            return True

        self._seen[fp] = now
        return False


# Test: same alert fired 3 times in 5 minutes
dedup = AlertDeduplicator(window_minutes=30)
alerts = [
    Alert(name="HighCPU", service="api-gateway", description="CPU at 92%", severity="warning"),
    Alert(name="HighCPU", service="api-gateway", description="CPU at 94%", severity="warning"),
    Alert(name="HighCPU", service="api-gateway", description="CPU at 96%", severity="warning"),
    Alert(name="HighMemory", service="api-gateway", description="Memory at 88%", severity="warning"),
]

for a in alerts:
    dup = dedup.is_duplicate(a)
    print(f"{'[DUP]' if dup else '[NEW]'} {a.name} on {a.service}: {a.description}")
```

### Step 2: LLM-Powered Alert Summarization

```python
"""
alert_summarizer.py - Generate human-readable summaries from raw alerts
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def summarize_alerts(alerts: list[dict]) -> str:
    prompt = f"""You are an on-call SRE receiving these alerts:

{json.dumps(alerts, indent=2)}

Write a 3-5 sentence executive summary that:
1. States the most critical issue first
2. Identifies the probable root cause
3. Lists affected services
4. Recommends immediate action

Be concise. This will be sent to the on-call engineer's phone."""

    response = client.chat.completions.create(
        model="gpt-4", temperature=0.2, max_tokens=300,
        messages=[
            {"role": "system", "content": "You are a senior SRE writing alert summaries."},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


alerts = [
    {"name": "HighCPU", "service": "order-service", "value": "95%", "duration": "10 min"},
    {"name": "HighLatency", "service": "order-service", "value": "P99=4.2s", "duration": "8 min"},
    {"name": "HighErrorRate", "service": "order-service", "value": "5xx=12%", "duration": "7 min"},
    {"name": "DBConnectionPool", "service": "order-db", "value": "98% used", "duration": "12 min"},
]

summary = summarize_alerts(alerts)
print(summary)
```

### Step 3: Dynamic Thresholds

```python
"""
dynamic_thresholds.py - Time-aware alert thresholds
"""
from datetime import datetime


class DynamicThreshold:
    """Adjust alert thresholds based on time of day and day of week."""

    def __init__(self, base_threshold: float, metric_name: str):
        self.base = base_threshold
        self.metric_name = metric_name

    def get_threshold(self, timestamp: datetime = None) -> float:
        ts = timestamp or datetime.utcnow()
        hour = ts.hour
        is_weekend = ts.weekday() >= 5

        # Relax thresholds during low-traffic periods
        if is_weekend:
            multiplier = 0.7  # Lower traffic on weekends, so lower threshold
        elif 2 <= hour <= 6:
            multiplier = 0.5  # Very low traffic at night
        elif 9 <= hour <= 17:
            multiplier = 1.0  # Business hours: normal threshold
        else:
            multiplier = 0.8  # Off-hours

        return self.base * multiplier

    def should_alert(self, value: float, timestamp: datetime = None) -> bool:
        return value > self.get_threshold(timestamp)


# CPU threshold: 85% during business hours, ~43% at 3am, ~60% on weekends
cpu_threshold = DynamicThreshold(base_threshold=85.0, metric_name="cpu_percent")

test_times = [
    datetime(2024, 1, 15, 10, 0),  # Monday 10am
    datetime(2024, 1, 15, 3, 0),   # Monday 3am
    datetime(2024, 1, 20, 14, 0),  # Saturday 2pm
]

for ts in test_times:
    threshold = cpu_threshold.get_threshold(ts)
    print(f"{ts.strftime('%A %H:%M')}: threshold = {threshold:.0f}%")
```

### Step 4: Semantic Alert Grouping

```python
"""
alert_grouper.py - Group related alerts into incidents using LLM
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def group_alerts(alerts: list[dict]) -> list[dict]:
    prompt = f"""Group these alerts by root cause. Alerts that are likely caused
by the same underlying issue should be in the same group.

Alerts:
{json.dumps(alerts, indent=2)}

Return JSON array of groups:
[{{"group_name": "...", "root_cause": "...", "alert_indices": [0, 1, ...], "severity": "SEV1-5"}}]"""

    response = client.chat.completions.create(
        model="gpt-4", temperature=0.1, max_tokens=500,
        messages=[
            {"role": "system", "content": "You are an SRE grouping correlated alerts."},
            {"role": "user", "content": prompt},
        ],
    )
    return json.loads(response.choices[0].message.content.strip())


alerts = [
    {"name": "HighCPU", "service": "order-service"},
    {"name": "HighLatency", "service": "order-service"},
    {"name": "HighErrorRate", "service": "order-service"},
    {"name": "DBPoolExhausted", "service": "order-db"},
    {"name": "DiskSpaceLow", "service": "log-collector"},
]

groups = group_alerts(alerts)
for g in groups:
    print(f"\nGroup: {g['group_name']} ({g['severity']})")
    print(f"  Root cause: {g['root_cause']}")
    print(f"  Alerts: {[alerts[i]['name'] for i in g['alert_indices']]}")
```

---

## Key Takeaways

1. Alert deduplication alone can reduce noise by 40-60% in a typical environment.
2. Semantic grouping (via LLM) collapses N related alerts into one actionable incident.
3. Dynamic thresholds prevent 3am pages for normal low-traffic metric levels.
4. LLM-generated summaries give on-call engineers immediate context without dashboard diving.
5. Combine all techniques: dedup -> group -> summarize -> dynamic threshold -> page.

---

## Validation

```bash
bash modules/07-intelligent-monitoring/validation/validate.sh
```

---

**Next: [Module 08 ->](../08-code-review-ai/)**
