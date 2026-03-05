# Module 03: Anomaly Detection in Metrics

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Intermediate |
| **Prerequisites** | Module 02 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Implement Z-score and moving-average anomaly detection for time-series data
- Use LLMs to correlate anomalies across multiple metrics and suggest root causes
- Build a natural-language-to-PromQL translator using few-shot prompting
- Reduce alert fatigue by grouping related anomalies into single incidents

---

## Concepts

### Multi-Layer Anomaly Detection

```
Prometheus / Grafana          Statistical Layer            LLM Correlation
+------------------+     +---------------------+     +--------------------+
| CPU metrics      |---->| Z-Score Detector    |---->|                    |
| Memory metrics   |---->| Moving Avg Detector |---->| GPT-4 Multi-Metric|
| Latency P99      |---->| Seasonal Detector   |---->| Correlator         |
| Error rates      |     +---------------------+     +--------------------+
+------------------+            |                            |
                                v                            v
                      +-----------------+          +-------------------+
                      | Per-Metric      |          | Correlated Alert  |
                      | Anomaly Events  |          | (grouped, ranked) |
                      +-----------------+          +-------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Z-Score** | Number of standard deviations a data point is from the mean; values above 3.0 are typically anomalous |
| **Moving Average** | Rolling window average that adapts to gradual trend changes |
| **Multi-Metric Correlation** | Connecting anomalies across CPU, memory, latency, and error rate to find a single root cause |
| **PromQL** | Prometheus Query Language used to query time-series metrics |
| **Alert Fatigue** | Operator burnout from receiving too many uncorrelated, noisy alerts |

---

## Hands-On Lab

### Step 1: Z-Score Anomaly Detection

```python
"""
zscore_detector.py - Detect spikes using standard deviation
"""
import math
from dataclasses import dataclass


@dataclass
class MetricPoint:
    timestamp: float
    value: float
    label: str = ""


@dataclass
class Anomaly:
    point: MetricPoint
    z_score: float
    direction: str   # "spike" or "drop"
    severity: str    # "warning" or "critical"


def detect_zscore_anomalies(
    data: list[MetricPoint],
    warning_threshold: float = 2.0,
    critical_threshold: float = 3.0,
) -> list[Anomaly]:
    if len(data) < 10:
        return []

    values = [p.value for p in data]
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std_dev = math.sqrt(variance) if variance > 0 else 1.0

    anomalies = []
    for point in data:
        z = (point.value - mean) / std_dev
        if abs(z) >= critical_threshold:
            anomalies.append(Anomaly(point=point, z_score=z,
                direction="spike" if z > 0 else "drop", severity="critical"))
        elif abs(z) >= warning_threshold:
            anomalies.append(Anomaly(point=point, z_score=z,
                direction="spike" if z > 0 else "drop", severity="warning"))

    return anomalies


# Inject anomalies at positions 50 and 75
cpu_data = [MetricPoint(timestamp=i, value=45 + (i % 5)) for i in range(100)]
cpu_data[50] = MetricPoint(timestamp=50, value=98)
cpu_data[75] = MetricPoint(timestamp=75, value=95)

for a in detect_zscore_anomalies(cpu_data):
    print(f"[{a.severity}] {a.direction} at t={a.point.timestamp}: "
          f"value={a.point.value}, z={a.z_score:.2f}")
```

### Step 2: Moving Average Detector

```python
"""
moving_avg_detector.py - Sliding window anomaly detection
"""
from collections import deque


class MovingAverageDetector:
    def __init__(self, window_size: int = 30, sensitivity: float = 2.0):
        self.window_size = window_size
        self.sensitivity = sensitivity
        self._window: deque[float] = deque(maxlen=window_size)

    def ingest(self, timestamp: float, value: float) -> dict | None:
        if len(self._window) < self.window_size:
            self._window.append(value)
            return None

        avg = sum(self._window) / len(self._window)
        std = (sum((v - avg) ** 2 for v in self._window) / len(self._window)) ** 0.5
        threshold = avg + (self.sensitivity * max(std, 1.0))
        self._window.append(value)

        if value > threshold:
            return {
                "timestamp": timestamp, "value": value,
                "moving_avg": round(avg, 2), "threshold": round(threshold, 2),
            }
        return None


detector = MovingAverageDetector(window_size=20, sensitivity=2.5)
latency_values = [12, 14, 11, 13, 15, 12, 14, 11, 13, 12,
                  14, 13, 11, 15, 12, 13, 14, 11, 12, 13,
                  14, 12, 11, 85, 90, 13, 12, 14, 11, 13]

for i, val in enumerate(latency_values):
    result = detector.ingest(timestamp=i, value=val)
    if result:
        print(f"Anomaly at t={i}: latency={val}ms (avg={result['moving_avg']}ms)")
```

### Step 3: LLM Multi-Metric Correlation

```python
"""
metric_correlator.py - Correlate anomalies across metrics using an LLM
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def correlate_anomalies(anomalies_by_metric: dict[str, list[dict]]) -> dict:
    prompt = "Analyze these anomalies across multiple metrics:\n\n"
    for metric, anomalies in anomalies_by_metric.items():
        prompt += f"## {metric}\n"
        for a in anomalies[:5]:
            prompt += f"- t={a['timestamp']}: value={a['value']}\n"

    prompt += ("\nReturn JSON: {\"correlated\": bool, \"probable_cause\": str, "
               "\"leading_indicator\": str, \"recommended_actions\": [str]}")

    response = client.chat.completions.create(
        model="gpt-4", temperature=0.1,
        messages=[
            {"role": "system", "content": "You are an SRE correlating metric anomalies."},
            {"role": "user", "content": prompt},
        ],
    )
    return json.loads(response.choices[0].message.content.strip())


# Example: CPU spike + latency spike + error rate jump
result = correlate_anomalies({
    "cpu_percent": [{"timestamp": 100, "value": 95}, {"timestamp": 101, "value": 98}],
    "p99_latency_ms": [{"timestamp": 101, "value": 4500}, {"timestamp": 102, "value": 5200}],
    "error_rate_pct": [{"timestamp": 102, "value": 12.5}],
})
print(f"Correlated: {result['correlated']}")
print(f"Root cause: {result['probable_cause']}")
```

### Step 4: Natural Language to PromQL

```python
"""
promql_helper.py - Translate natural language to PromQL queries
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()

EXAMPLES = """
"CPU usage for auth service" -> rate(container_cpu_usage_seconds_total{service="auth-service"}[5m]) * 100
"P99 latency for API" -> histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job="api-gateway"}[5m]))
"Error rate last hour" -> sum(rate(http_requests_total{status=~"5.."}[1h])) / sum(rate(http_requests_total[1h])) * 100
"""


def nl_to_promql(query: str) -> dict:
    response = client.chat.completions.create(
        model="gpt-4", temperature=0.1,
        messages=[
            {"role": "system", "content": f"Convert natural language to PromQL.\n{EXAMPLES}\nReturn JSON: {{\"promql\": \"...\", \"explanation\": \"...\"}}"},
            {"role": "user", "content": query},
        ],
    )
    return json.loads(response.choices[0].message.content.strip())

result = nl_to_promql("Show me error rate for order-service in the last 30 minutes")
print(f"PromQL: {result['promql']}")
```

---

## Key Takeaways

1. Statistical detectors (Z-score, moving average) catch obvious spikes cheaply -- use them as a first pass before calling the LLM.
2. Multi-metric correlation is where LLMs shine: connecting a CPU spike in service A with a latency jump in service B.
3. Natural-language-to-PromQL lets any team member query metrics without knowing PromQL syntax.
4. Alert grouping reduces fatigue: one correlated incident instead of three separate alerts.

---

## Validation

```bash
bash modules/03-anomaly-detection/validation/validate.sh
```

---

**Next: [Module 04 ->](../04-incident-triage/)**
