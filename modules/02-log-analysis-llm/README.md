# Module 02: Log Analysis with LLMs

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Beginner |
| **Prerequisites** | Module 01 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Parse syslog, JSON, and nginx access log formats into structured entries
- Detect error-rate spikes and repeated failure patterns using statistical methods
- Cluster similar errors using fuzzy fingerprinting
- Use LLMs to generate root-cause hypotheses from anomaly data
- Index and search logs in Elasticsearch

---

## Concepts

### The Log Analysis Pipeline

```
Raw Logs (syslog, JSON, nginx)
        |
        v
+------------------+
|   Log Parser     |  <-- regex + JSON parsing
|   (multi-format) |
+------------------+
        |
        v
+------------------+
| Anomaly Detector |  <-- error-rate spikes, repeated errors, criticals
+------------------+
        |
        v
+------------------+
| Error Clusterer  |  <-- fuzzy fingerprinting (normalize IPs, IDs, numbers)
+------------------+
        |
        v
+------------------+
| LLM Root-Cause   |  <-- GPT-4 with structured prompt
| Analysis         |
+------------------+
        |
        v
+------------------+
| AnomalyReport    |  <-- severity, clusters, suggestions
+------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Fuzzy Fingerprinting** | Normalizing variable parts of log messages (IPs, timestamps, IDs) so similar errors cluster together |
| **Error Cluster** | A group of log entries that represent the same underlying failure pattern |
| **Anomaly Report** | Structured output containing detected anomalies, clusters, severity, and root-cause suggestions |
| **Root-Cause Analysis** | LLM-generated hypotheses explaining why the errors are occurring |

---

## Hands-On Lab

### Step 1: Understanding the Log Parser

The parser in `src/log_analysis/log_analyzer.py` handles three formats:

```python
from src.log_analysis.log_analyzer import parse_log_line

# JSON structured log
entry = parse_log_line('{"timestamp":"2024-01-15T10:30:00Z","level":"ERROR","service":"auth","message":"Token expired"}')
print(entry.level)    # "error"
print(entry.service)  # "auth"

# Syslog format
entry = parse_log_line("Jan 15 10:30:01 web-01 nginx[1234]: upstream timed out (110: Connection timed out)")
print(entry.service)  # "nginx"
print(entry.level)    # "error"

# Nginx access log
entry = parse_log_line('192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 500 1234')
print(entry.level)    # "error" (status 500)
print(entry.metadata) # {"ip": "192.168.1.1", "status": 500, "bytes": 1234}
```

### Step 2: Error Clustering with Fuzzy Fingerprints

```python
"""
error_clustering_lab.py - How fingerprinting groups similar errors
"""
import re
import hashlib
from collections import Counter


def fingerprint(message: str) -> str:
    """Normalize a log message for clustering."""
    cleaned = message
    cleaned = re.sub(r"\b\d+\b", "N", cleaned)
    cleaned = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    return hashlib.md5(cleaned.encode()).hexdigest()[:12]


# These different messages produce the SAME fingerprint:
messages = [
    "Connection to 10.0.1.15:5432 failed after 30ms (attempt 1 of 3)",
    "Connection to 10.0.2.20:5432 failed after 45ms (attempt 2 of 3)",
    "Connection to 192.168.1.1:5432 failed after 12ms (attempt 1 of 3)",
]

fingerprints = [fingerprint(m) for m in messages]
print(f"All same cluster: {len(set(fingerprints)) == 1}")  # True
```

### Step 3: Full Analysis Pipeline

```python
"""
full_analysis_lab.py - End-to-end log analysis with LLM root-cause
"""
import asyncio
from src.log_analysis.log_analyzer import LogAnalyzer

sample_logs = [
    '{"timestamp":"2024-01-15T10:30:00Z","level":"INFO","service":"api-gateway","message":"Request received GET /api/users"}',
    '{"timestamp":"2024-01-15T10:30:02Z","level":"ERROR","service":"order-service","message":"Database connection timeout after 5000ms"}',
    '{"timestamp":"2024-01-15T10:30:02Z","level":"ERROR","service":"order-service","message":"Database connection timeout after 5000ms"}',
    '{"timestamp":"2024-01-15T10:30:03Z","level":"ERROR","service":"order-service","message":"Database connection timeout after 5000ms"}',
    '{"timestamp":"2024-01-15T10:30:03Z","level":"ERROR","service":"order-service","message":"Database connection timeout after 3000ms"}',
    '{"timestamp":"2024-01-15T10:30:04Z","level":"ERROR","service":"order-service","message":"Database connection timeout after 5000ms"}',
    '{"timestamp":"2024-01-15T10:30:04Z","level":"CRITICAL","service":"order-service","message":"Circuit breaker OPEN for database pool"}',
    '{"timestamp":"2024-01-15T10:30:05Z","level":"ERROR","service":"payment-service","message":"Upstream order-service unavailable"}',
]


async def main():
    analyzer = LogAnalyzer()
    report = await analyzer.analyze_logs(
        raw_logs=sample_logs,
        context="Recent deployment of order-service v2.3.1 at 10:25 UTC",
    )

    print(f"Severity: {report.severity}")
    print(f"Analyzed: {report.analyzed_count} logs")
    print(f"Anomalies: {report.anomaly_count}")
    print(f"Summary: {report.summary}")

    print("\n--- Error Clusters ---")
    for c in report.error_clusters:
        print(f"  {c['count']}x | Services: {c['services']} | {c['sample_message'][:80]}")

    print("\n--- Root Cause Suggestions ---")
    for suggestion in report.root_cause_suggestions:
        print(f"  - {suggestion}")

asyncio.run(main())
```

### Step 4: Elasticsearch Integration

```python
"""
es_integration_lab.py - Index parsed logs into Elasticsearch
"""
import asyncio
from elasticsearch import AsyncElasticsearch
from src.log_analysis.log_analyzer import LogAnalyzer, parse_log_line

async def index_and_search():
    es = AsyncElasticsearch("http://localhost:9200")
    analyzer = LogAnalyzer()

    logs = [
        '{"timestamp":"2024-01-15T10:30:02Z","level":"ERROR","service":"auth-service","message":"JWT validation failed: token expired"}',
        '{"timestamp":"2024-01-15T10:30:03Z","level":"ERROR","service":"auth-service","message":"JWT validation failed: invalid signature"}',
    ]
    entries = [parse_log_line(line) for line in logs]
    await analyzer.ingest_to_elasticsearch(entries)

    result = await es.search(
        index="ai-devops-logs",
        body={"query": {"bool": {"must": [{"match": {"level": "error"}}, {"match": {"service": "auth-service"}}]}}},
    )

    for hit in result["hits"]["hits"]:
        print(f"[{hit['_source']['level']}] {hit['_source']['service']}: {hit['_source']['message']}")

    await es.close()

asyncio.run(index_and_search())
```

### Step 5: REST API Usage

```bash
# Start the server
uvicorn src.main:app --reload

# Analyze logs via the API
curl -X POST http://localhost:8000/api/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "{\"level\":\"ERROR\",\"service\":\"db\",\"message\":\"Connection pool exhausted\"}",
      "{\"level\":\"ERROR\",\"service\":\"db\",\"message\":\"Connection pool exhausted\"}",
      "{\"level\":\"CRITICAL\",\"service\":\"db\",\"message\":\"All connections dead\"}"
    ],
    "context": "Database maintenance ended 10 minutes ago"
  }'
```

---

## Key Takeaways

1. Multi-format parsing is essential -- production environments generate syslog, JSON, and access log formats simultaneously.
2. Fuzzy fingerprinting catches variations (different IPs, request IDs) that exact matching misses.
3. Statistical anomaly detection runs fast and filters noise before sending data to the LLM.
4. The LLM synthesizes patterns across clusters into human-readable root-cause hypotheses.
5. Elasticsearch provides search and retention for historical trend analysis.

---

## Validation

```bash
bash modules/02-log-analysis-llm/validation/validate.sh
```

---

**Next: [Module 03 ->](../03-anomaly-detection/)**
