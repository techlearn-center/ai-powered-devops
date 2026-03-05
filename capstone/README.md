# Capstone Project: AI-Powered DevOps Platform

## Overview

This capstone project combines everything from all 10 modules into a single, production-grade AI-DevOps platform. You will deploy a system that ingests logs and alerts, triages incidents with LLM intelligence, suggests and executes remediations, and communicates results to your team via Slack -- all with proper safety guardrails.

---

## Architecture

```
+===========================================================================+
|                         INFRASTRUCTURE LAYER                               |
|                                                                           |
|  +-------------------+   +-----------------+   +-------------------+      |
|  | Elasticsearch     |   | Prometheus      |   | Grafana           |      |
|  | (log storage &    |   | (metrics        |   | (dashboards &     |      |
|  |  search)          |   |  collection)    |   |  visualization)   |      |
|  | Port: 9200        |   | Port: 9090      |   | Port: 3000        |      |
|  +--------+----------+   +--------+--------+   +-------------------+      |
|           |                        |                                       |
+===========|========================|=======================================+
            |                        |
+===========|========================|=======================================+
|           v                        v         AI-DEVOPS PLATFORM            |
|  +------------------------------------------------------------------+     |
|  |                    FastAPI Application (Port 8000)                |     |
|  |                                                                  |     |
|  |  +-----------------+   +------------------+   +--------------+   |     |
|  |  | /api/logs       |   | /api/incidents   |   | /api/chatops |   |     |
|  |  | Log Analyzer    |   | Incident Triage  |   | Slack Bot    |   |     |
|  |  | - Parse logs    |   | - Classify sev.  |   | - Intent NLU |   |     |
|  |  | - Detect anomaly|   | - Match runbooks |   | - Block Kit  |   |     |
|  |  | - Cluster errors|   | - Blast radius   |   | - LLM fallbk |   |     |
|  |  | - LLM root cause|   | - Team routing   |   |              |   |     |
|  |  +-----------------+   +------------------+   +--------------+   |     |
|  |                                                                  |     |
|  |  +-------------------+   +------------------------------------+  |     |
|  |  | /api/remediation  |   |         SAFETY LAYER               |  |     |
|  |  | Auto-Remediate    |   | - Circuit breaker (3 failures)    |  |     |
|  |  | - Pattern match   |   | - Rate limiter (5/hour)           |  |     |
|  |  | - LLM suggestions |   | - Approval gates (high-risk ops) |  |     |
|  |  | - Dry-run mode    |   | - Audit logging (all actions)    |  |     |
|  |  | - Rollback support|   | - LLM fallback (retries + default)|  |     |
|  |  +-------------------+   +------------------------------------+  |     |
|  +------------------------------------------------------------------+     |
|                                                                           |
+===========================================================================+
            |                   |                    |
            v                   v                    v
    +---------------+   +---------------+   +----------------+
    | Slack         |   | PagerDuty     |   | Jira           |
    | (ChatOps &    |   | (escalation   |   | (ticket        |
    |  notifications)|  |  & on-call)   |   |  creation)     |
    +---------------+   +---------------+   +----------------+
```

### Data Flow

```
1. Alert fires in Prometheus/CloudWatch
        |
        v
2. POST /api/incidents/triage
   - LLM classifies severity (SEV1-SEV5)
   - Identifies affected services via dependency map
   - Matches to runbook catalog
   - Routes to correct on-call team
        |
        v
3. POST /api/logs/analyze (concurrent)
   - Parses related logs (syslog, JSON, nginx)
   - Detects anomaly patterns (error spikes, repeats)
   - Clusters similar errors
   - LLM generates root-cause hypotheses
        |
        v
4. POST /api/remediation/evaluate
   - Matches incident to known remediation pattern
   - Falls back to LLM for unknown patterns
   - Safety checks: circuit breaker, rate limit, confidence
   - Dry-run or execute (with approval for high-risk)
        |
        v
5. POST /api/chatops/slack/events
   - Posts incident summary to Slack channel
   - Includes: severity, affected services, runbook, actions taken
   - Responds to follow-up questions via LLM
```

---

## Requirements

### Must Have (Acceptance Criteria)

- [ ] **Docker Compose launches all services** -- `docker compose up -d` starts app, Elasticsearch, Prometheus, and Grafana
- [ ] **Log analysis endpoint works** -- `POST /api/logs/analyze` accepts log lines and returns an `AnomalyReport` with severity, clusters, and root-cause suggestions
- [ ] **Incident triage endpoint works** -- `POST /api/incidents/triage` accepts an alert and returns a `TriageResult` with severity, runbooks, affected services, and team routing
- [ ] **ChatOps endpoint works** -- `POST /api/chatops/message` accepts a text query and returns a structured response with intent classification
- [ ] **Remediation endpoint works** -- `POST /api/remediation/evaluate` accepts an incident context and returns a `RemediationPlan` in dry-run mode
- [ ] **Safety guardrails are active** -- Circuit breaker trips after 3 failures; rate limiter caps at 5 remediations per hour; high-risk actions require approval
- [ ] **Health check passes** -- `GET /health` returns `{"status": "healthy"}`
- [ ] **All 10 module validation scripts pass** -- `bash scripts/validate-all.sh`

### Nice to Have

- [ ] CI/CD pipeline that runs validation on every push
- [ ] Grafana dashboard with LLM call latency, error rates, and token usage
- [ ] Slack bot responding to live messages (not just API calls)
- [ ] Post-mortem auto-generation from incident data
- [ ] Deployment risk scoring integrated into CI/CD
- [ ] Prometheus alerts that feed back into the triage system

---

## Getting Started

```bash
# 1. Clone and enter the repo
git clone https://github.com/techlearn-center/ai-powered-devops.git
cd ai-powered-devops

# 2. Copy environment config
cp .env.example .env
# Edit .env with your OPENAI_API_KEY and SLACK_BOT_TOKEN

# 3. Install dependencies (for local development)
pip install -r requirements.txt

# 4. Launch the full stack
docker compose up -d

# 5. Verify all services are running
curl http://localhost:8000/health
curl http://localhost:9200/_cluster/health
curl http://localhost:9090/-/healthy

# 6. Run the validation suite
bash scripts/validate-all.sh
```

---

## Testing Your Implementation

### Test 1: Log Analysis

```bash
curl -X POST http://localhost:8000/api/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "{\"level\":\"ERROR\",\"service\":\"order-service\",\"message\":\"Database timeout after 5000ms\"}",
      "{\"level\":\"ERROR\",\"service\":\"order-service\",\"message\":\"Database timeout after 5000ms\"}",
      "{\"level\":\"CRITICAL\",\"service\":\"order-service\",\"message\":\"Circuit breaker OPEN\"}"
    ],
    "context": "Deployed order-service v2.3.1 fifteen minutes ago"
  }'
```

Expected: JSON response with `severity`, `error_clusters`, `root_cause_suggestions`.

### Test 2: Incident Triage

```bash
curl -X POST http://localhost:8000/api/incidents/triage \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "HighErrorRate",
    "source": "prometheus",
    "description": "order-service error rate at 12% for 10 minutes",
    "labels": {"service": "order-service", "namespace": "production"}
  }'
```

Expected: JSON response with `severity`, `suggested_runbooks`, `affected_services`, `escalation_team`.

### Test 3: ChatOps

```bash
curl -X POST http://localhost:8000/api/chatops/message \
  -H "Content-Type: application/json" \
  -d '{"text": "Is the order service healthy?"}'
```

Expected: JSON response with health check data and Block Kit blocks.

### Test 4: Auto-Remediation (Dry Run)

```bash
curl -X POST http://localhost:8000/api/remediation/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-TEST-001",
    "alert_name": "DiskSpaceCritical",
    "severity": "SEV2",
    "service": "order-service",
    "description": "Disk at 97%",
    "metrics": {"disk_percent": 97}
  }'
```

Expected: JSON response with `status: "dry_run"`, matched pattern, and list of actions that would be executed.

---

## Evaluation Criteria

| Criteria | Weight | Description |
|---|---|---|
| **Functionality** | 30% | All four API endpoints work correctly with valid responses |
| **Architecture** | 20% | Clean separation of concerns, proper use of Pydantic models |
| **Safety** | 15% | Circuit breaker, rate limiter, approval gates, dry-run mode |
| **Observability** | 15% | Health endpoint, structured logging, Prometheus metrics |
| **Documentation** | 10% | Clear README, API docs, architecture diagram |
| **Code Quality** | 10% | Type hints, docstrings, error handling, no hardcoded secrets |

---

## Showcasing to Hiring Managers

When you complete this capstone:

1. **Fork this repo** to your personal GitHub
2. **Add your solution** with clear, descriptive commit messages
3. **Update the README** with your specific architecture decisions
4. **Record a demo** showing the end-to-end flow: alert -> triage -> remediation -> Slack notification
5. **Highlight the safety layer** -- interviewers care deeply about production safety
6. **Be ready to explain tradeoffs** -- why dry-run by default, why circuit breakers, why LLM fallbacks

See [docs/portfolio-guide.md](../docs/portfolio-guide.md) for detailed guidance.
