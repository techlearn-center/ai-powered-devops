# Module 01: AI-Powered DevOps Fundamentals

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Beginner |
| **Prerequisites** | Python 3.11+, OpenAI API key |

---

## Learning Objectives

By the end of this module, you will be able to:

- Understand where LLMs fit in the DevOps lifecycle and which tasks they augment best
- Set up an OpenAI API integration for operational automation
- Write effective prompts for log analysis, incident triage, and runbook generation
- Parse structured JSON output from LLM responses using Pydantic models
- Apply chain-of-thought and few-shot prompting patterns for DevOps diagnostics

---

## Concepts

### Where LLMs Fit in DevOps

Traditional DevOps relies on rules-based automation: regex for log parsing, static thresholds for alerts, and predefined runbooks. LLMs augment this by adding semantic understanding.

| Workflow | Traditional Approach | AI-Augmented Approach |
|---|---|---|
| Log Analysis | Regex patterns, keyword search | Semantic understanding, anomaly narration |
| Incident Triage | Static severity rules | Context-aware classification |
| Alerting | Threshold-based | Noise reduction, correlation |
| Runbooks | Static documents | Auto-generated, context-specific |
| Code Review | Linters, static analysis | Semantic analysis, security patterns |
| Post-Mortems | Manual writing | Auto-generated from incident data |

### The AI-DevOps Architecture

```
Monitoring Stack          AI Layer              Action Layer
+--------------+     +---------------+     +----------------+
| Prometheus   |---->| LLM Analyzer  |---->| Auto-Remediate |
| Elasticsearch|---->| (OpenAI GPT)  |---->| Slack Notify   |
| CloudWatch   |     +---------------+     | PagerDuty      |
+--------------+           |               | Jira Create    |
                    +------+------+        +----------------+
                    | Prompt Eng. |
                    | Few-shot    |
                    | Chain-of-   |
                    | Thought     |
                    +-------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Prompt Engineering** | Designing input text to elicit accurate, structured responses from an LLM |
| **Few-Shot Prompting** | Providing examples in the prompt so the model learns the expected output format |
| **Chain-of-Thought** | Asking the model to reason step-by-step before giving a final answer |
| **Structured Output** | Requesting JSON responses and validating them with Pydantic models |
| **Temperature** | Controls randomness (0.0 = deterministic, 1.0 = creative); use 0.1-0.2 for ops tasks |

---

## Hands-On Lab

### Step 1: Install Dependencies

```bash
pip install openai pydantic python-dotenv
```

### Step 2: Configure Your Environment

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Step 3: Your First DevOps LLM Call

```python
"""
first_devops_llm.py - Analyze a deployment log with an LLM
"""
import os
import json
from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


class DeploymentAnalysis(BaseModel):
    status: str          # success | failure | partial
    services_affected: list[str]
    root_cause: str
    recommended_action: str
    confidence: float


def analyze_deployment_log(log_text: str) -> DeploymentAnalysis:
    """Use an LLM to analyze a deployment log and return structured output."""
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4"),
        temperature=0.1,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior SRE analyzing deployment logs. "
                    "Return a JSON object with keys: status, services_affected, "
                    "root_cause, recommended_action, confidence (0.0-1.0)."
                ),
            },
            {
                "role": "user",
                "content": f"Analyze this deployment log:\n\n{log_text}",
            },
        ],
    )

    raw = response.choices[0].message.content.strip()
    data = json.loads(raw)
    return DeploymentAnalysis(**data)


if __name__ == "__main__":
    sample_log = """
    2024-01-15 14:32:01 [INFO] Starting deployment of order-service v2.3.1
    2024-01-15 14:32:15 [INFO] Pulling image: registry.internal/order-service:v2.3.1
    2024-01-15 14:32:45 [INFO] Health check passed for 2/3 replicas
    2024-01-15 14:33:01 [ERROR] Replica 3 failed health check: connection refused on port 8080
    2024-01-15 14:33:15 [WARN] Rolling back replica 3 to v2.3.0
    2024-01-15 14:33:30 [INFO] Deployment completed with warnings
    """

    result = analyze_deployment_log(sample_log)
    print(f"Status: {result.status}")
    print(f"Affected: {result.services_affected}")
    print(f"Root Cause: {result.root_cause}")
    print(f"Action: {result.recommended_action}")
```

### Step 4: Prompt Engineering Patterns for DevOps

```python
"""
prompt_patterns.py - Three essential prompting techniques for DevOps
"""

# Pattern 1: Chain-of-Thought Diagnosis
COT_DIAGNOSIS_PROMPT = """You are diagnosing a production issue. Think step by step:

1. What type of error is this? (network, application, infrastructure, data)
2. What is the blast radius? (single service, multiple services, full outage)
3. What changed recently? (deployments, config changes, traffic patterns)
4. What is the most likely root cause?
5. What should be done immediately?

Error details:
{error_details}

Provide your analysis as JSON with keys: error_type, blast_radius,
recent_changes_to_check, root_cause, immediate_actions."""


# Pattern 2: Few-Shot Error Classification
FEW_SHOT_CLASSIFICATION = """Classify the severity of production errors.

Example 1:
Error: "Connection timeout to payment gateway after 30s"
Classification: SEV2 - External dependency failure affecting payments

Example 2:
Error: "CSS file not found: /static/styles.css"
Classification: SEV4 - Cosmetic issue, non-critical

Example 3:
Error: "Out of memory: Kill process 1234 (java) score 950"
Classification: SEV1 - Service crash due to memory exhaustion

Now classify:
Error: "{error_message}"
Classification:"""


# Pattern 3: Structured Runbook Generation
RUNBOOK_GENERATION = """Generate a runbook for this alert.

Alert: {alert_name}
Service: {service_name}

Include these sections:
1. Quick Assessment (30 seconds) - what to check first
2. Diagnosis Steps - commands to run
3. Remediation Options - ranked by safety
4. Escalation Criteria - when to involve others
5. Post-Resolution - what to verify

Format as markdown with code blocks for commands."""
```

### Step 5: Structured Output with Pydantic

```python
"""
structured_output.py - Safely parse LLM JSON into validated models
"""
import json
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class IncidentSummary(BaseModel):
    title: str = Field(max_length=100)
    severity: str
    affected_services: list[str]
    root_cause: str
    mitigation_steps: list[str]
    requires_postmortem: bool = False

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        allowed = {"SEV1", "SEV2", "SEV3", "SEV4", "SEV5"}
        if v.upper() not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v.upper()


def parse_llm_response(raw_text: str, model_class: type[BaseModel]) -> BaseModel:
    """Parse LLM output, stripping markdown fences if present."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return model_class(**json.loads(text))
```

---

## Key Takeaways

1. LLMs excel at tasks that are hard to express as rules: semantic log understanding, context-aware classification, and natural language generation.
2. Always use structured output (JSON + Pydantic) when integrating LLMs into automation pipelines.
3. Temperature 0.1-0.2 is best for operational tasks where consistency matters.
4. Chain-of-thought and few-shot prompting dramatically improve diagnostic accuracy.
5. Never let an LLM make irreversible changes without human approval.

---

## Validation

```bash
bash modules/01-ai-devops-overview/validation/validate.sh
```

---

**Next: [Module 02 ->](../02-log-analysis-llm/)**
