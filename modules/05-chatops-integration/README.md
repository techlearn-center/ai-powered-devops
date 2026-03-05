# Module 05: ChatOps with AI Assistants

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Intermediate |
| **Prerequisites** | Module 04 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Build a Slack bot that responds to natural language DevOps commands
- Implement intent classification using regex patterns with LLM fallback
- Create rich Slack Block Kit responses for operational data
- Integrate with deployment, health check, and incident systems
- Handle Slack Events API webhooks in FastAPI

---

## Concepts

### ChatOps Architecture

```
Slack Workspace                ChatOps Bot                   Backend Systems
+------------------+     +--------------------+       +---------------------+
| "@bot deploy     |     | Intent Classifier  |       | ArgoCD (deploys)    |
|  status auth"    |---->| (regex patterns)   |------>| Health endpoints    |
+------------------+     +--------------------+       | PagerDuty (incidents|
        ^                        |                    | Prometheus (metrics)|
        |                        v                    +---------------------+
        |               +--------------------+
        +---------------| Response Handler   |
         Rich Block Kit | - deploy_status    |
         messages       | - health_check     |
                        | - incident_summary |
                        | - runbook          |
                        | - metrics          |
                        | - general (LLM)    |
                        +--------------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Intent Classification** | Determining what the user wants from their natural language message |
| **Block Kit** | Slack's UI framework for building rich, interactive messages |
| **Service Alias** | Short names that map to canonical service names ("auth" -> "auth-service") |
| **Ephemeral Message** | A Slack message visible only to the requesting user |

---

## Hands-On Lab

### Step 1: Setting Up the Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app
2. Add bot token scopes: `chat:write`, `app_mentions:read`, `channels:history`
3. Install to your workspace and copy the Bot Token

```bash
# Add to .env
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_SIGNING_SECRET=your-signing-secret
```

### Step 2: Intent Classification

```python
"""
intent_lab.py - Test the intent classifier on various queries
"""
from src.chatops.slack_bot import classify_intent

test_messages = [
    "What's the deployment status for auth-service in production?",
    "Is the order service healthy?",
    "Show me current incidents",
    "How do I fix a connection pool exhaustion?",
    "What's the CPU usage for api-gateway?",
    "Can you explain Kubernetes rolling updates?",
]

for msg in test_messages:
    cmd = classify_intent(msg)
    print(f"'{msg}'")
    print(f"  Intent: {cmd.intent} | Service: {cmd.service} | Env: {cmd.environment}\n")
```

### Step 3: Rich Slack Responses

```python
"""
slack_blocks_lab.py - Build rich deployment status messages
"""

def build_deploy_blocks(deployments: dict) -> list[dict]:
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": "Deployment Status"}}]

    status_icons = {"healthy": ":white_check_mark:", "deploying": ":arrows_counterclockwise:", "failed": ":x:"}

    for service, info in deployments.items():
        icon = status_icons.get(info["status"], ":question:")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"*{service}*\n"
                f"{icon} Status: `{info['status']}` | Version: `{info['version']}`\n"
                f"Deployed: {info['deployed_at']}"
            )},
        })
    return blocks

blocks = build_deploy_blocks({
    "api-gateway": {"version": "v2.14.3", "status": "healthy", "deployed_at": "2 hours ago"},
    "order-service": {"version": "v3.2.0", "status": "deploying", "deployed_at": "5 min ago"},
})
print(f"Generated {len(blocks)} blocks")
```

### Step 4: Testing the Bot Locally (No Slack Needed)

```python
"""
bot_test_lab.py - Test the bot without a Slack connection
"""
import asyncio
from src.chatops.slack_bot import DevOpsBot

async def main():
    bot = DevOpsBot()

    queries = [
        "What's deployed in production?",
        "Is the auth service healthy?",
        "Show me current incidents",
        "How do I troubleshoot high memory usage?",
    ]

    for query in queries:
        print(f"\nUser: {query}")
        response = await bot.handle_message(query)
        print(f"Bot: {response.text[:200]}")

asyncio.run(main())
```

### Step 5: REST API (Bypass Slack for Testing)

```bash
uvicorn src.main:app --reload

# Send a ChatOps message directly
curl -X POST http://localhost:8000/api/chatops/message \
  -H "Content-Type: application/json" \
  -d '{"text": "Is the order service healthy?"}'

# Test runbook lookup
curl -X POST http://localhost:8000/api/chatops/message \
  -H "Content-Type: application/json" \
  -d '{"text": "How do I fix a connection pool exhaustion?"}'
```

---

## Key Takeaways

1. Regex-based intent classification handles common queries instantly without LLM latency.
2. The LLM fallback ensures the bot can answer any question, even unanticipated ones.
3. Slack Block Kit makes responses far more scannable than plain text.
4. Service aliases ("auth" -> "auth-service") make the bot feel natural to use.
5. The `/api/chatops/message` REST endpoint lets you test without Slack infrastructure.

---

## Validation

```bash
bash modules/05-chatops-integration/validation/validate.sh
```

---

**Next: [Module 06 ->](../06-auto-remediation/)**
