"""
AI-Powered ChatOps Slack Bot
==============================
Responds to DevOps queries via Slack using natural language.
Supports deployment status, health checks, incident summaries,
runbook lookups, and ad-hoc infrastructure questions.

Usage:
    # Run directly
    python -m src.chatops.slack_bot

    # Or mount in FastAPI
    from src.chatops.slack_bot import router
    app.include_router(router)
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Optional

from openai import AsyncOpenAI
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.errors import SlackApiError

load_dotenv()

logger = logging.getLogger("chatops")

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class ChatCommand(BaseModel):
    """Parsed user command from Slack."""
    intent: str  # deploy_status | health_check | incident_summary | runbook | ask | unknown
    service: Optional[str] = None
    environment: Optional[str] = None
    time_range: Optional[str] = None
    raw_text: str = ""
    user_id: str = ""
    channel_id: str = ""


class BotResponse(BaseModel):
    """Structured response to send back to Slack."""
    text: str
    blocks: list[dict] = Field(default_factory=list)
    thread_ts: Optional[str] = None
    ephemeral: bool = False


# ---------------------------------------------------------------------------
# Intent Classification
# ---------------------------------------------------------------------------

INTENT_PATTERNS = {
    "deploy_status": [
        r"deploy(?:ment)?\s+status",
        r"what(?:'s| is)\s+deployed",
        r"last\s+deploy",
        r"release\s+status",
        r"rollback\s+status",
    ],
    "health_check": [
        r"health\s+(?:check|status)",
        r"is\s+\S+\s+(?:up|down|healthy|running)",
        r"service\s+status",
        r"check\s+\S+",
        r"status\s+of\s+\S+",
    ],
    "incident_summary": [
        r"incident\s+(?:summary|report|status)",
        r"what(?:'s| is)\s+(?:happening|going on|broken)",
        r"current\s+incidents?",
        r"active\s+alerts?",
        r"on-?call\s+(?:status|summary)",
    ],
    "runbook": [
        r"runbook\s+(?:for|on)",
        r"how\s+(?:to|do\s+I)\s+(?:fix|resolve|restart|rollback)",
        r"troubleshoot",
        r"fix\s+\S+",
    ],
    "metrics": [
        r"(?:cpu|memory|disk|latency|error\s+rate)",
        r"metrics?\s+for",
        r"show\s+(?:me\s+)?(?:the\s+)?(?:dashboard|graphs?|charts?)",
    ],
}

SERVICE_ALIASES = {
    "api": "api-gateway",
    "gateway": "api-gateway",
    "auth": "auth-service",
    "login": "auth-service",
    "users": "user-service",
    "orders": "order-service",
    "payments": "payment-service",
    "pay": "payment-service",
    "inventory": "inventory-service",
    "stock": "inventory-service",
    "notifications": "notification-service",
    "notif": "notification-service",
}


def classify_intent(text: str) -> ChatCommand:
    """Classify user message into a DevOps intent."""
    text_lower = text.lower().strip()

    # Remove bot mention
    text_lower = re.sub(r"<@\w+>", "", text_lower).strip()

    intent = "ask"  # default: pass to LLM
    for intent_name, patterns in INTENT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                intent = intent_name
                break
        if intent != "ask":
            break

    # Extract service name
    service = None
    for alias, canonical in SERVICE_ALIASES.items():
        if alias in text_lower:
            service = canonical
            break

    # Extract environment
    environment = None
    for env in ("production", "staging", "development", "prod", "stage", "dev"):
        if env in text_lower:
            environment = env if len(env) > 4 else {"prod": "production", "stage": "staging", "dev": "development"}[env]
            break

    return ChatCommand(
        intent=intent,
        service=service,
        environment=environment or "production",
        raw_text=text,
    )


# ---------------------------------------------------------------------------
# Response Handlers
# ---------------------------------------------------------------------------

class DevOpsBot:
    """AI-powered Slack bot for DevOps operations."""

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        slack_token: Optional[str] = None,
        model: str = "gpt-4",
    ):
        self.llm = AsyncOpenAI(api_key=openai_api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.slack = AsyncWebClient(token=slack_token or os.getenv("SLACK_BOT_TOKEN"))

    async def handle_message(self, text: str, user_id: str = "", channel_id: str = "") -> BotResponse:
        """Route a user message to the appropriate handler."""
        command = classify_intent(text)
        command.user_id = user_id
        command.channel_id = channel_id

        handlers = {
            "deploy_status": self._handle_deploy_status,
            "health_check": self._handle_health_check,
            "incident_summary": self._handle_incident_summary,
            "runbook": self._handle_runbook,
            "metrics": self._handle_metrics,
            "ask": self._handle_general_question,
        }

        handler = handlers.get(command.intent, self._handle_general_question)
        return await handler(command)

    # ── Deploy Status ─────────────────────────────────────────────

    async def _handle_deploy_status(self, cmd: ChatCommand) -> BotResponse:
        """Return current deployment status."""
        # In production, this would query your CD system (ArgoCD, Spinnaker, etc.)
        service = cmd.service or "all services"
        env = cmd.environment or "production"

        # Simulated deployment data
        deployments = {
            "api-gateway": {"version": "v2.14.3", "deployed_at": "2 hours ago", "status": "healthy"},
            "auth-service": {"version": "v1.8.1", "deployed_at": "1 day ago", "status": "healthy"},
            "order-service": {"version": "v3.2.0", "deployed_at": "30 minutes ago", "status": "rolling"},
        }

        if cmd.service and cmd.service in deployments:
            d = deployments[cmd.service]
            blocks = self._format_deploy_block(cmd.service, d, env)
        else:
            blocks = []
            for svc, d in deployments.items():
                blocks.extend(self._format_deploy_block(svc, d, env))
                blocks.append({"type": "divider"})

        return BotResponse(
            text=f"Deployment status for {service} in {env}",
            blocks=blocks,
        )

    def _format_deploy_block(self, service: str, deploy: dict, env: str) -> list[dict]:
        status_emoji = {"healthy": ":white_check_mark:", "rolling": ":arrows_counterclockwise:", "failed": ":x:"}
        return [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{service}* ({env})\n"
                        f"{status_emoji.get(deploy['status'], ':question:')} Status: `{deploy['status']}`\n"
                        f":package: Version: `{deploy['version']}`\n"
                        f":clock1: Deployed: {deploy['deployed_at']}"
                    ),
                },
            }
        ]

    # ── Health Check ──────────────────────────────────────────────

    async def _handle_health_check(self, cmd: ChatCommand) -> BotResponse:
        """Run health checks against services."""
        service = cmd.service or "all services"

        # In production, ping actual health endpoints
        health_data = {
            "api-gateway": {"status": "UP", "latency_ms": 12, "uptime": "99.99%"},
            "auth-service": {"status": "UP", "latency_ms": 8, "uptime": "99.97%"},
            "order-service": {"status": "DEGRADED", "latency_ms": 450, "uptime": "98.5%"},
            "payment-service": {"status": "UP", "latency_ms": 23, "uptime": "99.95%"},
        }

        lines = [f"*Health Check Results* ({cmd.environment})\n"]
        for svc, h in health_data.items():
            if cmd.service and svc != cmd.service:
                continue
            icon = ":white_check_mark:" if h["status"] == "UP" else ":warning:"
            lines.append(f"{icon} `{svc}` - {h['status']} | Latency: {h['latency_ms']}ms | Uptime: {h['uptime']}")

        return BotResponse(
            text=f"Health check for {service}",
            blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}],
        )

    # ── Incident Summary ──────────────────────────────────────────

    async def _handle_incident_summary(self, cmd: ChatCommand) -> BotResponse:
        """Summarize current active incidents."""
        # In production, pull from PagerDuty / Opsgenie / custom incident DB
        prompt = f"""Summarize the current incident landscape for a DevOps team.
User asked: "{cmd.raw_text}"
Environment: {cmd.environment}

Generate a realistic incident summary in markdown format including:
- Number of active incidents
- Highest severity active incident
- Services affected
- Time since last major incident
Keep it concise (5-7 lines)."""

        summary = await self._ask_llm(prompt)
        return BotResponse(
            text="Incident Summary",
            blocks=[
                {"type": "header", "text": {"type": "plain_text", "text": "Active Incident Summary"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            ],
        )

    # ── Runbook Lookup ────────────────────────────────────────────

    async def _handle_runbook(self, cmd: ChatCommand) -> BotResponse:
        """Look up and display relevant runbook steps."""
        prompt = f"""A DevOps engineer needs help with: "{cmd.raw_text}"
Service: {cmd.service or 'unknown'}
Environment: {cmd.environment}

Provide a step-by-step runbook response. Include:
1. Quick diagnosis commands (bash/kubectl)
2. Common root causes
3. Remediation steps
4. Escalation criteria

Use concise markdown formatting suitable for Slack."""

        runbook_text = await self._ask_llm(prompt)
        return BotResponse(
            text="Runbook",
            blocks=[
                {"type": "header", "text": {"type": "plain_text", "text": f"Runbook: {cmd.raw_text[:50]}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": runbook_text}},
            ],
        )

    # ── Metrics ───────────────────────────────────────────────────

    async def _handle_metrics(self, cmd: ChatCommand) -> BotResponse:
        """Display key metrics for requested services."""
        service = cmd.service or "api-gateway"
        text = (
            f"*Metrics for `{service}`* ({cmd.environment})\n\n"
            f":chart_with_upwards_trend: *Request Rate:* 1,247 req/s\n"
            f":hourglass: *P99 Latency:* 142ms\n"
            f":x: *Error Rate:* 0.12%\n"
            f":computer: *CPU Usage:* 45%\n"
            f":floppy_disk: *Memory Usage:* 62%\n\n"
            f":link: <https://grafana.internal/d/{service}|View Full Dashboard>"
        )
        return BotResponse(
            text=f"Metrics for {service}",
            blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
        )

    # ── General AI Question ───────────────────────────────────────

    async def _handle_general_question(self, cmd: ChatCommand) -> BotResponse:
        """Use LLM for any unclassified DevOps question."""
        prompt = f"""You are a helpful DevOps AI assistant in a Slack channel.
A team member asks: "{cmd.raw_text}"

Provide a helpful, concise answer. If it involves specific commands, format them
as code blocks. Keep the response under 300 words and suitable for Slack formatting."""

        answer = await self._ask_llm(prompt)
        return BotResponse(text=answer)

    # ── LLM Helper ────────────────────────────────────────────────

    async def _ask_llm(self, prompt: str) -> str:
        """Send a prompt to the LLM and return the response text."""
        try:
            response = await self.llm.chat.completions.create(
                model=self.model,
                temperature=0.3,
                max_tokens=800,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior SRE / DevOps engineer assistant. "
                            "Provide concise, actionable answers. Use Slack markdown formatting."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return f"I encountered an error processing your request: {e}"

    # ── Slack Message Sender ──────────────────────────────────────

    async def send_to_slack(self, channel: str, response: BotResponse):
        """Send a BotResponse to a Slack channel."""
        try:
            if response.blocks:
                await self.slack.chat_postMessage(
                    channel=channel,
                    text=response.text,
                    blocks=response.blocks,
                    thread_ts=response.thread_ts,
                )
            else:
                await self.slack.chat_postMessage(
                    channel=channel,
                    text=response.text,
                    thread_ts=response.thread_ts,
                )
        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")


# ---------------------------------------------------------------------------
# FastAPI Endpoints
# ---------------------------------------------------------------------------

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/chatops", tags=["ChatOps"])

_bot = DevOpsBot()


class SlackMessageRequest(BaseModel):
    text: str
    user_id: str = "U0000000"
    channel_id: str = "C0000000"


@router.post("/message")
async def handle_chat_message(request: SlackMessageRequest):
    """Process a ChatOps message and return the bot response."""
    response = await _bot.handle_message(
        text=request.text,
        user_id=request.user_id,
        channel_id=request.channel_id,
    )
    return response.model_dump()


@router.post("/slack/events")
async def slack_events(request: Request):
    """Handle Slack Events API webhook (URL verification + message events)."""
    body = await request.json()

    # URL verification challenge
    if body.get("type") == "url_verification":
        return {"challenge": body["challenge"]}

    # Process message events
    event = body.get("event", {})
    if event.get("type") == "app_mention" or event.get("type") == "message":
        text = event.get("text", "")
        user_id = event.get("user", "")
        channel = event.get("channel", "")

        if user_id and not event.get("bot_id"):  # Ignore bot messages
            response = await _bot.handle_message(text, user_id, channel)
            await _bot.send_to_slack(channel, response)

    return {"ok": True}


@router.get("/health")
async def chatops_health():
    """ChatOps bot health check."""
    return {"status": "healthy", "bot": "ai-devops-chatops", "timestamp": datetime.utcnow().isoformat()}
