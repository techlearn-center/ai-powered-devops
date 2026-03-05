"""
AI-Powered DevOps Platform - FastAPI Application
==================================================
Central API server that exposes all AI-DevOps capabilities:
- LLM-powered log analysis
- Automated incident triage
- ChatOps Slack integration
- Auto-remediation engine
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.log_analysis.log_analyzer import router as log_router
from src.incident.auto_triage import router as incident_router
from src.chatops.slack_bot import router as chatops_router
from src.remediation.auto_remediate import router as remediation_router

app = FastAPI(
    title="AI-Powered DevOps Platform",
    description="LLM-powered log analysis, incident triage, ChatOps, and auto-remediation",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(log_router)
app.include_router(incident_router)
app.include_router(chatops_router)
app.include_router(remediation_router)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ai-devops-platform"}


@app.get("/")
async def root():
    return {
        "service": "AI-Powered DevOps Platform",
        "version": "1.0.0",
        "endpoints": [
            "/api/logs/analyze",
            "/api/logs/parse",
            "/api/incidents/triage",
            "/api/incidents/recent",
            "/api/chatops/message",
            "/api/chatops/slack/events",
            "/api/remediation/evaluate",
            "/api/remediation/history",
            "/api/remediation/stats",
            "/health",
        ],
    }
