"""
Auto-Remediation Engine
========================
Detects known failure patterns, executes predefined safe remediations,
and escalates unknown issues to humans. Includes dry-run mode and
approval workflows for production safety.

Usage:
    engine = RemediationEngine()
    result = await engine.evaluate_and_remediate(incident)
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Callable, Awaitable

from openai import AsyncOpenAI
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("remediation")

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


class RemediationAction(BaseModel):
    """A single remediation step to execute."""
    name: str
    description: str
    command: Optional[str] = None  # Shell command to run
    script: Optional[str] = None  # Python function name to invoke
    rollback_command: Optional[str] = None
    timeout_seconds: int = 60
    requires_approval: bool = False
    risk_level: str = "low"  # low | medium | high | critical


class RemediationPlan(BaseModel):
    """Complete remediation plan for an incident."""
    plan_id: str
    incident_id: str
    pattern_matched: str
    actions: list[RemediationAction] = Field(default_factory=list)
    status: RemediationStatus = RemediationStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: list[dict] = Field(default_factory=list)
    dry_run: bool = True
    approved_by: Optional[str] = None
    confidence_score: float = 0.0


class IncidentContext(BaseModel):
    """Minimal incident context for remediation evaluation."""
    incident_id: str
    alert_name: str
    severity: str
    service: str = "unknown"
    description: str = ""
    labels: dict = Field(default_factory=dict)
    metrics: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Known Remediation Patterns
# ---------------------------------------------------------------------------

REMEDIATION_PATTERNS: dict[str, dict] = {
    "high_cpu_single_process": {
        "description": "Single process consuming excessive CPU",
        "match_keywords": ["high cpu", "cpu spike", "cpu utilization"],
        "match_labels": {"metric": "cpu_usage_percent"},
        "threshold": lambda ctx: ctx.metrics.get("cpu_percent", 0) > 90,
        "actions": [
            RemediationAction(
                name="identify_process",
                description="Identify the top CPU-consuming process",
                command="ps aux --sort=-%cpu | head -5",
                timeout_seconds=10,
            ),
            RemediationAction(
                name="collect_diagnostics",
                description="Capture thread dump and flame graph data",
                command="top -bn1 -H > /tmp/remediation_cpu_dump.txt",
                timeout_seconds=15,
            ),
            RemediationAction(
                name="restart_service",
                description="Gracefully restart the affected service",
                command="systemctl restart {service}",
                rollback_command="systemctl start {service}",
                timeout_seconds=60,
                requires_approval=True,
                risk_level="medium",
            ),
        ],
        "confidence": 0.85,
    },
    "disk_space_critical": {
        "description": "Disk usage above critical threshold",
        "match_keywords": ["disk full", "disk space", "no space left", "filesystem full"],
        "match_labels": {"metric": "disk_usage_percent"},
        "threshold": lambda ctx: ctx.metrics.get("disk_percent", 0) > 95,
        "actions": [
            RemediationAction(
                name="analyze_disk",
                description="Identify largest directories and files",
                command="du -sh /var/log/* /tmp/* /var/cache/* 2>/dev/null | sort -rh | head -10",
                timeout_seconds=30,
            ),
            RemediationAction(
                name="clean_old_logs",
                description="Rotate and compress logs older than 7 days",
                command="find /var/log -name '*.log' -mtime +7 -exec gzip {} \\;",
                rollback_command="find /var/log -name '*.log.gz' -mtime -1 -exec gunzip {} \\;",
                timeout_seconds=120,
                risk_level="low",
            ),
            RemediationAction(
                name="clean_docker",
                description="Remove unused Docker images and containers",
                command="docker system prune -f --volumes",
                rollback_command="echo 'Docker prune is not reversible - images will re-pull on next deploy'",
                timeout_seconds=120,
                requires_approval=True,
                risk_level="medium",
            ),
        ],
        "confidence": 0.92,
    },
    "service_crash_loop": {
        "description": "Service repeatedly crashing and restarting",
        "match_keywords": ["crashloop", "crash loop", "oomkilled", "restart loop", "exit code 137"],
        "match_labels": {},
        "threshold": lambda ctx: True,
        "actions": [
            RemediationAction(
                name="capture_logs",
                description="Capture recent crash logs for analysis",
                command="journalctl -u {service} --since '30 minutes ago' --no-pager | tail -100",
                timeout_seconds=15,
            ),
            RemediationAction(
                name="check_resources",
                description="Check memory and CPU limits",
                command="systemctl show {service} | grep -E 'Memory|CPU'",
                timeout_seconds=10,
            ),
            RemediationAction(
                name="increase_memory_limit",
                description="Temporarily increase memory limit by 50%",
                command="systemctl set-property {service} MemoryMax=+50%",
                rollback_command="systemctl revert {service}",
                timeout_seconds=30,
                requires_approval=True,
                risk_level="medium",
            ),
            RemediationAction(
                name="restart_with_debug",
                description="Restart service with debug logging enabled",
                command="systemctl restart {service}",
                timeout_seconds=60,
                requires_approval=True,
                risk_level="medium",
            ),
        ],
        "confidence": 0.78,
    },
    "high_error_rate": {
        "description": "Elevated HTTP 5xx error rate",
        "match_keywords": ["error rate", "5xx", "500 errors", "internal server error"],
        "match_labels": {},
        "threshold": lambda ctx: ctx.metrics.get("error_rate", 0) > 5.0,
        "actions": [
            RemediationAction(
                name="check_recent_deploys",
                description="Check for recent deployments that might have caused the errors",
                command="git -C /app log --oneline -5",
                timeout_seconds=10,
            ),
            RemediationAction(
                name="check_dependencies",
                description="Verify upstream dependency health",
                command="curl -sf http://localhost:8000/health || echo 'UNHEALTHY'",
                timeout_seconds=15,
            ),
            RemediationAction(
                name="rollback_deployment",
                description="Roll back to the previous known-good version",
                command="kubectl rollout undo deployment/{service}",
                rollback_command="kubectl rollout undo deployment/{service}",
                timeout_seconds=120,
                requires_approval=True,
                risk_level="high",
            ),
        ],
        "confidence": 0.80,
    },
    "connection_pool_exhaustion": {
        "description": "Database connection pool exhausted",
        "match_keywords": ["connection pool", "too many connections", "connection refused", "pool exhausted"],
        "match_labels": {},
        "threshold": lambda ctx: True,
        "actions": [
            RemediationAction(
                name="check_connections",
                description="Check current database connection count",
                command="psql -c 'SELECT count(*) FROM pg_stat_activity;'",
                timeout_seconds=10,
            ),
            RemediationAction(
                name="kill_idle_connections",
                description="Terminate idle connections older than 10 minutes",
                command=(
                    "psql -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE state = 'idle' AND state_change < now() - interval '10 minutes';\""
                ),
                rollback_command="echo 'Connections will be re-established by the application'",
                timeout_seconds=30,
                requires_approval=True,
                risk_level="medium",
            ),
        ],
        "confidence": 0.88,
    },
}


# ---------------------------------------------------------------------------
# Remediation Engine
# ---------------------------------------------------------------------------

class RemediationEngine:
    """Auto-remediation engine with safety guardrails."""

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        model: str = "gpt-4",
        dry_run: bool = True,
        approval_callback: Optional[Callable[[RemediationPlan], Awaitable[bool]]] = None,
        max_auto_remediations_per_hour: int = 5,
    ):
        self.client = AsyncOpenAI(api_key=openai_api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.dry_run = dry_run if os.getenv("REMEDIATION_DRY_RUN", "true").lower() != "false" else False
        self.approval_callback = approval_callback
        self.max_per_hour = max_auto_remediations_per_hour
        self._execution_log: list[RemediationPlan] = []
        self._circuit_breaker_open = False

    # ── Public API ────────────────────────────────────────────────

    async def evaluate_and_remediate(self, incident: IncidentContext) -> RemediationPlan:
        """
        Full remediation pipeline:
        1. Match incident to known patterns
        2. If no match, ask LLM for suggestions
        3. Check safety constraints (circuit breaker, rate limit)
        4. Execute or escalate
        """
        # Safety: circuit breaker
        if self._circuit_breaker_open:
            return self._escalate(incident, "Circuit breaker is OPEN - too many recent failures")

        # Safety: rate limiter
        if not self._check_rate_limit():
            return self._escalate(incident, f"Rate limit exceeded ({self.max_per_hour}/hour)")

        # Step 1: Match known patterns
        pattern_name, pattern = self._match_pattern(incident)

        if pattern:
            plan = RemediationPlan(
                plan_id=f"REM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                incident_id=incident.incident_id,
                pattern_matched=pattern_name,
                actions=pattern["actions"],
                confidence_score=pattern["confidence"],
                dry_run=self.dry_run,
            )
        else:
            # Step 2: Ask LLM for suggestions
            plan = await self._llm_suggest_remediation(incident)

        # Step 3: Execute the plan
        if plan.confidence_score < 0.5:
            plan.status = RemediationStatus.ESCALATED
            plan.results.append({"note": "Low confidence - escalating to human operator"})
        elif self.dry_run:
            plan = await self._dry_run_plan(plan, incident)
        else:
            plan = await self._execute_plan(plan, incident)

        self._execution_log.append(plan)
        return plan

    async def approve_plan(self, plan_id: str, approver: str) -> Optional[RemediationPlan]:
        """Approve a pending remediation plan for execution."""
        for plan in self._execution_log:
            if plan.plan_id == plan_id and plan.status == RemediationStatus.PENDING:
                plan.approved_by = approver
                plan.status = RemediationStatus.APPROVED
                return plan
        return None

    # ── Pattern Matching ──────────────────────────────────────────

    def _match_pattern(self, incident: IncidentContext) -> tuple[str, Optional[dict]]:
        """Match an incident against known remediation patterns."""
        searchable = f"{incident.alert_name} {incident.description}".lower()

        best_match = None
        best_score = 0

        for name, pattern in REMEDIATION_PATTERNS.items():
            score = 0
            for keyword in pattern["match_keywords"]:
                if keyword in searchable:
                    score += 1

            # Check label matches
            for key, value in pattern.get("match_labels", {}).items():
                if incident.labels.get(key) == value:
                    score += 2

            # Check threshold
            threshold_fn = pattern.get("threshold", lambda ctx: True)
            try:
                if threshold_fn(incident) and score > 0:
                    score += 1
            except Exception:
                pass

            if score > best_score:
                best_score = score
                best_match = (name, pattern)

        if best_match and best_score >= 1:
            return best_match
        return ("unknown", None)

    # ── LLM Remediation Suggestions ───────────────────────────────

    async def _llm_suggest_remediation(self, incident: IncidentContext) -> RemediationPlan:
        """Use LLM to suggest remediation when no pattern matches."""
        prompt = f"""Analyze this incident and suggest safe remediation steps.

Incident: {incident.alert_name}
Service: {incident.service}
Severity: {incident.severity}
Description: {incident.description}
Labels: {json.dumps(incident.labels)}
Metrics: {json.dumps(incident.metrics)}

Respond with a JSON object:
{{
    "pattern_name": "description of the detected pattern",
    "confidence": 0.0-1.0,
    "actions": [
        {{
            "name": "step_name",
            "description": "what this step does",
            "command": "shell command to execute",
            "risk_level": "low|medium|high",
            "requires_approval": true/false
        }}
    ]
}}

Rules:
- Only suggest commands that are safe and reversible
- High-risk actions MUST require approval
- Include diagnostic steps before remediation steps
- Maximum 5 actions"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=0.1,
                max_tokens=1000,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an SRE automation engine. Suggest safe, "
                            "reversible remediation actions. Always err on the side of caution."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            text = response.choices[0].message.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(text)

            actions = [
                RemediationAction(
                    name=a["name"],
                    description=a["description"],
                    command=a.get("command"),
                    risk_level=a.get("risk_level", "medium"),
                    requires_approval=a.get("requires_approval", True),
                )
                for a in data.get("actions", [])
            ]

            return RemediationPlan(
                plan_id=f"REM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                incident_id=incident.incident_id,
                pattern_matched=data.get("pattern_name", "llm-suggested"),
                actions=actions,
                confidence_score=data.get("confidence", 0.5),
                dry_run=self.dry_run,
            )
        except Exception as e:
            logger.error(f"LLM remediation suggestion failed: {e}")
            return RemediationPlan(
                plan_id=f"REM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                incident_id=incident.incident_id,
                pattern_matched="unknown",
                status=RemediationStatus.ESCALATED,
                results=[{"error": f"LLM suggestion failed: {e}"}],
            )

    # ── Plan Execution ────────────────────────────────────────────

    async def _dry_run_plan(self, plan: RemediationPlan, incident: IncidentContext) -> RemediationPlan:
        """Simulate plan execution without actually running commands."""
        plan.status = RemediationStatus.DRY_RUN
        plan.executed_at = datetime.utcnow()

        for action in plan.actions:
            cmd = (action.command or "").replace("{service}", incident.service)
            plan.results.append({
                "action": action.name,
                "status": "dry_run",
                "command": cmd,
                "description": action.description,
                "risk_level": action.risk_level,
                "requires_approval": action.requires_approval,
                "message": f"[DRY RUN] Would execute: {cmd}",
            })
            logger.info(f"[DRY RUN] {action.name}: {cmd}")

        plan.completed_at = datetime.utcnow()
        return plan

    async def _execute_plan(self, plan: RemediationPlan, incident: IncidentContext) -> RemediationPlan:
        """Execute remediation actions with safety checks."""
        plan.status = RemediationStatus.EXECUTING
        plan.executed_at = datetime.utcnow()

        for action in plan.actions:
            # Check if approval is needed
            if action.requires_approval:
                if self.approval_callback:
                    approved = await self.approval_callback(plan)
                    if not approved:
                        plan.status = RemediationStatus.PENDING
                        plan.results.append({
                            "action": action.name,
                            "status": "awaiting_approval",
                            "message": f"Action '{action.name}' requires human approval",
                        })
                        return plan
                elif os.getenv("REMEDIATION_APPROVAL_REQUIRED", "true").lower() == "true":
                    plan.status = RemediationStatus.PENDING
                    plan.results.append({
                        "action": action.name,
                        "status": "awaiting_approval",
                        "message": "Approval required but no callback configured",
                    })
                    return plan

            # Execute the command
            cmd = (action.command or "").replace("{service}", incident.service)
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=action.timeout_seconds
                )

                success = proc.returncode == 0
                plan.results.append({
                    "action": action.name,
                    "status": "success" if success else "failed",
                    "command": cmd,
                    "stdout": stdout.decode()[:500],
                    "stderr": stderr.decode()[:500],
                    "return_code": proc.returncode,
                })

                if not success:
                    logger.warning(f"Action {action.name} failed with return code {proc.returncode}")
                    # Try rollback if available
                    if action.rollback_command:
                        await self._execute_rollback(action, incident)
                    plan.status = RemediationStatus.FAILED
                    self._maybe_trip_circuit_breaker()
                    return plan

            except asyncio.TimeoutError:
                plan.results.append({
                    "action": action.name,
                    "status": "timeout",
                    "command": cmd,
                    "message": f"Timed out after {action.timeout_seconds}s",
                })
                plan.status = RemediationStatus.FAILED
                return plan
            except Exception as e:
                plan.results.append({
                    "action": action.name,
                    "status": "error",
                    "message": str(e),
                })
                plan.status = RemediationStatus.FAILED
                return plan

        plan.status = RemediationStatus.COMPLETED
        plan.completed_at = datetime.utcnow()
        return plan

    async def _execute_rollback(self, action: RemediationAction, incident: IncidentContext):
        """Attempt to roll back a failed action."""
        if not action.rollback_command:
            return
        cmd = action.rollback_command.replace("{service}", incident.service)
        logger.info(f"Executing rollback: {cmd}")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=action.timeout_seconds)
        except Exception as e:
            logger.error(f"Rollback failed for {action.name}: {e}")

    # ── Safety Mechanisms ─────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        """Ensure we haven't exceeded the hourly remediation limit."""
        cutoff = datetime.utcnow() - timedelta(hours=1)
        recent = [p for p in self._execution_log if p.created_at > cutoff]
        return len(recent) < self.max_per_hour

    def _maybe_trip_circuit_breaker(self):
        """Trip the circuit breaker if too many recent failures."""
        cutoff = datetime.utcnow() - timedelta(minutes=30)
        recent_failures = [
            p for p in self._execution_log
            if p.created_at > cutoff and p.status == RemediationStatus.FAILED
        ]
        if len(recent_failures) >= 3:
            self._circuit_breaker_open = True
            logger.critical("Circuit breaker TRIPPED - auto-remediation paused")

    def _escalate(self, incident: IncidentContext, reason: str) -> RemediationPlan:
        """Create an escalation plan when auto-remediation cannot proceed."""
        plan = RemediationPlan(
            plan_id=f"ESC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            incident_id=incident.incident_id,
            pattern_matched="escalation",
            status=RemediationStatus.ESCALATED,
            results=[{"reason": reason, "incident": incident.model_dump()}],
        )
        self._execution_log.append(plan)
        return plan

    # ── Reporting ─────────────────────────────────────────────────

    def get_execution_history(self, limit: int = 20) -> list[dict]:
        """Return recent remediation execution history."""
        return [p.model_dump() for p in self._execution_log[-limit:]]

    def get_stats(self) -> dict:
        """Return remediation engine statistics."""
        total = len(self._execution_log)
        if total == 0:
            return {"total": 0}

        statuses = {}
        for p in self._execution_log:
            statuses[p.status.value] = statuses.get(p.status.value, 0) + 1

        return {
            "total": total,
            "by_status": statuses,
            "circuit_breaker_open": self._circuit_breaker_open,
            "dry_run_mode": self.dry_run,
        }


# ---------------------------------------------------------------------------
# FastAPI Endpoints
# ---------------------------------------------------------------------------

from fastapi import APIRouter

router = APIRouter(prefix="/api/remediation", tags=["Auto-Remediation"])

_engine = RemediationEngine()


@router.post("/evaluate", response_model=RemediationPlan)
async def evaluate_remediation(incident: IncidentContext):
    """Evaluate an incident and return a remediation plan."""
    return await _engine.evaluate_and_remediate(incident)


@router.post("/approve/{plan_id}")
async def approve_remediation(plan_id: str, approver: str = "admin"):
    """Approve a pending remediation plan."""
    result = await _engine.approve_plan(plan_id, approver)
    if result is None:
        return {"error": "Plan not found or not in pending state"}
    return result.model_dump()


@router.get("/history")
async def remediation_history(limit: int = 20):
    """Get remediation execution history."""
    return {"history": _engine.get_execution_history(limit)}


@router.get("/stats")
async def remediation_stats():
    """Get remediation engine statistics."""
    return _engine.get_stats()
