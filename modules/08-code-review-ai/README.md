# Module 08: AI-Powered Code Review

| | |
|---|---|
| **Time** | 3-5 hours |
| **Difficulty** | Advanced |
| **Prerequisites** | Module 07 completed |

---

## Learning Objectives

By the end of this module, you will be able to:

- Build an LLM-powered code review bot that analyzes pull request diffs
- Detect security vulnerabilities, performance issues, and anti-patterns using semantic analysis
- Generate actionable review comments with suggested fixes
- Implement deployment risk scoring based on code changes
- Integrate with GitHub webhooks for automated PR reviews

---

## Concepts

### AI Code Review Pipeline

```
GitHub PR Webhook          Analysis Engine           Review Output
+---------------+     +---------------------+     +------------------+
| PR opened /   |     | 1. Parse diff       |     | Review Comments  |
| updated       |---->| 2. Security scan    |---->|  - severity      |
+---------------+     | 3. Performance check|     |  - line number   |
                      | 4. Best practices   |     |  - suggestion    |
                      | 5. Risk scoring     |     |  - fix snippet   |
                      +---------------------+     +------------------+
                             |                          |
                      +------+------+           +-------+-------+
                      | LLM Engine  |           | Risk Score    |
                      | (GPT-4)     |           | (0-100)       |
                      +-------------+           +---------------+
```

### Key Terminology

| Term | Definition |
|---|---|
| **Diff Analysis** | Examining only the changed lines in a PR, not the entire file |
| **Security Scan** | Detecting hardcoded secrets, SQL injection, XSS, insecure configurations |
| **Risk Score** | Numerical rating (0-100) of how risky a deployment would be based on the changes |
| **Semantic Review** | Understanding code intent, not just syntax -- detecting logic errors and architectural issues |

---

## Hands-On Lab

### Step 1: Parsing Git Diffs

```python
"""
diff_parser.py - Extract structured change data from git diffs
"""
import re
from dataclasses import dataclass


@dataclass
class FileChange:
    filename: str
    additions: list[str]
    deletions: list[str]
    language: str


def parse_diff(diff_text: str) -> list[FileChange]:
    """Parse a unified diff into structured file changes."""
    files = []
    current_file = None
    additions = []
    deletions = []

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file:
                files.append(FileChange(
                    filename=current_file,
                    additions=additions,
                    deletions=deletions,
                    language=_detect_language(current_file),
                ))
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else "unknown"
            additions, deletions = [], []
        elif line.startswith("+") and not line.startswith("+++"):
            additions.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            deletions.append(line[1:])

    if current_file:
        files.append(FileChange(
            filename=current_file, additions=additions,
            deletions=deletions, language=_detect_language(current_file),
        ))

    return files


def _detect_language(filename: str) -> str:
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".go": "go", ".java": "java", ".rs": "rust", ".yml": "yaml",
        ".yaml": "yaml", ".tf": "terraform", ".sh": "bash",
    }
    for ext, lang in ext_map.items():
        if filename.endswith(ext):
            return lang
    return "unknown"
```

### Step 2: Security Vulnerability Scanner

```python
"""
security_scanner.py - Detect common security issues in code changes
"""
import re
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()

# Rule-based quick checks (fast, no LLM needed)
SECURITY_PATTERNS = {
    "hardcoded_secret": {
        "pattern": re.compile(
            r'(?:password|secret|api_key|token|private_key)\s*=\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE,
        ),
        "severity": "critical",
        "message": "Hardcoded secret detected. Use environment variables instead.",
    },
    "sql_injection": {
        "pattern": re.compile(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{'),
        "severity": "critical",
        "message": "Potential SQL injection via f-string. Use parameterized queries.",
    },
    "eval_usage": {
        "pattern": re.compile(r'\beval\s*\('),
        "severity": "high",
        "message": "eval() usage detected. This can execute arbitrary code.",
    },
    "insecure_http": {
        "pattern": re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)'),
        "severity": "medium",
        "message": "Non-localhost HTTP URL detected. Use HTTPS in production.",
    },
}


def quick_security_scan(code_lines: list[str]) -> list[dict]:
    findings = []
    for i, line in enumerate(code_lines, 1):
        for name, rule in SECURITY_PATTERNS.items():
            if rule["pattern"].search(line):
                findings.append({
                    "rule": name, "line": i,
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "code": line.strip(),
                })
    return findings


def llm_security_review(diff_text: str) -> list[dict]:
    """Deep security review using LLM for semantic analysis."""
    response = client.chat.completions.create(
        model="gpt-4", temperature=0.1, max_tokens=1000,
        messages=[
            {"role": "system", "content": (
                "You are a senior security engineer reviewing code. "
                "Find vulnerabilities. Return JSON array of: "
                "{\"severity\": \"critical|high|medium|low\", \"issue\": str, "
                "\"line_hint\": str, \"fix\": str}"
            )},
            {"role": "user", "content": f"Review this diff for security issues:\n\n{diff_text}"},
        ],
    )
    return json.loads(response.choices[0].message.content.strip())
```

### Step 3: Deployment Risk Scoring

```python
"""
risk_scorer.py - Score deployment risk based on PR changes
"""
from dataclasses import dataclass


@dataclass
class RiskScore:
    score: int          # 0-100
    level: str          # low | medium | high | critical
    factors: list[str]  # reasons contributing to the score


def calculate_risk_score(file_changes: list[dict]) -> RiskScore:
    """Calculate deployment risk based on what files changed."""
    score = 0
    factors = []

    total_additions = sum(len(f.get("additions", [])) for f in file_changes)
    total_deletions = sum(len(f.get("deletions", [])) for f in file_changes)
    total_files = len(file_changes)

    # Factor 1: Change size
    total_lines = total_additions + total_deletions
    if total_lines > 500:
        score += 30
        factors.append(f"Large change: {total_lines} lines across {total_files} files")
    elif total_lines > 200:
        score += 15
        factors.append(f"Medium change: {total_lines} lines")

    # Factor 2: Critical file changes
    critical_patterns = ["migration", "schema", "database", "auth", "payment", "deploy", "infra"]
    for f in file_changes:
        filename = f.get("filename", "").lower()
        for pattern in critical_patterns:
            if pattern in filename:
                score += 15
                factors.append(f"Critical file modified: {f['filename']}")
                break

    # Factor 3: Config file changes
    config_patterns = [".yml", ".yaml", ".env", ".toml", "Dockerfile", "terraform"]
    for f in file_changes:
        for pattern in config_patterns:
            if pattern in f.get("filename", ""):
                score += 10
                factors.append(f"Config file changed: {f['filename']}")
                break

    # Factor 4: Deletion-heavy changes
    if total_deletions > total_additions * 2:
        score += 10
        factors.append("Deletion-heavy change (potential feature removal)")

    score = min(score, 100)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"

    return RiskScore(score=score, level=level, factors=factors)
```

### Step 4: Full PR Review Bot

```python
"""
pr_review_bot.py - Automated PR review combining all checks
"""
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI()


def review_pr(diff_text: str, pr_title: str, pr_description: str) -> dict:
    """Run a comprehensive AI code review on a PR."""
    response = client.chat.completions.create(
        model="gpt-4", temperature=0.2, max_tokens=2000,
        messages=[
            {"role": "system", "content": (
                "You are a senior engineer reviewing a pull request. Provide:\n"
                "1. Overall assessment (approve/request_changes/comment)\n"
                "2. Security issues found\n"
                "3. Performance concerns\n"
                "4. Code quality suggestions\n"
                "5. A deployment risk assessment\n"
                "Return JSON: {\"decision\": str, \"summary\": str, "
                "\"security_issues\": [str], \"performance_issues\": [str], "
                "\"suggestions\": [str], \"risk_level\": str}"
            )},
            {"role": "user", "content": (
                f"PR Title: {pr_title}\n"
                f"Description: {pr_description}\n\n"
                f"Diff:\n{diff_text}"
            )},
        ],
    )
    return json.loads(response.choices[0].message.content.strip())
```

---

## Key Takeaways

1. Rule-based pattern matching catches low-hanging fruit (hardcoded secrets, eval, SQL injection) instantly.
2. LLM semantic review catches subtle issues that regex cannot: logic errors, architectural anti-patterns, missing error handling.
3. Deployment risk scoring gives teams objective data to decide whether a change needs extra review.
4. Combine fast rule-based checks with deeper LLM analysis for the best coverage-to-latency ratio.
5. Always present findings with suggested fixes, not just complaints.

---

## Validation

```bash
bash modules/08-code-review-ai/validation/validate.sh
```

---

**Next: [Module 09 ->](../09-infrastructure-optimization/)**
