"""
CI/CD Security Scanner
Scans CI/CD pipeline definitions (GitHub Actions, GitLab CI, Jenkinsfile,
CircleCI, Azure Pipelines) for security issues: unpinned actions, script
injection, hardcoded secrets, untrusted runners, missing permissions, etc.

Author: Mohith Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict

from report_generator import generate_html


RULES = [
    {
        "id": "CICD-001",
        "name": "Unpinned third-party GitHub Action (not pinned to SHA)",
        "severity": "HIGH",
        "confidence": 0.92,
        "source": "OWASP CICD-SEC-4, SLSA L2",
        "remediation": "Pin third-party actions to a full commit SHA: uses: actions/checkout@<40-char-sha>",
    },
    {
        "id": "CICD-002",
        "name": "Script injection via ${{ github.event.* }} in run: block",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source": "OWASP CICD-SEC-7 (GHSL-2022-099)",
        "remediation": "Move untrusted input into an env var, then reference $VAR inside the script. Never embed ${{ github.* }} directly.",
    },
    {
        "id": "CICD-003",
        "name": "Hardcoded secret / API key in pipeline",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "source": "OWASP CICD-SEC-6",
        "remediation": "Move to repository secrets and reference via ${{ secrets.XXX }}. Rotate any leaked credential immediately.",
    },
    {
        "id": "CICD-004",
        "name": "Workflow uses `pull_request_target` with `checkout` of PR code",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "source": "OWASP CICD-SEC-7 (pwn request)",
        "remediation": "Never checkout PR code under pull_request_target. Use pull_request + restrict secret exposure.",
    },
    {
        "id": "CICD-005",
        "name": "Default permissions (GITHUB_TOKEN write-all) not restricted",
        "severity": "HIGH",
        "confidence": 0.85,
        "source": "OWASP CICD-SEC-2",
        "remediation": "Set `permissions: read-all` at the workflow level and grant write per-job only when needed.",
    },
    {
        "id": "CICD-006",
        "name": "Self-hosted runner used with public repo (code execution risk)",
        "severity": "HIGH",
        "confidence": 0.85,
        "source": "GitHub security docs",
        "remediation": "Do not use self-hosted runners on public repos, or restrict to private/organization visibility + require approval.",
    },
    {
        "id": "CICD-007",
        "name": "Unverified third-party action (not from verified creator)",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "source": "OWASP CICD-SEC-3",
        "remediation": "Prefer verified actions (actions/*, aws-actions/*, docker/*). Audit third-party actions before use.",
    },
    {
        "id": "CICD-008",
        "name": "`curl | sh` or `wget | bash` pipe-to-shell in pipeline",
        "severity": "HIGH",
        "confidence": 0.93,
        "source": "SLSA integrity",
        "remediation": "Download artifact, verify checksum/signature, then execute. Never pipe untrusted stdout to a shell.",
    },
    {
        "id": "CICD-009",
        "name": "Docker image pulled without digest (`:latest` or floating tag)",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "source": "SLSA integrity",
        "remediation": "Pin to a digest (ubuntu:22.04@sha256:<digest>) or a specific immutable version.",
    },
    {
        "id": "CICD-010",
        "name": "No secret-scanning / SAST step in workflow",
        "severity": "LOW",
        "confidence": 0.60,
        "source": "OWASP CICD-SEC-1",
        "remediation": "Add a secret-scanning step (trufflehog, gitleaks) and a SAST step (semgrep, bandit) before deploy.",
    },
    {
        "id": "CICD-011",
        "name": "AWS credentials passed as environment variables (prefer OIDC)",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "source": "OWASP CICD-SEC-6",
        "remediation": "Use aws-actions/configure-aws-credentials with OIDC role-to-assume instead of static keys.",
    },
    {
        "id": "CICD-012",
        "name": "`workflow_dispatch` with unvalidated input in run: block",
        "severity": "HIGH",
        "confidence": 0.85,
        "source": "OWASP CICD-SEC-7",
        "remediation": "Validate/escape inputs. Never interpolate ${{ github.event.inputs.* }} directly into run scripts.",
    },
]


# Secret regexes (subset of trufflehog/gitleaks patterns)
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT (classic)"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT (fine-grained)"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API key"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key block"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"$][^'\"]{6,}['\"]", "Hardcoded password"),
    (r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", "Hardcoded Bearer token"),
]

UNTRUSTED_INPUT_SOURCES = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.inputs",
    "github.head_ref",
]

VERIFIED_ACTION_OWNERS = {"actions", "github", "docker", "aws-actions", "azure",
                          "google-github-actions", "hashicorp", "octokit"}


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    confidence: float
    source: str
    file: str
    line: int
    snippet: str
    risk_score: float
    remediation: str


def risk_score(rule: dict, extra: float = 0.0) -> float:
    base = rule["confidence"] * 60
    sev_bonus = {"CRITICAL": 18, "HIGH": 10, "MEDIUM": 5, "LOW": 0}
    return round(min(100.0, base + sev_bonus.get(rule["severity"], 0) + extra), 1)


def mk(r, file, line, snippet, extra=0.0):
    return Finding(
        id=r["id"], name=r["name"], severity=r["severity"],
        confidence=r["confidence"], source=r["source"],
        file=file, line=line, snippet=snippet[:200],
        risk_score=risk_score(r, extra), remediation=r["remediation"],
    )


def rule(rid):
    return next(r for r in RULES if r["id"] == rid)


# -------------------------------------------------------------
# Workflow file scanners
# -------------------------------------------------------------
def scan_github_actions(text: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    full = text.lower()

    # Workflow-level signals
    uses_pr_target = "pull_request_target" in full
    has_checkout_ref = re.search(r"actions/checkout.*\n[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text)
    has_top_perms = re.search(r"^permissions:", text, re.MULTILINE)

    # Line-by-line rules
    in_run_block = False
    run_buffer = []
    run_start_line = 0

    for i, ln in enumerate(lines, 1):
        lower = ln.lower()

        # Rule 1 - unpinned action
        m = re.search(r"uses:\s*([A-Za-z0-9_\-./]+)@([A-Za-z0-9_\-./]+)", ln)
        if m:
            owner_name, ref = m.group(1), m.group(2)
            owner = owner_name.split("/")[0]
            is_docker_or_local = owner_name.startswith("./") or "docker://" in owner_name
            # pinned to sha if ref is a 40-char hex
            pinned = bool(re.match(r"^[0-9a-f]{40}$", ref))
            if not pinned and not is_docker_or_local and owner not in VERIFIED_ACTION_OWNERS:
                findings.append(mk(rule("CICD-001"), path, i, ln.strip()))
            if not is_docker_or_local and owner not in VERIFIED_ACTION_OWNERS and not pinned:
                findings.append(mk(rule("CICD-007"), path, i, ln.strip()))

        # Rule 9 - image without digest
        m = re.search(r"image:\s*([A-Za-z0-9_\-/.:@]+)", ln)
        if m:
            img = m.group(1)
            if "@sha256:" not in img and (img.endswith(":latest") or ":" not in img.split("/")[-1]):
                findings.append(mk(rule("CICD-009"), path, i, ln.strip()))

        # Rule 6 - self-hosted runner
        if re.search(r"runs-on:\s*\[?\s*self-hosted", lower):
            findings.append(mk(rule("CICD-006"), path, i, ln.strip()))

        # Rule 8 - curl | sh
        if re.search(r"(curl|wget)[^|]*\|[^\n]*(sh|bash)\b", ln):
            findings.append(mk(rule("CICD-008"), path, i, ln.strip()))

        # Secrets
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, ln):
                f = mk(rule("CICD-003"), path, i, ln.strip())
                f.name = f"Hardcoded secret / API key in pipeline ({label})"
                findings.append(f)

        # Rule 11 - AWS creds env
        if re.search(r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY", ln) and "secrets." not in lower:
            findings.append(mk(rule("CICD-011"), path, i, ln.strip()))

        # Track run: blocks for script injection rule
        stripped = ln.strip()
        m_run = re.match(r"^\s*run:\s*\|?\s*(.*)$", ln)
        if m_run:
            in_run_block = True
            run_start_line = i
            run_buffer = [m_run.group(1)] if m_run.group(1) else []
            continue
        if in_run_block:
            # end when another top-level key or decreased indent
            if re.match(r"^\s*[a-zA-Z_-]+\s*:", ln) and not ln.startswith(" " * 8):
                _check_run_block(run_buffer, run_start_line, path, findings)
                in_run_block = False
                run_buffer = []
            else:
                run_buffer.append(ln)

    if in_run_block:
        _check_run_block(run_buffer, run_start_line, path, findings)

    # Workflow-level findings
    if uses_pr_target and has_checkout_ref:
        findings.append(mk(rule("CICD-004"), path, 1,
                           "pull_request_target + checkout of PR ref"))
    if not has_top_perms:
        findings.append(mk(rule("CICD-005"), path, 1,
                           "no top-level `permissions:` block (uses default write-all)"))

    # Rule 10 - no secret scanning / SAST
    if not re.search(r"trufflehog|gitleaks|semgrep|bandit|snyk|sast", full):
        findings.append(mk(rule("CICD-010"), path, 1, "no secret-scan / SAST step detected"))

    return findings


def _check_run_block(buf: List[str], line: int, path: str, findings: List[Finding]):
    joined = "\n".join(buf)
    for src in UNTRUSTED_INPUT_SOURCES:
        if "${{" in joined and src in joined:
            findings.append(mk(rule("CICD-002"), path, line,
                               f"run block interpolates ${{ {src} }}"))
    # Rule 12 - workflow_dispatch inputs in run block
    if "github.event.inputs" in joined and "${{" in joined:
        findings.append(mk(rule("CICD-012"), path, line,
                           "run block interpolates ${{ github.event.inputs.* }}"))


def scan_gitlab_ci(text: str, path: str) -> List[Finding]:
    findings = []
    for i, ln in enumerate(text.splitlines(), 1):
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, ln):
                f = mk(rule("CICD-003"), path, i, ln.strip())
                f.name = f"Hardcoded secret / API key in pipeline ({label})"
                findings.append(f)
        if re.search(r"(curl|wget)[^|]*\|[^\n]*(sh|bash)\b", ln):
            findings.append(mk(rule("CICD-008"), path, i, ln.strip()))
        m = re.search(r"image:\s*([A-Za-z0-9_\-/.:@]+)", ln)
        if m:
            img = m.group(1)
            if "@sha256:" not in img and (img.endswith(":latest") or ":" not in img.split("/")[-1]):
                findings.append(mk(rule("CICD-009"), path, i, ln.strip()))
    return findings


def scan_jenkinsfile(text: str, path: str) -> List[Finding]:
    findings = []
    for i, ln in enumerate(text.splitlines(), 1):
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, ln):
                f = mk(rule("CICD-003"), path, i, ln.strip())
                f.name = f"Hardcoded secret / API key in pipeline ({label})"
                findings.append(f)
        if re.search(r"(curl|wget)[^|]*\|[^\n]*(sh|bash)\b", ln):
            findings.append(mk(rule("CICD-008"), path, i, ln.strip()))
    return findings


def scan_file(p: Path) -> List[Finding]:
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    name = p.name.lower()
    s = str(p).lower()
    if "github/workflows" in s.replace("\\", "/") or (p.suffix in (".yml", ".yaml") and re.search(r"^\s*on:", text, re.M)):
        return scan_github_actions(text, str(p))
    if name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return scan_gitlab_ci(text, str(p))
    if name in ("jenkinsfile",) or name.endswith(".jenkinsfile"):
        return scan_jenkinsfile(text, str(p))
    if p.suffix in (".yml", ".yaml"):
        # Fallback - try both
        if "jobs:" in text and ("uses:" in text or "run:" in text):
            return scan_github_actions(text, str(p))
    return []


def scan_target(target: Path) -> List[Finding]:
    if target.is_file():
        return scan_file(target)
    findings: List[Finding] = []
    for p in target.rglob("*"):
        if p.is_file():
            findings.extend(scan_file(p))
    return findings


def build_summary(findings):
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "tool": "CI/CD Security Scanner",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "by_severity": by_sev,
    }


def print_report(summary, findings):
    print("=" * 60)
    print("  CI/CD Security Scanner v1.0")
    print("=" * 60)
    print(f"[*] Total findings: {summary['total_findings']}")
    print(f"[*] Breakdown     : {summary['by_severity']}")
    print()
    for f in sorted(findings, key=lambda x: -x.risk_score)[:20]:
        print(f"[{f.severity}] {f.name}")
        print(f"   {f.file}:{f.line} (risk={f.risk_score}, {f.source})")
        print(f"   > {f.snippet}")
        print()


def main():
    ap = argparse.ArgumentParser(description="CI/CD Security Scanner")
    ap.add_argument("target")
    ap.add_argument("-o", "--output", default="reports/cicd_report.json")
    ap.add_argument("--html", default="reports/cicd_report.html")
    args = ap.parse_args()
    target = Path(args.target)
    if not target.exists():
        print(f"[x] Not found: {target}", file=sys.stderr); sys.exit(1)
    findings = scan_target(target)
    summary = build_summary(findings)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "findings": [asdict(f) for f in findings]}, fh, indent=2)
    generate_html(summary, findings, args.html)
    print_report(summary, findings)
    print(f"[*] JSON report: {args.output}")
    print(f"[*] HTML report: {args.html}")


if __name__ == "__main__":
    try:
        from license_guard import verify_license
        verify_license()
    except Exception:
        pass
    main()
