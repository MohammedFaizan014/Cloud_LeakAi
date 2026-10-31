"""Deterministic infrastructure scanner.

Static, rule-based analysis of uploaded configuration files and logs.
The scanner NEVER executes uploaded content - it only reads it as text.
All financial figures are marked illustrative; no live cloud pricing is used.
"""
from __future__ import annotations

import re

# Rough typical on-demand rates used ONLY for clearly-labelled illustrative
# estimates. Never presented as a live price.
ILLUSTRATIVE = {
    "vcpu_hour": 0.048,       # ~$35/vCPU-month
    "gb_ram_hour": 0.0063,    # ~$4.6/GB-month
    "gb_storage_month": 0.10,
    "log_gb_month": 0.50,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def _find_lines(content: str, pattern: str) -> list[tuple[int, str]]:
    out = []
    flags = re.IGNORECASE
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(pattern, line, flags):
            out.append((i, line.strip()))
    return out


def _block_values(content: str, key: str) -> list[tuple[int, str]]:
    """Return (line, value) for simple `key: value` / `key = value` occurrences."""
    out = []
    for i, line in enumerate(content.splitlines(), start=1):
        m = re.match(rf"\s*#?\s*{re.escape(key)}\s*[:=]\s*(.+?)\s*$", line, re.IGNORECASE)
        if m and not line.strip().startswith("#"):
            out.append((i, m.group(1).strip().strip("'\"")))
    return out


def make_finding(**kw) -> dict:
    f = {
        "category": kw.get("category", "waste"),
        "severity": kw["severity"],
        "title": kw["title"],
        "description": kw["description"],
        "evidence_file": kw.get("evidence_file"),
        "evidence_line": kw.get("evidence_line"),
        "evidence_snippet": kw.get("evidence_snippet"),
        "recommendation": kw["recommendation"],
        "estimated_monthly_waste": kw.get("monthly_waste"),
        "waste_illustrative": 1 if kw.get("monthly_waste") is not None else 0,
        "confidence": kw.get("confidence", 0.7),
        "proposed_fix": kw.get("proposed_fix"),
        "fix_target_line": kw.get("fix_target_line", kw.get("evidence_line")),
        "root_cause": kw.get("root_cause", ""),
    }
    return f


# ---------------------------------------------------------------- rule sets

def scan_docker_compose(filename: str, content: str) -> list[dict]:
    findings = []
    # Privileged containers
    for line, _ in _find_lines(content, r"privileged\s*:\s*true"):
        findings.append(make_finding(
            category="security", severity="critical",
            title="Container running in privileged mode",
            description="A service is granted privileged mode, giving it nearly full host access. A compromised container can escalate to the host.",
            evidence_file=filename, evidence_line=line,
            evidence_snippet="privileged: true",
            recommendation="Remove privileged: true. Grant only the specific capabilities the service needs via cap_add.",
            confidence=0.98, root_cause="Over-broad container capabilities",
            proposed_fix="    privileged: false  # or remove the key; add only needed cap_add entries",
            fix_target_line=line))
    # Hardcoded credentials
    for line, val in _find_lines(content, r"(?i)(password|secret|token|api_key|apikey)\s*[:=]\s*\S+"):
        if re.search(r"(?i)\$\{|\{\{|\bexample\b|changeme", val):
            continue
        findings.append(make_finding(
            category="security", severity="critical",
            title="Hardcoded credential in compose file",
            description="A plaintext credential is committed in the compose file. Anyone with repository access obtains production credentials.",
            evidence_file=filename, evidence_line=line, evidence_snippet=val[:60],
            recommendation="Move the secret to an environment variable interpolated from the host or a secrets manager (docker secrets / vault).",
            confidence=0.9, root_cause="Secrets stored in version control",
            proposed_fix=f"    - substitute with ${{SECRET_VAR}} injected at deploy time (was: {val[:40]})",
            fix_target_line=line))
    # Missing memory/cpu limits
    if not re.search(r"(?i)mem_limit|deploy\s*:|cpus\s*:", content):
        findings.append(make_finding(
            category="waste", severity="high",
            title="No CPU or memory limits on containers",
            description="Containers without resource limits can consume unbounded host memory, forcing oversizing of the whole node.",
            evidence_file=filename, evidence_line=1,
            evidence_snippet="(no mem_limit / deploy.resources.limits found)",
            recommendation="Add deploy.resources.limits with realistic memory and CPU values per service, then size instances from measured usage.",
            confidence=0.85, root_cause="Unbounded container resources",
            monthly_waste=120.0,  # illustrative
            proposed_fix="    deploy:\n      resources:\n        limits:\n          memory: 512M\n          cpus: '0.5'"))
    # Excessive replicas
    for line, val in _block_values(content, "replicas"):
        try:
            n = int(val)
        except ValueError:
            continue
        if n > 3:
            findings.append(make_finding(
                category="waste", severity="medium",
                title=f"High replica count ({n}) declared statically",
                description=f"The compose file pins {n} replicas. Static over-provisioning pays for idle capacity around the clock.",
                evidence_file=filename, evidence_line=line, evidence_snippet=f"replicas: {n}",
                recommendation="Reduce to 2 replicas or use autoscaling driven by measured load.",
                confidence=0.7, root_cause="Static over-provisioning",
                monthly_waste=round((n - 2) * 25.0, 2),
                proposed_fix="    replicas: 2  # or remove static count and use an autoscaler"))
    # latest tags
    for line, val in _find_lines(content, r"image\s*:\s*\S+:(latest|$)")[:3]:
        findings.append(make_finding(
            category="reliability", severity="medium",
            title="Container image uses floating 'latest' tag",
            description="Pinning to :latest makes deployments non-reproducible; rollbacks and audits lose track of what actually ran.",
            evidence_file=filename, evidence_line=line, evidence_snippet="image: ...:latest",
            recommendation="Pin images to an immutable version or digest tag.",
            confidence=0.9, root_cause="Unpinned dependency versions",
            proposed_fix="    image: <image>:<pinned-version>"))
    # Public port binding
    for line, val in _find_lines(content, r"ports\s*:"):
        block = content.splitlines()
        for j in range(line, min(line + 4, len(block))):
            m = re.match(r"\s*-?\s*\"?(\d+):(\d+)\"?", block[j])
            if m:
                findings.append(make_finding(
                    category="security", severity="high",
                    title="Service port published on all host interfaces",
                    description="Publishing ports binds 0.0.0.0 by default, exposing internal services (e.g. databases) to the network.",
                    evidence_file=filename, evidence_line=j + 1, evidence_snippet=block[j].strip(),
                    recommendation="Bind to 127.0.0.1 for internal services or restrict ingress with a firewall / security group.",
                    confidence=0.85, root_cause="Over-exposed service networking",
                    proposed_fix=f"    - 127.0.0.1:{m.group(1)}:{m.group(2)}"))
                break
    return findings


def scan_dockerfile(filename: str, content: str) -> list[dict]:
    findings = []
    for line, _ in _find_lines(content, r"^FROM\s+\S+:(latest|\$)")[:2]:
        findings.append(make_finding(
            category="reliability", severity="medium",
            title="Base image not version-pinned",
            description="FROM ...:latest produces non-reproducible builds and unpredictable behaviour between builds.",
            evidence_file=filename, evidence_line=line, evidence_snippet="FROM ...:latest",
            recommendation="Pin the base image to a specific version tag (and ideally a digest).",
            confidence=0.9, root_cause="Unpinned base image",
            proposed_fix="FROM node:20.11-alpine  # pinned version"))
    if not re.search(r"(?mi)^\s*USER\s+\S+", content):
        findings.append(make_finding(
            category="security", severity="high",
            title="Container runs as root",
            description="No USER directive means the process runs as root inside the container; any exploit gains root privileges.",
            evidence_file=filename, evidence_line=1,
            evidence_snippet="(no USER directive found)",
            recommendation="Create and switch to a dedicated non-root user before the entrypoint.",
            confidence=0.9, root_cause="Missing non-root user",
            proposed_fix="RUN addgroup -S app && adduser -S app -G app\nUSER app"))
    if not re.search(r"(?mi)^\s*HEALTHCHECK", content):
        findings.append(make_finding(
            category="reliability", severity="low",
            title="No container healthcheck defined",
            description="Without a HEALTHCHECK the orchestrator cannot detect and replace wedged containers automatically.",
            evidence_file=filename, evidence_line=1, evidence_snippet="(no HEALTHCHECK found)",
            recommendation="Add a HEALTHCHECK hitting a lightweight readiness endpoint.",
            confidence=0.8, root_cause="Missing liveness probing"))
    for line, _ in _find_lines(content, r"(?i)COPY\s+\S*\.env"):
        findings.append(make_finding(
            category="security", severity="critical",
            title="Environment/secret file baked into image",
            description="Copying .env files into the image embeds credentials in every layer; anyone who pulls the image can extract them.",
            evidence_file=filename, evidence_line=line, evidence_snippet="COPY ... .env*",
            recommendation="Remove .env from the image; inject configuration at runtime and add .env to .dockerignore.",
            confidence=0.95, root_cause="Secrets in image layers",
            proposed_fix="# remove this COPY; inject env at runtime\n# .dockerignore: .env*"))
    return findings


def scan_kubernetes(filename: str, content: str) -> list[dict]:
    findings = []
    for line, val in _block_values(content, "replicas"):
        try:
            n = int(val)
        except ValueError:
            continue
        if n > 5:
            findings.append(make_finding(
                category="waste", severity="medium",
                title=f"Static replica count of {n} without autoscaling",
                description=f"The deployment requests {n} replicas at all times. If utilisation is low, most of that compute is idle spend.",
                evidence_file=filename, evidence_line=line, evidence_snippet=f"replicas: {n}",
                recommendation="Right-size to measured load and add an HPA instead of a fixed high replica count.",
                confidence=0.7, root_cause="Static over-provisioning",
                monthly_waste=round((n - 3) * 30.0, 2),
                proposed_fix="  replicas: 3\n---\napiVersion: autoscaling/v2  # HPA from 3 to max on CPU/memory"))
    if not re.search(r"(?i)resources\s*:\s*\n?\s*(limits|requests)", content):
        findings.append(make_finding(
            category="waste", severity="high",
            title="Containers without resource requests/limits",
            description="Pods without requests/limits are scheduled unbounded, cause node over-provisioning and risk noisy-neighbour eviction storms.",
            evidence_file=filename, evidence_line=1,
            evidence_snippet="(no resources.limits/requests found)",
            recommendation="Set requests from measured p50 usage and limits from p99, then review monthly.",
            confidence=0.85, root_cause="Unbounded pod resources",
            monthly_waste=90.0,
            proposed_fix("limits") if False else "        resources:\n          requests:\n            cpu: 100m\n            memory: 128Mi\n          limits:\n            cpu: 500m\n            memory: 512Mi"))
    for line, _ in _find_lines(content, r"(?i)privileged\s*:\s*true"):
        findings.append(make_finding(
            category="security", severity="critical",
            title="Privileged pod container",
            description="privileged: true in a securityContext gives the container full host kernel access - a common container-escape vector.",
            evidence_file=filename, evidence_line=line, evidence_snippet="privileged: true",
            recommendation="Set privileged: false and add only required capabilities.",
            confidence=0.98, root_cause="Over-broad pod security context",
            proposed_fix="            privileged: false"))
    for line, _ in _find_lines(content, r"(?i)runAsUser\s*:\s*0\b"):
        findings.append(make_finding(
            category="security", severity="high",
            title="Pod runs as root (runAsUser: 0)",
            description="Running the container process as UID 0 breaks container isolation assumptions and widens blast radius.",
            evidence_file=filename, evidence_line=line, evidence_snippet="runAsUser: 0",
            recommendation="Set runAsUser to a non-root UID (e.g. 10001) and enable runAsNonRoot.",
            confidence=0.95, root_cause="Root workload identity",
            proposed_fix="          runAsNonRoot: true\n          runAsUser: 10001"))
    for line, _ in _find_lines(content, r"(?i)type\s*:\s*LoadBalancer"):
        findings.append(make_finding(
            category="waste", severity="low",
            title="LoadBalancer service provisioned per service",
            description="Each LoadBalancer service provisions a cloud load balancer with a fixed monthly cost. Multiple services multiply that cost.",
            evidence_file=filename, evidence_line=line, evidence_snippet="type: LoadBalancer",
            recommendation="Share a single ingress controller (or Gateway API) across services instead of one LB per service.",
            confidence=0.65, root_cause="Per-service load balancers",
            monthly_waste=18.0,
            proposed_fix="  type: ClusterIP  # expose via the shared ingress"))
    return findings


def scan_terraform(filename: str, content: str) -> list[dict]:
    findings = []
    for line, itype in _find_lines(content, r"instance_type\s*=\s*\"([a-z0-9.]+)\""):
        m = re.search(r"(?<== )\"([a-z0-9.\-]+)\"", itype)
        if not m:
            continue
        name = m.group(1)
        fam = re.match(r"([a-z]\d+)\.(\d+)xl", name)
        if fam and int(fam.group(2)) >= 4:
            findings.append(make_finding(
                category="waste", severity="high",
                title=f"Potentially oversized instance ({name})",
                description=f"A {fam.group(2)}x-large instance ({name}) is provisioned. Without utilisation data this size is often inherited rather than measured.",
                evidence_file=filename, evidence_line=line, evidence_snippet=f'instance_type = "{name}"',
                recommendation="Check CPU/memory utilisation for 2-4 weeks; downsize to the smallest size whose p99 fits. Marked illustrative - no live pricing.",
                confidence=0.6, root_cause="Inherited instance sizing",
                monthly_waste=round(int(fam.group(2)) * 70.0, 2)))
    for line, _ in _find_lines(content, r"(?i)encrypted\s*=\s*false"):
        findings.append(make_finding(
            category="security", severity="high",
            title="Storage volume without encryption",
            description="encrypted = false stores data at rest unencrypted, failing most compliance baselines.",
            evidence_file=filename, evidence_line=line, evidence_snippet="encrypted = false",
            recommendation="Enable encryption (encrypted = true with a customer-managed KMS key).",
            confidence=0.95, root_cause="Disabled at-rest encryption",
            proposed_fix="  encrypted = true\n  kms_key_id = var.kms_key_arn"))
    for line, _ in _find_lines(content, r"(?i)cidr_blocks\s*=\s*\"0\.0\.0\.0/0\""):
        findings.append(make_finding(
            category="security", severity="critical",
            title="Security group open to the internet (0.0.0.0/0)",
            description="An ingress rule allows any source IP. Databases or admin ports exposed this way are actively scanned within hours.",
            evidence_file=filename, evidence_line=line, evidence_snippet='cidr_blocks = "0.0.0.0/0"',
            recommendation="Restrict cidr_blocks to known source ranges; use a bastion/SSM Session Manager for administrative access.",
            confidence=0.9, root_cause="Unrestricted ingress",
            proposed_fix='  cidr_blocks = ["10.0.0.0/8"]  # or your office/VPN CIDR'))
    for line, m in [(l, re.search(r"size\s*=\s*(\d+)", c)) for l, c in _find_lines(content, r"(?i)ebs_|volume|size\s*=\s*\d{3,}")]:
        if not m:
            continue
        gb = int(m.group(1))
        if gb >= 500:
            findings.append(make_finding(
                category="waste", severity="medium",
                title=f"Large storage allocation ({gb} GB)",
                description=f"A {gb} GB volume is allocated. Storage is billed on allocated size, so unused capacity is pure waste.",
                evidence_file=filename, evidence_line=line, evidence_snippet=f"size = {gb}",
                recommendation="Verify actual used space and right-size; consider gp3 with baseline performance instead of gp2.",
                confidence=0.6, root_cause="Allocated-but-unused storage",
                monthly_waste=round((gb - 100) * ILLUSTRATIVE["gb_storage_month"], 2)))
    return findings


def scan_cloudformation(filename: str, content: str) -> list[dict]:
    findings = []
    for line, _ in _find_lines(content, r"(?i)0\.0\.0\.0/0"):
        findings.append(make_finding(
            category="security", severity="critical",
            title="Security group ingress open to 0.0.0.0/0",
            description="A CloudFormation ingress rule permits every source address.",
            evidence_file=filename, evidence_line=line, evidence_snippet="0.0.0.0/0",
            recommendation="Restrict to required CIDR ranges.",
            confidence=0.9, root_cause="Unrestricted ingress",
            proposed_fix='          CidrIp: 10.0.0.0/8'))
    return findings


def scan_nginx(filename: str, content: str) -> list[dict]:
    findings = []
    if not re.search(r"(?i)listen\s+.*443|ssl_certificate", content):
        findings.append(make_finding(
            category="security", severity="high",
            title="No HTTPS listener configured",
            description="The nginx config serves plain HTTP only; traffic (including credentials) travels unencrypted.",
            evidence_file=filename, evidence_line=1, evidence_snippet="(no 443/ssl_certificate found)",
            recommendation="Terminate TLS with a certificate (Let's Encrypt/ACM) and redirect HTTP to HTTPS.",
            confidence=0.85, root_cause="Missing TLS termination"))
    for line, _ in _find_lines(content, r"(?i)server_tokens\s+on"):
        findings.append(make_finding(
            category="security", severity="low",
            title="Server version disclosed (server_tokens on)",
            description="nginx advertises its exact version in headers and error pages, helping attackers target known CVEs.",
            evidence_file=filename, evidence_line=line, evidence_snippet="server_tokens on;",
            recommendation="Set server_tokens off.",
            confidence=0.95, root_cause="Information disclosure",
            proposed_fix="server_tokens off;"))
    if not re.search(r"(?i)gzip\s+on", content):
        findings.append(make_finding(
            category="efficiency", severity="low",
            title="Response compression disabled",
            description="Without gzip/brotli, text responses transfer at full size, increasing egress and page latency.",
            evidence_file=filename, evidence_line=1, evidence_snippet="(no gzip on found)",
            recommendation="Enable gzip with sensible types and levels (e.g. gzip_comp_level 5).",
            confidence=0.8, root_cause="Missing compression",
            proposed_fix="gzip on;\ngzip_types text/plain text/css application/json;\ngzip_comp_level 5;"))
    return findings


def scan_dbconfig(filename: str, content: str) -> list[dict]:
    findings = []
    for key, limit, msg in [
        ("max_connections", 200, "max_connections is set very high; each connection costs memory and can hide pool misconfiguration."),
        ("pool_max", 100, "Application pool_max is very large relative to typical needs."),
    ]:
        for line, val in _block_values(content, key):
            try:
                n = int(val)
            except ValueError:
                continue
            if n > limit:
                findings.append(make_finding(
                    category="efficiency", severity="medium",
                    title=f"Oversized {key} ({n})",
                    description=msg,
                    evidence_file=filename, evidence_line=line, evidence_snippet=f"{key} = {val}",
                    recommendation="Right-size the pool to (cores * 2 + effective_spindles) guidance and add pooling (pgbouncer / proxy) if needed.",
                    confidence=0.7, root_cause="Oversized connection pools",
                    proposed_fix=f"{key} = {limit // 2}"))
    if re.search(r"(?i)slow_query_log\s*=\s*(0|off|false)", content):
        findings.append(make_finding(
            category="efficiency", severity="low",
            title="Slow query log disabled",
            description="Without the slow query log, expensive queries stay invisible and force over-provisioning.",
            evidence_file=filename, evidence_line=_find_lines(content, r"(?i)slow_query_log\s*=\s*(0|off|false)")[0][0],
            evidence_snippet="slow_query_log = OFF",
            recommendation="Enable slow_query_log with long_query_time ~ 0.5s in production diagnostics.",
            confidence=0.85, root_cause="Missing query observability",
            proposed_fix="slow_query_log = ON\nlong_query_time = 0.5"))
    return findings


def scan_logs(filename: str, content: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    debug = sum(1 for l in lines if re.search(r"\bDEBUG\b", l))
    if len(lines) >= 20 and debug / max(len(lines), 1) > 0.3:
        findings.append(make_finding(
            category="waste", severity="medium",
            title="Verbose DEBUG logging in production logs",
            description=f"{debug} of {len(lines)} log lines are DEBUG level. High-volume debug logging inflates log ingestion and storage cost.",
            evidence_file=filename, evidence_line=next((i for i, l in enumerate(lines, 1) if "DEBUG" in l), 1),
            evidence_snippet=next((l.strip()[:80] for l in lines if "DEBUG" in l), "DEBUG ..."),
            recommendation="Set production log level to INFO; keep DEBUG behind a runtime flag.",
            confidence=0.75, root_cause="Excessive log verbosity",
            monthly_waste=round(debug * ILLUSTRATIVE["log_gb_month"] * 0.02, 2),
            proposed_fix="log_level=INFO  # DEBUG only behind a runtime flag"))
    # Retry storms
    retries = sum(1 for l in lines if re.search(r"(?i)retry|attempt \d+", l))
    if retries >= 5:
        findings.append(make_finding(
            category="waste", severity="medium",
            title=f"Frequent client retries detected ({retries} log events)",
            description="Repeated retry events suggest aggressive retry policy, which multiplies request volume (and API call cost) against a struggling endpoint.",
            evidence_file=filename, evidence_line=next((i for i, l in enumerate(lines, 1) if re.search(r"(?i)retry", l)), 1),
            evidence_snippet=next((l.strip()[:80] for l in lines if re.search(r"(?i)retry", l)), "retry ..."),
            recommendation="Use exponential backoff with jitter and a circuit breaker; cap retries at 3.",
            confidence=0.7, root_cause="Aggressive retry policy"))
    # Tight polling
    polls = [l for l in lines if re.search(r"(?i)poll", l)]
    if len(polls) >= 5:
        findings.append(make_finding(
            category="waste", severity="low",
            title="High-frequency polling observed",
            description=f"{len(polls)} polling events in the supplied log window. Tight polling burns API quota and compute for data that changes slowly.",
            evidence_file=filename, evidence_line=next((i for i, l in enumerate(lines, 1) if re.search(r"(?i)poll", l)), 1),
            evidence_snippet=polls[0].strip()[:80],
            recommendation="Increase poll interval or switch to webhooks/event-driven updates.",
            confidence=0.6, root_cause="Polling instead of events"))
    return findings


def scan_generic_env(filename: str, content: str) -> list[dict]:
    findings = []
    for line, _ in _find_lines(content, r"(?i)^(?!#).*(password|secret|token|private_key)\s*=\s*\S+"):
        val = content.splitlines()[line - 1]
        if re.search(r"(?i)\$\{|example|changeme|xxx", val):
            continue
        findings.append(make_finding(
            category="security", severity="critical",
            title="Plaintext secret in configuration file",
            description="A secret-looking value is stored in plaintext in a config/template file.",
            evidence_file=filename, evidence_line=line, evidence_snippet=val.strip()[:60],
            recommendation="Store in a secrets manager and inject at runtime; never commit real secrets.",
            confidence=0.85, root_cause="Secrets in plaintext config",
            proposed_fix="# value injected from secrets manager at deploy time"))
    return findings


def scan_file(filename: str, content: str) -> list[dict]:
    name = filename.lower()
    if name.endswith((".yml", ".yaml")) and ("compose" in name or "docker-compose" in content[:2000]):
        return scan_docker_compose(filename, content)
    if "dockerfile" in name:
        return scan_dockerfile(filename, content)
    if name.endswith((".yml", ".yaml")) and ("k8s" in name or "deployment" in name or "kind:" in content):
        return scan_kubernetes(filename, content)
    if name.endswith(".tf") or "terraform" in name:
        return scan_terraform(filename, content)
    if "cloudformation" in name or name.endswith(".json") and "AWSTemplateFormatVersion" in content:
        return scan_cloudformation(filename, content)
    if "nginx" in name or name.endswith(".conf"):
        if "nginx" in content.lower() or "server {" in content:
            return scan_nginx(filename, content)
        return scan_generic_env(filename, content)
    if name.endswith((".cnf", ".ini")) or "database" in name or "db" in name:
        return scan_dbconfig(filename, content)
    if name.endswith(".log") or "log" in name:
        return scan_logs(filename, content)
    if name.endswith((".env", ".env.example", ".properties", ".cfg")) or "env" in name:
        return scan_generic_env(filename, content)
    # Fallback: try generic + k8s
    return scan_generic_env(filename, content) + scan_kubernetes(filename, content)


def run_scan(files: list[dict]) -> list[dict]:
    """files: [{id, filename, content}] -> list of finding dicts (with file_id)."""
    out = []
    for f in files:
        for finding in scan_file(f["filename"], f["content"]):
            finding["file_id"] = f.get("id")
            out.append(finding)
    return out


def build_remediation(finding: dict) -> dict | None:
    """Derive a structured remediation plan from a deterministic finding."""
    fix = finding.get("proposed_fix")
    severity = finding["severity"]
    level = "SAFE" if severity in ("low", "informational") else ("REVIEW_REQUIRED" if severity == "medium" else "HIGH_RISK")
    snippet = finding.get("evidence_snippet") or ""
    original = None
    if finding.get("evidence_line") and snippet:
        original = f"# {finding['evidence_file']}:{finding['evidence_line']}\n{snippet}"
    if severity == "critical":
        complexity = "high"
        side_effects = "Can affect production availability; verify in staging, apply during a maintenance window, and watch rollout metrics closely."
        rollback = "Revert to the original configuration snippet below and redeploy the previous version; keep a staged backup of the file."
    elif severity == "high":
        complexity = "medium"
        side_effects = "May require service restart or redeploy; brief connection drops possible during rollout."
        rollback = "Restore the original file from version control and redeploy."
    else:
        complexity = "low"
        side_effects = "Minimal; expected to be a configuration-only change with no downtime."
        rollback = "Revert the configuration change; no downtime expected."
    return {
        "action_level": level,
        "root_cause": finding.get("root_cause") or "Configuration as supplied",
        "recommended_action": finding["recommendation"],
        "original_config": original,
        "proposed_config": fix,
        "expected_monthly_savings": finding.get("estimated_monthly_waste"),
        "security_improvement": (
            f"Reduces {severity}-severity exposure: {finding['title']}" if finding["category"] == "security"
            else "Indirect: smaller footprint reduces attack surface and patching scope."),
        "complexity": complexity,
        "side_effects": side_effects,
        "rollback_instructions": rollback,
        "confidence": finding.get("confidence", 0.7),
        "source": "deterministic",
    }
