---
name: container-posture
description: "Audits Dockerfiles and Kubernetes manifests for security misconfigurations. Use when reviewing container images, pod specs, RBAC policies, or Kubernetes deployment files for vulnerabilities like privileged containers, exposed secrets, missing security contexts, and insecure RBAC."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Container Security Auditor

Systematically audit Dockerfiles and Kubernetes manifests for security misconfigurations that create exploitable attack surface in production.

## When to Use

- Reviewing a `Dockerfile` or `docker-compose.yml` before building an image
- Auditing Kubernetes manifests (`Deployment`, `Pod`, `ServiceAccount`, `ClusterRoleBinding`)
- Pre-deployment security checks on Helm charts or raw YAML
- Security reviews of CI/CD pipelines that build and deploy containers
- Any time a user mentions "k8s", "kubectl", "pod spec", "container image", or "Dockerfile"

## When NOT to Use

- Runtime cluster debugging (use `kubectl` directly instead)
- Scanning compiled container image layers (use Trivy/Grype for that)
- Application-level code security (use language-specific skills)
- Helm chart templating issues unrelated to security

## Rationalizations to Reject

- **"It's only used in development"** → Dev misconfigs reach prod when templates are copy-pasted. Flag it.
- **"We override it in the values file"** → Verify the override actually exists before downgrading severity.
- **"root is needed for this workload"** → Almost never true. Document why before accepting.
- **"We'll add resource limits later"** → Missing limits is a DoS vector today.

---

## Workflow

### Step 1: DISCOVER — Find target files

```bash
# Dockerfiles
find . -name "Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*"

# Kubernetes manifests
find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "kind:" 2>/dev/null

# Helm charts
find . -name "Chart.yaml"

# Docker Compose
find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml"
```

For each file found, determine its type and route to the appropriate checklist below.

### Step 2: AUDIT — Apply the relevant checklist

Route based on file type:
- `Dockerfile*` → [Dockerfile Checklist](references/dockerfile.md)
- `kind: Pod / Deployment / DaemonSet / StatefulSet` → [Pod Security Checklist](references/pod-security.md)
- `kind: ClusterRole / Role / ClusterRoleBinding / RoleBinding` → [RBAC Checklist](references/rbac.md)

### Step 3: VERIFY — Confirm each finding is real

For every candidate finding:
1. Is this in a test/example file? (`test/`, `example/`, `.sample`) → Skip
2. Is there a compensating control elsewhere? (e.g., PSP, OPA, admission controller) → Note it, lower severity
3. Is the risk reachable in production? → Confirm before reporting CRITICAL

### Step 4: REPORT — Structured findings

Use this format for every finding:

```
Finding: <short title>
Severity: CRITICAL | HIGH | MEDIUM | LOW
File: <path>:<line>
Issue: <what is wrong>
Risk: <what an attacker can do>
Fix: <concrete remediation>
```

---

## Severity Guide

| Severity | Examples |
|---|---|
| CRITICAL | `privileged: true`, root container with hostPath write, secrets in ENV, `cluster-admin` wildcard binding |
| HIGH | Missing `runAsNonRoot`, `hostPID/hostNetwork: true`, no resource limits on public-facing pods |
| MEDIUM | `latest` image tag, missing `readOnlyRootFilesystem`, image not pinned by digest |
| LOW | Missing `allowPrivilegeEscalation: false`, no liveness/readiness probe, verbose logging in prod |

---

## Reference Guides

- [Dockerfile Security Checklist](references/dockerfile.md)
- [Pod & Container Security Checklist](references/pod-security.md)
- [RBAC Misconfiguration Patterns](references/rbac.md)
