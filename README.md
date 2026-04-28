# Container Security Auditor

A Claude Code plugin that audits **Dockerfiles** and **Kubernetes manifests** for security misconfigurations — no external tools required.

## What It Detects

### Dockerfile
| Check | Severity |
|---|---|
| Secrets in `ENV` / `ARG` / `COPY .env` | CRITICAL |
| Running as root (missing `USER`) | HIGH |
| `latest` or unpinned base image | MEDIUM |
| `ADD` used instead of `COPY` | MEDIUM |
| Sensitive ports exposed (`22`, `2375`) | MEDIUM |
| Multi-stage build secret leakage | CRITICAL |

### Kubernetes Manifests
| Check | Severity |
|---|---|
| `privileged: true` | CRITICAL |
| `hostPID` / `hostNetwork` / `hostPath` | CRITICAL / HIGH |
| Missing `securityContext` | HIGH |
| `runAsUser: 0` | HIGH |
| Missing resource limits | HIGH |
| Secrets mounted as env vars | MEDIUM |
| `latest` image tag | MEDIUM |
| Dangerous capabilities (`ALL`, `SYS_ADMIN`) | CRITICAL |

### RBAC
| Check | Severity |
|---|---|
| `cluster-admin` bound to app service account | CRITICAL |
| Wildcard `*` verbs / resources | CRITICAL |
| `secrets` read access | HIGH |
| `pods/exec` or `pods/attach` access | HIGH |
| Role escalation permissions | CRITICAL |
| Default service account with token | MEDIUM |

### Network Policy
| Check | Severity |
|---|---|
| No `NetworkPolicy` in namespace | HIGH |
| Missing default-deny baseline | HIGH |
| Open egress (SSRF to metadata API) | CRITICAL |
| Unrestricted ingress (`namespaceSelector: {}`) | HIGH |

## Installation

### From a local clone
```
cd /path/to/parent-dir
/plugin marketplace add ./container-security-auditor
```

### Usage

The skill activates automatically when Claude detects Dockerfiles or Kubernetes YAML files in the conversation. You can also invoke it directly:

```
Audit the Kubernetes manifests in ./k8s/ for security issues
```

Or use the slash command:

```
/container-audit ./k8s/deployment.yaml
/container-audit ./deploy/
```

## Example Output

```
Finding: Privileged Container
Severity: CRITICAL
File: k8s/deployment.yaml:34
Issue: securityContext.privileged is set to true
Risk: Container has full access to host kernel — equivalent to root on the node.
      An attacker who compromises the app can escape to the host and pivot
      across the cluster.
Fix:  Remove privileged: true. If a capability is needed, add only the specific
      capability via securityContext.capabilities.add.

---

Finding: Root User in Dockerfile
Severity: HIGH
File: Dockerfile:12
Issue: No USER instruction — image runs as UID 0 (root)
Risk:  Process breakout from the container grants root on the host if combined
       with hostPath mounts or a privileged context.
Fix:   Add before CMD/ENTRYPOINT:
         RUN addgroup --system app && adduser --system --ingroup app app
         USER app
```

## How It Works

This plugin uses only Claude's built-in `Read`, `Grep`, and `Glob` tools — no external scanners, no network calls, no install dependencies. Claude reads the files directly and applies the checklists in the `references/` directory.

This means it works:
- Offline
- In any CI environment
- Without installing Trivy, kubeaudit, or any other tool

## Plugin Structure

```
container-security-auditor/
  .claude-plugin/
    plugin.json                          # Plugin metadata
  skills/
    container-security-auditor/
      SKILL.md                           # Skill entry point + workflow
      references/
        dockerfile.md                    # Dockerfile-specific checks
        pod-security.md                  # Pod/container securityContext checks
        rbac.md                          # RBAC misconfiguration patterns
        network-policy.md                # NetworkPolicy gap analysis
  commands/
    container-audit.md                   # /container-audit slash command
  README.md
```

## Author

Built by [Joshua Jebaraj](https://github.com/JOSHUAJEBARAJ) as a Claude Code plugin for container security auditing.

## License

[Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)
