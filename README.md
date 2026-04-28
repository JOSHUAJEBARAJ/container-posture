# Container Security Auditor

A Claude Code plugin that audits **Dockerfiles** and **Kubernetes manifests** for security misconfigurations — no external tools required.

## What It Detects

### Dockerfile
| Check | Severity |
|---|---|
| Secrets in `ENV` / `ARG` / `COPY .env` | CRITICAL |
| Running as root (missing `USER`) | HIGH |
| `latest` or unpinned base image | MEDIUM |
| Docker socket declared as `VOLUME` | CRITICAL |
| `sudo` / `chmod 777` in `RUN` steps | HIGH |

### Kubernetes Pod Security
| Check | Severity |
|---|---|
| `privileged: true` | CRITICAL |
| `hostPID` / `hostNetwork` / `hostIPC` | CRITICAL / HIGH |
| `hostPath` volume mounts | CRITICAL / HIGH |
| Missing `securityContext` | HIGH |
| `runAsUser: 0` / missing `runAsNonRoot` | HIGH |
| Missing `allowPrivilegeEscalation: false` | HIGH |
| Missing resource limits (CPU / memory) | HIGH |
| Dangerous capabilities (`ALL`, `SYS_ADMIN`) | CRITICAL |
| Seccomp profile missing or `Unconfined` | HIGH |
| AppArmor profile missing or `Unconfined` | MEDIUM |
| `hostAliases` set | MEDIUM |
| `hostUsers` not set to `false` | MEDIUM |
| Secrets mounted as env vars | MEDIUM |
| Default service account / auto-mounted token | MEDIUM |
| `latest` image tag | MEDIUM |

### RBAC
| Check | Severity |
|---|---|
| `cluster-admin` bound to app service account | CRITICAL |
| Wildcard `*` verbs / resources | CRITICAL |
| `secrets` read access | HIGH |
| `pods/exec` or `pods/attach` access | HIGH |
| Role escalation (`bind` / `escalate` verbs) | CRITICAL |

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
  commands/
    container-audit.md                   # /container-audit slash command
  README.md
```

## Author

Built by [Joshua Jebaraj](https://github.com/JOSHUAJEBARAJ) as a Claude Code plugin for container security auditing.

## License

[Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)
