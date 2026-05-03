# container-posture

A Claude Code plugin that audits **Dockerfiles** and **Kubernetes manifests** for security misconfigurations — privileged pods, root containers, hardcoded secrets, over-permissive RBAC, and more.

No external scanners. No network calls. No install dependencies. Just Claude reading your files.

---

## Install

Requires a recent version of Claude Code. If you see `This plugin uses a source type your Claude Code version does not support`, run `claude update` first.

**1. Add the marketplace:**

```
/plugin marketplace add JOSHUAJEBARAJ/container-posture
```

**2. Install the plugin:**

```
/plugin install container-posture@container-posture
```

**3. Verify:** run `/plugin` — `container-posture` should appear as installed and the `/container-posture` skill should be available.

### Local install (for development)

From the **parent directory** of this repo:

```
/plugin marketplace add ./container-posture
/plugin install container-posture@container-posture
```

---

## Use

Invoke the skill directly:

```
/container-posture ./k8s/deployment.yaml     # one file
/container-posture ./deploy/                 # a directory
/container-posture .                         # current working directory
```

Or just describe what you want — the skill activates automatically when Claude detects Dockerfiles or Kubernetes YAML in conversation:

```
Check the security posture of the Kubernetes manifests in ./k8s/
Audit this Dockerfile for security issues
```

### Example output

```
Finding: Privileged Container
Severity: CRITICAL
File: k8s/deployment.yaml:34
Issue: securityContext.privileged is set to true
Risk: Container has full host kernel access — equivalent to root on the node.
      An attacker who compromises the app can escape to the host and pivot
      across the cluster.
Fix:  Remove privileged: true. Grant only the specific capability needed.

Finding: Missing Seccomp Profile
Severity: HIGH
File: k8s/deployment.yaml
Issue: No seccompProfile defined — all syscalls permitted
Fix:  Add to securityContext:
        seccompProfile:
          type: RuntimeDefault

Finding: Root User in Dockerfile
Severity: HIGH
File: Dockerfile:12
Issue: No USER instruction — image runs as UID 0 (root)
Fix:  Add before CMD/ENTRYPOINT:
        RUN groupadd -r appuser && useradd -r -g appuser appuser
        USER appuser
```

### Try it on the demo samples

The `demo/samples/` directory ships with intentionally vulnerable files you can point the plugin at:

```
cd demo/samples
claude
/container-posture .
```

---

## How it works

The plugin uses only Claude's built-in `Read`, `Grep`, and `Glob` tools. Claude reads your files directly and applies the checklists in the `references/` directory. That means:

- Works offline.
- Runs in any CI environment that has Claude Code.
- No Trivy, no kubeaudit, no daemons to install or update.

---

## What it detects

### Dockerfile

| Check | Severity |
|---|---|
| Secrets in `ENV` / `ARG` / `COPY .env` | CRITICAL |
| Running as root (missing `USER`) | HIGH |
| `latest` or unpinned base image | MEDIUM |
| Docker socket declared as `VOLUME` | CRITICAL |
| `sudo` / `chmod 777` in `RUN` steps | HIGH |

### Kubernetes pod security

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

---

## Plugin structure

```
container-posture/                # Repo root (the marketplace)
  .claude-plugin/
    marketplace.json              # Marketplace descriptor
  plugins/
    container-posture/            # The plugin itself
      .claude-plugin/
        plugin.json               # Plugin metadata
      skills/
        container-posture/
          SKILL.md                # Skill entry point + workflow
          references/
            dockerfile.md         # Dockerfile-specific checks
            pod-security.md       # Pod/container securityContext checks
            rbac.md               # RBAC misconfiguration patterns
  demo/
    samples/                      # Vulnerable Dockerfile + manifests for demos
  README.md
```

## References

The checks in this plugin are sourced from:

- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) — Dockerfile rules
- [kubesec](https://github.com/controlplaneio/kubesec) — Kubernetes manifest scoring rules (seccomp, AppArmor, hostAliases, hostUsers, capabilities)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — privileged, hostPID, hostNetwork, securityContext baselines
- [RBAC Best Practices — Kubernetes Docs](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) — least-privilege RBAC patterns

## Author

Built by [Joshua Jebaraj](https://github.com/JOSHUAJEBARAJ) as a Claude Code plugin for container security posture review.

## License

[Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)
