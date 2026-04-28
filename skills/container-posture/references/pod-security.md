# Pod & Container Security Checklist

Apply to `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `Job`, and `CronJob` manifests.

## 1. Privileged Containers

**Check:** Is `securityContext.privileged` set to `true`?

```yaml
# CRITICAL — full host access, bypasses all namespace isolation
containers:
  - name: app
    securityContext:
      privileged: true

# GOOD
securityContext:
  privileged: false
```

Grep: `privileged: true`

Severity: CRITICAL — a privileged container can escape to the host node.

---

## 2. Missing securityContext

**Check:** Does the pod or container have no `securityContext` at all?

```yaml
# BAD — runs as root, can write anywhere, can escalate
containers:
  - name: app
    image: myapp:1.0

# GOOD — explicit, locked-down context
containers:
  - name: app
    image: myapp:1.0
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

Grep: look for `containers:` blocks lacking a `securityContext:` child.

Severity: HIGH

---

## 3. runAsRoot / runAsUser: 0

**Check:** Is the container explicitly or implicitly running as UID 0?

```yaml
# BAD
securityContext:
  runAsUser: 0

# BAD (implicit) — no runAsNonRoot: true and no runAsUser set
```

Grep patterns:
- `runAsUser: 0`
- Absence of `runAsNonRoot: true`

Severity: HIGH

---

## 4. allowPrivilegeEscalation

**Check:** Is `allowPrivilegeEscalation` missing or set to `true`?

```yaml
# BAD — setuid binaries can escalate to root
securityContext:
  allowPrivilegeEscalation: true

# GOOD
securityContext:
  allowPrivilegeEscalation: false
```

Grep: `allowPrivilegeEscalation: true`

Severity: HIGH

---

## 5. readOnlyRootFilesystem

**Check:** Is the root filesystem writable?

```yaml
# BAD (default) — attacker can write malware, modify configs
# No readOnlyRootFilesystem set

# GOOD
securityContext:
  readOnlyRootFilesystem: true
```

If the app needs writable paths, use `emptyDir` volume mounts for specific dirs only.

Severity: MEDIUM

---

## 6. Host Namespace Sharing

**Check:** Are host-level namespaces enabled?

```yaml
# CRITICAL — container sees all host processes
spec:
  hostPID: true

# CRITICAL — container shares host network stack
spec:
  hostNetwork: true

# HIGH — container sees all host IPC resources
spec:
  hostIPC: true
```

Grep: `hostPID: true`, `hostNetwork: true`, `hostIPC: true`

Severity: CRITICAL for `hostPID`/`hostNetwork`, HIGH for `hostIPC`

---

## 7. hostPath Volume Mounts

**Check:** Are host filesystem paths mounted into the container?

```yaml
# CRITICAL — write access to host filesystem
volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory

# HIGH — read access to sensitive host paths
volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock  # full Docker daemon access = root equivalent
```

Grep: `hostPath:`

Severity: CRITICAL for `/`, `/etc`, `/var/run/docker.sock`; HIGH for other paths.

---

## 8. Missing Resource Limits

**Check:** Are CPU and memory limits set?

```yaml
# BAD — unbounded resource consumption, DoS risk
containers:
  - name: app
    image: myapp:1.0

# GOOD
containers:
  - name: app
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "500m"
```

Grep: look for `containers:` blocks lacking a `resources.limits` child.

Severity: HIGH for public-facing workloads, MEDIUM otherwise.

---

## 9. Secrets as Environment Variables

**Check:** Are Kubernetes Secrets mounted as environment variables?

```yaml
# BAD — secret value appears in process environment, visible in /proc, logs
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-secret
        key: password

# BETTER — mount as file, harder to accidentally log
volumeMounts:
  - name: db-secret-vol
    mountPath: /run/secrets
    readOnly: true
volumes:
  - name: db-secret-vol
    secret:
      secretName: db-secret
```

Severity: MEDIUM — env vars leak into child processes and crash dumps.

---

## 10. Unpinned Image Tags

**Check:** Are container images using `latest` or no tag?

```yaml
# BAD
image: nginx:latest
image: myapp

# GOOD
image: nginx:1.25.3
image: myapp:v2.1.0@sha256:abc123...
```

Grep: `image:.*:latest`, `image: [^:]+$` (no tag at all)

Severity: MEDIUM

---

## 11. Capabilities

**Check:** Are dangerous Linux capabilities added?

```yaml
# CRITICAL — grants all capabilities, equivalent to root
securityContext:
  capabilities:
    add: ["ALL"]

# HIGH — specific dangerous capabilities
securityContext:
  capabilities:
    add: ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"]

# GOOD — drop all, add only what's needed
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

Grep: `add: \["ALL"\]`, `add:.*SYS_ADMIN`, `add:.*NET_ADMIN`

Severity: CRITICAL for `ALL`/`SYS_ADMIN`, HIGH for others.

---

## Quick Grep Summary

```bash
grep -n "privileged: true" manifest.yaml
grep -n "hostPID: true\|hostNetwork: true\|hostIPC: true" manifest.yaml
grep -n "hostPath:" manifest.yaml
grep -n "runAsUser: 0" manifest.yaml
grep -n "allowPrivilegeEscalation: true" manifest.yaml
grep -nE "image:.*:latest" manifest.yaml
grep -nE 'add: \["ALL"\]' manifest.yaml
grep -n "automountServiceAccountToken" manifest.yaml
grep -n "seccompProfile" manifest.yaml         # absence or Unconfined
grep -n "appArmorProfile" manifest.yaml        # absence or Unconfined
grep -n "hostAliases:" manifest.yaml
grep -n "hostUsers:" manifest.yaml             # absence of hostUsers: false
```

---

## 12. Default ServiceAccount Usage

**Check:** Is a dedicated `serviceAccountName` set on the pod, and is `automountServiceAccountToken` disabled when API access is not needed?

```yaml
# BAD — pod uses the namespace default SA, which may have accumulated permissions
spec:
  containers:
    - name: app
      image: myapp:1.0
  # no serviceAccountName set

# GOOD — dedicated SA scoped to only what the workload needs
spec:
  serviceAccountName: myapp-sa
  automountServiceAccountToken: false  # disable if the pod doesn't call the k8s API
```

The default ServiceAccount token is auto-mounted into every pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If the default SA has accumulated permissions, any compromised pod can use that token to interact with the API server.

Grep: absence of `serviceAccountName`, `automountServiceAccountToken: true` without justification

Severity: MEDIUM — escalates to HIGH if the default SA has been granted any RBAC permissions.

---

## 13. Seccomp Profile Missing or Unconfined

**Check:** Is a seccomp profile set, and is it something other than `Unconfined`?

```yaml
# BAD — no seccomp profile means all syscalls are permitted
spec:
  containers:
    - name: app
      image: myapp:1.0
      # no seccompProfile set

# BAD — explicitly disables seccomp filtering
securityContext:
  seccompProfile:
    type: Unconfined

# GOOD — restricts syscalls to the runtime default allowlist
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

Without a seccomp profile every syscall is available to the container. An attacker with code execution can invoke dangerous syscalls (`ptrace`, `mount`, `kexec_load`) to escalate privileges or escape the container.

Grep: absence of `seccompProfile`, `seccompProfile:.*Unconfined`

Severity: HIGH for missing/Unconfined on security-sensitive workloads.

---

## 14. AppArmor Profile Missing or Unconfined

**Check:** Is an AppArmor profile set, and is it something other than `Unconfined`?

```yaml
# BAD — no AppArmor profile, no mandatory access control on file/network operations
spec:
  containers:
    - name: app
      image: myapp:1.0
      # no appArmorProfile set

# BAD — explicitly disables AppArmor
securityContext:
  appArmorProfile:
    type: Unconfined

# GOOD — enforces the runtime default AppArmor profile
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

AppArmor restricts what files, capabilities, and network operations a container process can perform — even if it runs as root. Without it, a compromised container has no mandatory access control boundary beyond namespace isolation.

Grep: absence of `appArmorProfile`, `appArmorProfile:.*Unconfined`

Severity: MEDIUM

---

## 15. hostAliases Set

**Check:** Does the pod spec define `hostAliases`?

```yaml
# BAD — overrides /etc/hosts inside the pod; can redirect DNS resolution
spec:
  hostAliases:
    - ip: "1.2.3.4"
      hostnames:
        - "legit-service.internal"
```

`hostAliases` injects entries into the pod's `/etc/hosts`, allowing a misconfigured or malicious manifest to redirect internal hostnames to attacker-controlled IPs. In a shared cluster this is a lateral movement enabler.

Grep: `hostAliases:`

Severity: MEDIUM — review every occurrence; flag if the redirected hostname is a sensitive internal service.

---

## 16. hostUsers Not Set to False

**Check:** Is `hostUsers: false` set to enable user namespace isolation?

```yaml
# BAD (default) — pod shares the host user namespace; root in the container is
# root on the host node if other controls fail
spec:
  hostUsers: true   # or field absent, which defaults to true

# GOOD — Kubernetes creates a separate user namespace; UID 0 inside the container
# maps to an unprivileged UID on the host
spec:
  hostUsers: false
```

User namespace isolation means that even if an attacker escapes the container and runs as UID 0, that UID maps to an unprivileged user on the host, dramatically reducing the blast radius of a container escape.

Grep: absence of `hostUsers: false`

Note: `hostUsers` requires Kubernetes ≥ 1.25 and a compatible container runtime. Verify cluster support before flagging as mandatory.

Severity: MEDIUM
