# Dockerfile Security Checklist

Apply these checks to every `Dockerfile` found during discovery. Flag only security issues — skip performance or style observations.

Source: [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

## 1. Unpinned Base Image

**Check:** Is the base image using `latest` or missing a version tag entirely?

```dockerfile
# BAD — silently pulls new (potentially vulnerable) layers on every build
FROM ubuntu:latest
FROM node:latest

# BETTER — version tag (still mutable, but intentional)
FROM node:20-alpine

# BEST — immutable, digest-pinned; cannot be tampered with
FROM node:20-alpine@sha256:abc123...
```

An unpinned image means a supply-chain compromise of the upstream image silently reaches your production container.

Grep: `^FROM .*:latest`, `^FROM [^:@\s]+\s*$` (no tag at all)

Severity: MEDIUM

---

## 2. Running as Root (Missing USER Instruction)

**Check:** Is there a `USER` instruction before `CMD`/`ENTRYPOINT`? Absence means UID 0 (root).

```dockerfile
# BAD — no USER = root
FROM ubuntu:22.04
RUN apt-get install -y curl
CMD ["curl"]

# GOOD — create a dedicated non-root user and switch to it
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
```

Running as root means any process breakout gives the attacker full host access when combined with hostPath mounts or a privileged context.

Grep: absence of `^USER` in the file, or `^USER root`, `^USER 0`

Severity: HIGH (CRITICAL if combined with `hostPath` or `privileged: true`)

---

## 3. Secrets Baked into Image Layers

**Check:** Are secrets stored in `ENV`, `ARG`, or copied via `COPY`/`ADD`? Every layer is permanently stored and readable via `docker history`.

```dockerfile
# CRITICAL — visible to anyone with image access
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ARG DB_PASSWORD=supersecret
RUN curl -H "Authorization: Bearer hardcoded-token" https://api.example.com

# BAD — .env file embedded in the image
COPY .env /app/.env

# GOOD — use Docker Secrets (swarm) or BuildKit secret mounts
RUN --mount=type=secret,id=db_password \
    DB_PASSWORD=$(cat /run/secrets/db_password) ./configure.sh
```

Even if the `ENV` is overridden at runtime, the value is permanently recorded in the image layer history.

Grep:
- `ENV.*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)`
- `ARG.*(PASSWORD|SECRET|TOKEN|KEY)`
- `COPY.*\.env`

Severity: CRITICAL

---

## 4. Docker Socket Exposed Inside the Container

**Check:** Is `/var/run/docker.sock` mounted into the container from the Dockerfile or referenced in a `VOLUME` instruction?

```dockerfile
# BAD — mounting the Docker socket gives the container full root control of the host
VOLUME /var/run/docker.sock
```

Also flag in `docker-compose.yml`:
```yaml
volumes:
  - "/var/run/docker.sock:/var/run/docker.sock"
```

Access to the Docker socket is equivalent to unrestricted root on the host. An attacker inside the container can create a privileged container that mounts the host filesystem.

Grep: `docker.sock`

Severity: CRITICAL

---

## 5. ADD Used Instead of COPY (Remote URL Fetch)

**Check:** Is `ADD` used with a remote URL or in contexts where `COPY` would suffice?

```dockerfile
# BAD — ADD silently fetches and decompresses remote content; no integrity check
ADD https://example.com/install.sh /tmp/install.sh
RUN sh /tmp/install.sh

# GOOD — fetch explicitly with checksum verification, then COPY
# Or use COPY for local files
COPY app/ /app/
```

`ADD` with a URL performs an unauthenticated fetch with no integrity guarantee — a compromised upstream URL leads to code execution at build time.

Grep: `^ADD https?://`

Severity: HIGH for remote URLs, MEDIUM for local archive extraction.

---

## 6. Privileged Operations in RUN Steps

**Check:** Do any `RUN` instructions invoke `sudo` or set broad file permissions?

```dockerfile
# BAD — escalates to root during build; permissions may persist at runtime
RUN sudo chmod 777 /etc/passwd
RUN sudo apt-get install -y ...
RUN chmod -R 777 /app
```

`sudo` in a `RUN` step means the build requires or assumes root, and broad `chmod 777` grants world-write access to sensitive paths.

Grep: `RUN.*sudo`, `chmod.*777`, `chmod.*666`

Severity: HIGH

---

## 7. Sensitive Ports Exposed

**Check:** Are management, debug, or unauthenticated service ports declared in `EXPOSE`?

```dockerfile
EXPOSE 22    # SSH — remote shell access
EXPOSE 2375  # Docker daemon — unauthenticated API, full host control
EXPOSE 2376  # Docker daemon TLS — still a high-value target
EXPOSE 4040  # Spark UI — no auth by default
```

`EXPOSE` is documentation but signals intent. Flag ports that provide privileged or unauthenticated access.

Grep: `^EXPOSE (22|23|2375|2376|3389|4040)\b`

Severity: CRITICAL for `2375`/`2376` (Docker daemon), HIGH for `22` (SSH), MEDIUM for others.

---

## 8. Multi-Stage Build Secret Leakage

**Check:** In multi-stage builds, are credentials or keys copied from the build stage into the final image?

```dockerfile
# BAD — SSH key ends up in the final image layer
FROM builder AS build
COPY id_rsa /root/.ssh/id_rsa
RUN git clone git@github.com:org/private-repo.git

FROM final
COPY --from=build /root/.ssh/id_rsa /root/.ssh/id_rsa  # leaked into final image!

# GOOD — use BuildKit SSH forwarding; key never touches the filesystem
RUN --mount=type=ssh git clone git@github.com:org/private-repo.git

# GOOD — use BuildKit secret mounts; secret is not stored in any layer
RUN --mount=type=secret,id=mysecret ./build.sh
```

Grep: `COPY --from=.*ssh\|id_rsa\|\.pem\|\.key\|credentials`

Severity: CRITICAL

---

## 9. No-New-Privileges Not Enforced

**Check:** Is `--security-opt=no-new-privileges` absent from runtime instructions or `docker-compose.yml`?

```yaml
# BAD — container processes can gain new privileges via setuid/setgid binaries
services:
  app:
    image: myapp

# GOOD
services:
  app:
    image: myapp
    security_opt:
      - no-new-privileges:true
```

Without this, a setuid binary inside the container (e.g., `sudo`, `pkexec`) can escalate a low-privilege process to root.

Grep in compose files: absence of `no-new-privileges`

Severity: HIGH

---

## 10. Capabilities Not Dropped

**Check:** Does the Dockerfile or compose file add broad capabilities or fail to drop defaults?

```yaml
# CRITICAL — adds every Linux kernel capability; equivalent to running as root on the host
cap_add:
  - ALL

# HIGH — SYS_ADMIN is nearly equivalent to root
cap_add:
  - SYS_ADMIN

# GOOD — drop all, add only what the workload specifically requires
cap_drop:
  - ALL
cap_add:
  - CHOWN
  - NET_BIND_SERVICE
```

Default Docker capabilities already include dangerous ones (`DAC_OVERRIDE`, `NET_RAW`, `SYS_CHROOT`). Always drop all and add back only what is necessary.

Grep: `cap_add:.*ALL`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`

Severity: CRITICAL for `ALL`/`SYS_ADMIN`, HIGH for other dangerous caps.

---

## 11. Read-Only Filesystem Not Set

**Check:** Is `--read-only` / `read_only: true` absent for containers that don't need a writable root filesystem?

```yaml
# BAD — attacker who achieves code execution can write malware, modify configs
services:
  app:
    image: myapp

# GOOD — root filesystem is immutable; writable paths are explicit tmpfs mounts
services:
  app:
    image: myapp
    read_only: true
    tmpfs:
      - /tmp
```

A writable root filesystem allows an attacker with code execution to persist payloads, modify application binaries, and exfiltrate data.

Grep in compose files: absence of `read_only: true`

Severity: MEDIUM

---

## Quick Grep Summary

```bash
# Unpinned base image
grep -n "^FROM.*:latest" Dockerfile
grep -nE "^FROM [^:@[:space:]]+[[:space:]]*$" Dockerfile

# Root user
grep -n "^USER" Dockerfile              # absence = root

# Secrets in layers
grep -nEi "ENV.*(PASSWORD|SECRET|TOKEN|KEY|API)" Dockerfile
grep -nEi "ARG.*(PASSWORD|SECRET|TOKEN|KEY)" Dockerfile
grep -n "COPY.*\.env" Dockerfile

# Docker socket
grep -rn "docker.sock" .

# Remote ADD
grep -nE "^ADD https?://" Dockerfile

# Privileged steps
grep -n "sudo\|chmod.*777\|chmod.*666" Dockerfile

# Sensitive ports
grep -nE "^EXPOSE (22|2375|2376|3389|4040)" Dockerfile

# Multi-stage secret leakage
grep -nE "COPY --from=.*(id_rsa|\.pem|\.key|credentials|\.ssh)" Dockerfile

# Capabilities (compose)
grep -n "cap_add\|CAP_SYS_ADMIN\|CAP_NET_ADMIN" docker-compose*.yml
```
