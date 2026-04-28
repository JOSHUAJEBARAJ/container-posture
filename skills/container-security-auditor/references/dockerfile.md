# Dockerfile Security Checklist

Apply these checks to every `Dockerfile` found during discovery.

## 1. Base Image

**Check:** Is the base image pinned to a specific digest or at minimum a version tag?

```dockerfile
# BAD — latest is unpinned, silently pulls new (potentially vulnerable) layers
FROM ubuntu:latest
FROM node:latest

# BETTER — version tag (still mutable, but intentional)
FROM node:20-alpine

# BEST — immutable, digest-pinned
FROM node:20-alpine@sha256:abc123...
```

Grep pattern: `^FROM .*:latest`

Severity: MEDIUM

---

## 2. Running as Root

**Check:** Does the image run as root by default?

```dockerfile
# BAD — no USER instruction means root
FROM ubuntu:22.04
RUN apt-get install -y curl
CMD ["curl"]

# GOOD — drop to non-root before CMD/ENTRYPOINT
RUN addgroup --system app && adduser --system --ingroup app app
USER app
```

Grep pattern: `^USER` — if absent, the image runs as root (UID 0).

Severity: HIGH (CRITICAL if combined with hostPath or privileged)

---

## 3. Secrets in Image Layers

**Check:** Are secrets baked into the image via `ENV`, `ARG`, or `COPY`?

```dockerfile
# CRITICAL — secret is stored in every layer, visible via docker history
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ARG DB_PASSWORD=supersecret
RUN curl -H "Authorization: Bearer $TOKEN" https://api.example.com

# BAD — .env file copied into image
COPY .env /app/.env

# GOOD — inject secrets at runtime via orchestrator, not build time
# Use Docker secrets, k8s Secrets volumes, or Vault agent
```

Grep patterns:
- `ENV.*PASSWORD|ENV.*SECRET|ENV.*TOKEN|ENV.*KEY`
- `ARG.*PASSWORD|ARG.*SECRET|ARG.*TOKEN`
- `COPY.*\.env`

Severity: CRITICAL

---

## 4. ADD vs COPY

**Check:** Is `ADD` used where `COPY` would suffice?

```dockerfile
# BAD — ADD can fetch remote URLs and auto-extract archives, unexpected behavior
ADD https://example.com/script.sh /tmp/
ADD app.tar.gz /app/

# GOOD — COPY is explicit and predictable
COPY app/ /app/
```

Grep pattern: `^ADD `

Severity: MEDIUM — escalates to HIGH if adding from remote URLs.

---

## 5. Package Cache Not Cleared

**Check:** Does the Dockerfile install packages and clean up in the same `RUN` layer?

```dockerfile
# BAD — cache left in image, increases attack surface and image size
RUN apt-get update
RUN apt-get install -y curl wget

# GOOD — single layer, cache cleaned
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*
```

Severity: LOW (hardening best practice, not a direct exploit path)

---

## 6. Privileged Build Steps

**Check:** Does any `RUN` step use `--privileged` or invoke `sudo`?

```dockerfile
# BAD
RUN sudo chmod 777 /etc/passwd
RUN --mount=type=cache,sharing=locked ...
```

Grep pattern: `RUN.*sudo`, `RUN.*--privileged`

Severity: HIGH

---

## 7. Exposed Sensitive Ports

**Check:** Are management or debug ports exposed?

```dockerfile
# Risky if not intended for public exposure
EXPOSE 22    # SSH
EXPOSE 2375  # Docker daemon (unauthenticated)
EXPOSE 4040  # Spark UI
EXPOSE 9090  # Prometheus
```

Grep pattern: `^EXPOSE (22|2375|4040|9090|8080|3000)\b`

Severity: MEDIUM — depends on network exposure.

---

## 8. Multi-Stage Build Secret Leakage

**Check:** In multi-stage builds, are secrets or credentials copied from a build stage to the final stage?

```dockerfile
# BAD — SSH key ends up in final image
FROM builder AS build
COPY id_rsa /root/.ssh/
RUN git clone git@github.com:org/private-repo.git

FROM final
COPY --from=build /root/.ssh/id_rsa /root/.ssh/  # leaked!

# GOOD — use --mount=type=secret or BuildKit SSH forwarding
RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret
```

Severity: CRITICAL if private keys or credentials are copied to final stage.

---

## Quick Grep Summary

Run these against any Dockerfile:

```bash
grep -n "^FROM.*:latest" Dockerfile
grep -n "^USER" Dockerfile          # absence = root
grep -nE "ENV.*(PASSWORD|SECRET|TOKEN|KEY|API)" Dockerfile
grep -nE "ARG.*(PASSWORD|SECRET|TOKEN|KEY)" Dockerfile
grep -n "COPY.*\.env" Dockerfile
grep -n "^ADD " Dockerfile
grep -nE "^EXPOSE (22|2375|4040)" Dockerfile
grep -n "sudo" Dockerfile
```
