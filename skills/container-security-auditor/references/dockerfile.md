# Dockerfile Security Checklist

Apply these checks to `Dockerfile` instructions only. Runtime flags, Kubernetes securityContext, and compose settings are covered in `pod-security.md`.

Source: [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

## 1. Unpinned Base Image

**Check:** Is the base image using `latest` or missing a version tag entirely?

```dockerfile
# BAD — silently pulls new (potentially vulnerable) layers on every build
FROM ubuntu:latest
FROM node:latest

# BETTER — explicit version tag
FROM node:20-alpine

# BEST — digest-pinned, immutable
FROM node:20-alpine@sha256:abc123...
```

An unpinned image means a supply-chain compromise of the upstream image silently reaches your production container on the next build.

Grep: `^FROM .*:latest`, `^FROM [^:@\s]+\s*$` (no tag at all)

Severity: MEDIUM

---

## 2. Missing USER Instruction (Runs as Root)

**Check:** Is there a `USER` instruction before `CMD`/`ENTRYPOINT`? Absence means the container runs as UID 0 (root).

```dockerfile
# BAD — no USER = runs as root inside the container
FROM ubuntu:22.04
RUN apt-get install -y curl
CMD ["curl"]

# GOOD — create and switch to a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
```

Running as root means any code execution vulnerability inside the container gives the attacker root-level file system access.

Grep: absence of `^USER` in the file, or explicitly `^USER root` / `^USER 0`

Severity: HIGH

---

## 3. Secrets Baked into Image Layers

**Check:** Are secrets stored in `ENV` or `ARG` instructions, or copied in via `COPY`? Every layer is permanently stored and visible via `docker history`.

```dockerfile
# CRITICAL — stored in image history, readable by anyone with image access
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ARG DB_PASSWORD=supersecret
RUN curl -H "Authorization: Bearer hardcoded-token" https://api.example.com

# BAD — .env file embedded into the image
COPY .env /app/.env

# GOOD — use BuildKit secret mounts; never stored in any layer
RUN --mount=type=secret,id=db_password \
    DB_PASSWORD=$(cat /run/secrets/db_password) ./configure.sh
```

Even if the value is overridden at runtime, it remains permanently recorded in the image layer history.

Grep:
- `ENV.*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)`
- `ARG.*(PASSWORD|SECRET|TOKEN|KEY)`
- `COPY.*\.env`

Severity: CRITICAL

---

## 4. Docker Socket Declared as VOLUME

**Check:** Is `/var/run/docker.sock` declared in a `VOLUME` instruction?

```dockerfile
# BAD — signals intent to mount the Docker daemon socket
VOLUME /var/run/docker.sock
```

Access to the Docker socket is equivalent to unrestricted root on the host. A container with socket access can create privileged containers that mount the host filesystem.

Grep: `docker\.sock`

Severity: CRITICAL

---

## 5. Privileged Instructions in RUN Steps

**Check:** Do any `RUN` instructions invoke `sudo` or set world-writable permissions?

```dockerfile
# BAD — sudo inside RUN implies the build requires or assumes root
RUN sudo apt-get install -y curl
RUN sudo chmod 777 /app

# BAD — world-writable paths are exploitable at runtime
RUN chmod -R 777 /app
RUN chmod 666 /etc/passwd
```

`sudo` in a `RUN` step means the build assumes root access. World-writable paths (`777`) allow any process inside the container to overwrite application files.

Grep: `RUN.*sudo`, `chmod.*777`, `chmod.*666`

Severity: HIGH

---

## Quick Grep Summary

```bash
# Unpinned base image
grep -n "^FROM.*:latest" Dockerfile
grep -nE "^FROM [^:@[:space:]]+[[:space:]]*$" Dockerfile

# Missing USER (root)
grep -n "^USER" Dockerfile                          # absence = root

# Secrets in layers
grep -nEi "ENV.*(PASSWORD|SECRET|TOKEN|KEY|API)" Dockerfile
grep -nEi "ARG.*(PASSWORD|SECRET|TOKEN|KEY)" Dockerfile
grep -n "COPY.*\.env" Dockerfile

# Docker socket
grep -n "docker\.sock" Dockerfile

# Privileged RUN steps
grep -nE "RUN.*sudo|chmod.*(777|666)" Dockerfile
```
