---
name: container-audit
description: Audit a Dockerfile or Kubernetes manifest for security misconfigurations
argument-hint: "<path-to-file-or-directory>"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Container Security Audit

**Target:** $ARGUMENTS

Parse the argument:
- If a file path is given, audit that single file.
- If a directory path is given, discover all `Dockerfile*`, `*.yaml`, and `*.yml` files within it.
- If no argument is given, discover from the current working directory.

Then invoke the `container-security-auditor` skill to perform the full audit workflow and produce a structured findings report.
