# RBAC Misconfiguration Patterns

Apply to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` manifests.

## Core Principle

RBAC violations follow one rule: **least privilege**. Every deviation from minimum necessary permissions is a finding.

---

## 1. Wildcard Permissions

**Check:** Are wildcard `*` verbs or resources used?

```yaml
# CRITICAL — grants every action on every resource in the cluster
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]

# HIGH — grants every action on a specific resource type
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["*"]

# GOOD — explicit, minimal permissions
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
```

Grep: `verbs: \["\*"\]`, `resources: \["\*"\]`

Severity: CRITICAL for full wildcards, HIGH for resource-scoped wildcards.

---

## 2. cluster-admin Binding

**Check:** Is `cluster-admin` bound to a non-system subject?

```yaml
# CRITICAL — grants superuser access to the entire cluster
kind: ClusterRoleBinding
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: my-app
    namespace: default

# Also flag bindings to groups like "system:authenticated" or "system:unauthenticated"
subjects:
  - kind: Group
    name: system:authenticated  # ALL authenticated users get cluster-admin
```

Grep: `name: cluster-admin`

Severity: CRITICAL

---

## 3. Secrets Access

**Check:** Does a role grant read or list access to Secrets?

```yaml
# HIGH — can read all secrets in the namespace/cluster
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]

# ACCEPTABLE — only list (no values exposed, but still leaks secret names)
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
```

Grep: `resources: \["secrets"\]` combined with `verbs:.*get`

Severity: HIGH for `get`/`list` on secrets.

---

## 4. Pod exec / attach / portforward

**Check:** Can the role exec into pods?

```yaml
# HIGH — exec into any pod = lateral movement to any workload
rules:
  - apiGroups: [""]
    resources: ["pods/exec", "pods/attach", "pods/portforward"]
    verbs: ["create"]
```

Grep: `pods/exec`, `pods/attach`, `pods/portforward`

Severity: HIGH — exec access is equivalent to shell access to the application.

---

## 5. Escalating Permissions

**Check:** Can the role create or bind new roles (privilege escalation)?

```yaml
# CRITICAL — role that can create/bind roles can grant itself cluster-admin
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings", "rolebindings"]
    verbs: ["create", "update", "patch"]

  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "roles"]
    verbs: ["create", "update", "patch", "bind", "escalate"]
```

Grep: `resources:.*rolebindings`, `verbs:.*bind`, `verbs:.*escalate`

Severity: CRITICAL

---

## 6. Default ServiceAccount Usage

**Check:** Is the default `ServiceAccount` being used (no explicit SA set)?

```yaml
# BAD — pod uses the namespace default SA, which may have accumulated permissions
spec:
  containers:
    - name: app
      image: myapp:1.0
  # no serviceAccountName set

# GOOD — dedicated SA with no permissions beyond what's needed
spec:
  serviceAccountName: myapp-sa
  automountServiceAccountToken: false  # if the app doesn't call the API
```

Also check for `automountServiceAccountToken: true` on service accounts that don't need API access.

Severity: MEDIUM — escalates to HIGH if default SA has been granted permissions.

---

## 7. Namespace Scope Confusion

**Check:** Is a `ClusterRoleBinding` used where a `RoleBinding` would suffice?

```yaml
# Overly broad — applies to ALL namespaces
kind: ClusterRoleBinding
roleRef:
  kind: ClusterRole
  name: pod-reader

# Better — scoped to one namespace
kind: RoleBinding
roleRef:
  kind: Role
  name: pod-reader
  namespace: production
```

Severity: MEDIUM — widened blast radius if account is compromised.

---

## Quick Grep Summary

```bash
grep -n "cluster-admin" *.yaml
grep -nE 'verbs: \["\*"\]' *.yaml
grep -nE 'resources: \["\*"\]' *.yaml
grep -n "pods/exec\|pods/attach\|pods/portforward" *.yaml
grep -n "secrets" *.yaml | grep -v "#"
grep -nE "verbs:.*(bind|escalate)" *.yaml
grep -n "automountServiceAccountToken" *.yaml
```
