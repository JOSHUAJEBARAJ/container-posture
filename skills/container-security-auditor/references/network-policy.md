# Network Policy Gap Analysis

Kubernetes has no default network isolation — every pod can talk to every other pod unless a `NetworkPolicy` explicitly restricts traffic. This checklist finds gaps.

## Core Principle

Absence of a `NetworkPolicy` is itself a finding. Default-allow is the wrong default for production workloads.

---

## 1. No NetworkPolicy at All

**Check:** Does the namespace have zero NetworkPolicy resources?

```bash
# If this returns nothing, every pod can reach every other pod
grep -rl "kind: NetworkPolicy" .
```

If no NetworkPolicy files exist:

```
Finding: No Network Policies Defined
Severity: HIGH
Issue: All pods in the namespace can freely communicate with each other and
       reach any service. A compromised pod can pivot to databases, internal
       APIs, or the Kubernetes API server.
Fix: Define a default-deny ingress policy per namespace, then explicitly
     allow required traffic.
```

---

## 2. Default-Deny Policy Missing

**Check:** Even if NetworkPolicies exist, is there a default-deny baseline?

```yaml
# GOOD — deny all ingress by default, then allow selectively
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}      # matches ALL pods in namespace
  policyTypes:
    - Ingress
```

Without this, any pod not matched by an existing policy is unrestricted.

Severity: HIGH if any NetworkPolicy exists but no default-deny is present.

---

## 3. Overly Permissive Ingress

**Check:** Does a NetworkPolicy allow traffic from any namespace or any pod?

```yaml
# BAD — allows traffic from every pod in every namespace
spec:
  ingress:
    - from:
        - namespaceSelector: {}   # matches ALL namespaces
          podSelector: {}         # matches ALL pods

# BAD — no from clause = allow all ingress
spec:
  ingress:
    - {}

# GOOD — restrict to specific namespace + label
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: frontend
          podSelector:
            matchLabels:
              app: web
```

Grep: `namespaceSelector: {}`, `ingress:\n    - {}` (empty from = allow all)

Severity: HIGH

---

## 4. Unrestricted Egress

**Check:** Is egress unrestricted (no egress policy defined)?

```yaml
# BAD — pod can reach any IP including cloud metadata endpoints, internal services
spec:
  policyTypes:
    - Ingress   # only ingress restricted, egress is open

# GOOD — restrict egress too
spec:
  policyTypes:
    - Ingress
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: database
      ports:
        - protocol: TCP
          port: 5432
    - ports:                # allow DNS
        - protocol: UDP
          port: 53
```

Severity: MEDIUM — open egress enables data exfiltration and SSRF to cloud metadata APIs (169.254.169.254).

---

## 5. Cloud Metadata API Exposure

**Check:** Is egress to `169.254.169.254` (AWS/GCP/Azure metadata API) unrestricted?

If egress is open (no egress NetworkPolicy), any pod can call:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
This leaks cloud provider credentials attached to the node's IAM role.

Severity: CRITICAL in cloud environments with open egress.

---

## 6. Kubernetes API Server Access

**Check:** Can arbitrary pods reach the API server?

The API server typically runs on port `443` or `6443`. If egress is unrestricted, any compromised pod can:
- Enumerate cluster resources
- Attempt to escalate via the default ServiceAccount token

Fix: Restrict egress to the API server to only pods that explicitly need it, using CIDR blocks or a dedicated policy.

Severity: HIGH

---

## Recommended Baseline Policies

### Default-deny ingress (apply to every namespace)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

### Default-deny egress with DNS allowed
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

---

## Quick Checklist

```
[ ] At least one NetworkPolicy exists per namespace
[ ] Default-deny ingress policy is present
[ ] Default-deny egress policy is present (or egress is explicitly scoped)
[ ] No policy uses namespaceSelector: {} without podSelector restriction
[ ] No policy has an empty ingress rule ({})
[ ] Egress to 169.254.169.254 is blocked
[ ] API server egress is restricted to pods that need it
```
