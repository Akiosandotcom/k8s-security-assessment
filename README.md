# Kubernetes Security Assessment

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Scope: read-only](https://img.shields.io/badge/cluster%20scope-read--only-276749.svg)](docs/METHODOLOGY.md)

A read-only security assessment collector for Kubernetes, built for K3s.
It gathers cluster inventory and produces a local archive of configuration
findings for platform engineers and security teams.

**[Quick start](#quick-start) · [Sample report](examples/networkpolicy-coverage.json) · [Methodology](docs/METHODOLOGY.md)**

## Why this project exists

A Kubernetes review often starts with three questions. Which permissions need
a closer look? Which pods use sensitive settings? Which namespaces have zero
NetworkPolicy objects? This collector puts the evidence for those questions in
one archive and records collection failures so reviewers can see where the
evidence is incomplete.

## What it checks

| Area | Review signal | Where to look |
| --- | --- | --- |
| Inventory | Nodes, workloads, RBAC objects, services, ingresses, namespaces and storage | `raw/` |
| RBAC | Wildcards, permissions on sensitive resources, selected administrative bindings and default ServiceAccount token settings | `rbac/` |
| Pod hardening | Privileged containers, host namespaces, hostPath mounts and selected security context settings | `podsec/risky_pods.json` |
| NetworkPolicy | Namespaces with zero NetworkPolicy objects | `netpol/coverage.json` |
| K3s encryption at rest | Local encryption status when available on the K3s server | `raw/k3s_secrets_encryption.txt` |
| CIS Benchmark | Optional results from a locally installed kube-bench | `benchmark/` |

## Quick start

Use Linux with Bash, jq 1.6 or later, tar, and either `kubectl` or `k3s kubectl`.
Use a kubeconfig with read access to the inventory resources you want to review.
Run from a directory you control.

```bash
export KUBECONFIG="$HOME/.kube/config"
kubectl config current-context
bash ./k8s-security-assessment.sh
```

If `KUBECONFIG` is unset, the script uses `/etc/rancher/k3s/k3s.yaml` when
readable and otherwise uses the Kubernetes client's default configuration.
The two identity permission reviews also require impersonation permissions.
For optional local checks, see [requirements and coverage](docs/METHODOLOGY.md#requirements-and-coverage).

## Read the report

The run creates a `k8s-assessment-<timestamp>/` directory and matching
`.tar.gz` archive. Start with `scan.log` and the inventory `.err` files.
An exit code of `2` indicates an incomplete inventory or a detected analysis
failure. Optional tool failures and identity review errors are documented
in the corresponding report files or log.

The [synthetic NetworkPolicy report](examples/networkpolicy-coverage.json)
shows the output schema. In that example, `sandbox` has no NetworkPolicy
objects. For the other namespaces, confirm workload selectors, ingress and
egress rules, and enforcement separately. See
[how to interpret each check](docs/METHODOLOGY.md#interpretation).

## Report handling

The collector skips Kubernetes Secret objects and K3s configuration file dumps.
It strips the top-level last-applied annotation and masks non-boolean literal
container environment values in supported workload specifications. Reports can
still contain internal addresses, resource names, annotations and command-line
arguments. Keep generated reports out of the public repository and use synthetic
examples when opening public issues.

## License

[MIT](LICENSE).
