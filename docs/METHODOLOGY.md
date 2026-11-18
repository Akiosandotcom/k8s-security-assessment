# Assessment methodology

## Requirements and coverage

The script reads Kubernetes inventory with `kubectl` and analyzes the returned
objects locally with jq. Its coverage depends on the kubeconfig's selected
context and read permissions. It also runs two authorization reviews using
`kubectl auth can-i --list` for the anonymous identity and the default
ServiceAccount in the `default` namespace. The caller needs impersonation
permissions for those identities. Review the corresponding files in `rbac/`
for access errors and API warnings.

The encryption check calls `k3s secrets-encrypt status` and requires a K3s
server with sufficient access to its local state. For the optional
[kube-bench](https://github.com/aquasecurity/kube-bench) check, use a trusted
installation on `PATH`, or set `KB_DIR` to a directory containing the executable
and `cfg/`. The default directory lookup is `$HOME/kube-bench`. Confirm the
benchmark profile matches the distribution and version under review.

## Interpretation

| Check | How to interpret the result |
| --- | --- |
| Inventory | Confirm which resources were collected before drawing conclusions. Unavailable inventory may be represented by empty JSON plus an accompanying `.err` file. |
| RBAC | Treat flagged rules as review candidates. Check bindings, subjects and namespace scope to determine effective access. Administrative binding checks include a role-name heuristic for RoleBindings. |
| Pod hardening | Findings describe fields in current Pod specifications, including regular, init and ephemeral containers. Check admission policy and runtime context separately. The ServiceAccount token field in this report reflects the Pod-level configuration. |
| NetworkPolicy | The coverage check counts policy presence by namespace. Assess selected workloads, directions and CNI enforcement separately. Missing inventory yields `{"status":"unavailable"}`. |
| K3s encryption and kube-bench | Interpret the local tool result in the context of the node, profile and tool permissions. Review the logs when the check is skipped or fails. |

## Data handling

Raw reports contain selected API resources after targeted masking. Report
directories, archives and logs are intended for internal review. Inspect
annotations, IP addresses and other deployment details before sharing any
excerpt. Use fabricated identifiers and values in public examples.
