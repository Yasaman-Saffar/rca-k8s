# Security Tests — Role 1 (Cluster Security & Connectivity Engineer)

Evidence log for RBAC, connectivity, and hook controls. Every entry records the exact
command run and the actual output, so results are reproducible and auditable.

## 1. RBAC — permission boundaries

Namespace: `rca-agent-test`
ServiceAccount: `system:serviceaccount:rca-agent-test:rca-agent`
Manifest: [`rbac/rca-agent-rbac.yaml`](../rbac/rca-agent-rbac.yaml)

Design: the Role grants `get/list/watch` on read-only resources only, and **`secrets` is
deliberately not in the resource list**. This is a stronger control than any hook — the
Kubernetes API server itself rejects the request (403) before any agent code, MCP server,
or hook ever runs.

```
$ kubectl apply -f rbac/rca-agent-rbac.yaml
serviceaccount/rca-agent created
role.rbac.authorization.k8s.io/rca-agent-readonly created
rolebinding.rbac.authorization.k8s.io/rca-agent-binding created

$ kubectl auth can-i delete pods --as=$SA -n rca-agent-test
no

$ kubectl auth can-i update deployments --as=$SA -n rca-agent-test
no

$ kubectl auth can-i patch deployments --as=$SA -n rca-agent-test
no

$ kubectl auth can-i create pods/exec --as=$SA -n rca-agent-test
no

$ kubectl auth can-i get secrets --as=$SA -n rca-agent-test
no

$ kubectl auth can-i list secrets --as=$SA -n rca-agent-test
no

$ kubectl auth can-i get pods --as=$SA -n rca-agent-test
yes

$ kubectl auth can-i get pods/log --as=$SA -n rca-agent-test
yes

$ kubectl auth can-i list events --as=$SA -n rca-agent-test
yes

$ kubectl auth can-i get pods --as=$SA -n test
no
```

**Result: PASS.** All 10 checks match expectation — no mutation verb, no exec, no secret
access, and no access outside the assigned namespace; read-only resources inside the
namespace are allowed. Verified independently by the user and re-run by the agent with
identical results.

Definition of Done items covered:
- [x] `k auth can-i delete/edit/patch pods ...` for SA all `no`
- [x] `k auth can-i get secrets ...` for SA `no`

## 2. Scoped token + isolated kubeconfig

A dedicated kubeconfig (`.secrets/rca-agent.kubeconfig`, gitignored — never committed) was
built from scratch using only the SA token, so the agent never has access to the operator's
personal kubeconfig/credentials.

```
$ TOKEN=$(kubectl create token rca-agent -n rca-agent-test --duration=8760h)
$ echo ${TOKEN:0:20}...
eyJhbGciOiJSUzI1NiIs...

$ kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > .secrets/ca.crt
$ head -1 .secrets/ca.crt
-----BEGIN CERTIFICATE-----

$ kubectl config set-cluster rca-cluster --server="https://188.121.116.254:6443" --certificate-authority=.secrets/ca.crt --embed-certs=true
Cluster "rca-cluster" set.
$ kubectl config set-credentials rca-agent --token="$TOKEN"
User "rca-agent" set.
$ kubectl config set-context rca-agent-context --cluster=rca-cluster --namespace=rca-agent-test --user=rca-agent
Context "rca-agent-context" modified.
$ kubectl config use-context rca-agent-context
Switched to context "rca-agent-context".

$ kubectl --kubeconfig=.secrets/rca-agent.kubeconfig get pods
NAME                          READY   STATUS    RESTARTS   AGE
nginx-test-59749c5748-5r929   1/1     Running   0          35m

$ kubectl --kubeconfig=.secrets/rca-agent.kubeconfig get secrets
Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:rca-agent-test:rca-agent" cannot list resource "secrets" in API group "" in the namespace "rca-agent-test"

$ kubectl --kubeconfig=.secrets/rca-agent.kubeconfig delete pod nginx-test-59749c5748-5r929
Error from server (Forbidden): pods "nginx-test-59749c5748-5r929" is forbidden: User "system:serviceaccount:rca-agent-test:rca-agent" cannot delete resource "pods" in API group "" in the namespace "rca-agent-test"
```

**Result: PASS.** The isolated credential works for reads, uses TLS verification (real CA,
no `insecure-skip-tls-verify`), and is rejected by the API server itself for both
`get secrets` and `delete pod` — confirmed independently by the user and re-run by the
agent with identical results.

## 3. MCP server wiring and tool surface

`.mcp.json` launches `kubernetes-mcp-server@latest` with `--read-only --disable-destructive`
against the isolated kubeconfig from §2. A manual MCP handshake
([`testbed/test_mcp_handshake.py`](../testbed/test_mcp_handshake.py)) was used to inspect
exactly which tools the server exposes to the agent:

```
$ python3 testbed/test_mcp_handshake.py
INIT RESPONSE: {"jsonrpc":"2.0","id":1,"result":{...,"serverInfo":{"name":"kubernetes-mcp-server","version":"v0.0.66",...}}}
TOOL COUNT: 14
TOOLS: ['configuration_view', 'events_list', 'namespaces_list', 'nodes_log', 'nodes_stats_summary',
        'nodes_top', 'pods_get', 'pods_list', 'pods_list_in_namespace', 'pods_log', 'pods_top',
        'projects_list', 'resources_get', 'resources_list']
```

**Result: PASS.** All 14 exposed tools are read-oriented (`*_list`, `*_get`, `*_log`, `*_top`,
`configuration_view`). No tool named `delete`, `apply`, `patch`, `scale`, `exec`, or `cp` is
present — the agent has no mutating capability offered to it at the MCP tool-surface level,
independent of and in addition to the RBAC enforcement proven in §1.

## 4. Hooks and secret-leak test

Deliverables: [`hooks/hooks.json`](../hooks/hooks.json),
[`hooks/scripts/block-mutations.py`](../hooks/scripts/block-mutations.py),
[`hooks/scripts/redact-secrets.py`](../hooks/scripts/redact-secrets.py).

### 4.1 Design note beyond the original spec

While testing, we found that RBAC alone does not protect against `kubectl` invoked via
Bash with an **unscoped/admin kubeconfig** (no `KUBECONFIG` override) — RBAC only binds
the scoped `rca-agent` identity, so a Bash call using the operator's default kubeconfig
would bypass it entirely. `block-mutations.py` was extended beyond the original
apply/delete/edit/scale/patch/cp/exec list to also unconditionally block any
`kubectl`/`oc`/`k` command touching `secret`/`secrets`, regardless of verb or which
kubeconfig is active — this is the only backstop against that bypass path.

### 4.2 Unit tests (script-level, via `testbed/test_block_mutations.py` / `testbed/test_redact_secrets.py`)

All 12 cases pass:

```
block-mutations.py:
  kubectl apply ................................ BLOCK (exit 2)  ✓
  kubectl delete ................................ BLOCK (exit 2)  ✓
  k delete (alias) .............................. BLOCK (exit 2)  ✓
  kubectl get ................................... ALLOW (exit 0)  ✓
  unrelated 'cp' shell command .................. ALLOW (exit 0)  ✓  (no false positive)
  non-Bash tool .................................. ALLOW (exit 0)  ✓
  kubectl get secret (admin kubeconfig) ......... BLOCK (exit 2)  ✓
  kubectl describe secret ....................... BLOCK (exit 2)  ✓

redact-secrets.py:
  DB_PASSWORD=... in tool output ................ BLOCK (exit 2)  ✓
  AWS access key in tool output ................. BLOCK (exit 2)  ✓
  private key block in tool output .............. BLOCK (exit 2)  ✓
  benign pod list output ......................... ALLOW (exit 0)  ✓
```

One real bug was caught and fixed during testing: the initial secret regex required a
word boundary immediately before `password`/`secret`/etc., which missed real-world
compound identifiers like `DB_PASSWORD` (the `_` is a word character, so `\bpassword\b`
never matched). Fixed to allow the keyword to appear anywhere inside a surrounding
identifier.

### 4.3 Live end-to-end test (real session, real fake secret)

With `.claude/settings.json` wiring the two hooks into a live Claude Code session against
this project:

```
$ kubectl create secret generic fake-secret -n rca-agent-test --from-literal=DB_PASSWORD=Sup3rSecretXyz123
secret/fake-secret created

# genuine attempt, in a live session, to read the secret's value via Bash:
$ kubectl get secret fake-secret -n rca-agent-test -o yaml
PreToolUse:Bash hook error: Blocked: 'kubectl get secret fake-secret -n rca-agent-test -o yaml'
touches Secret resources directly via kubectl/oc. This agent must never read Secret
values, regardless of which kubeconfig is active. Use the read-only MCP tools for
everything else.
```

**Result: PASS.** The command was blocked at `PreToolUse`, before execution — the secret
value never reached the model's context or the visible transcript at any point. Also
observed: because `PreToolUse` evaluates the whole command string before anything runs,
a compound command containing an unrelated mutating substring is blocked atomically (none
of it runs, not even unrelated earlier lines in the same command) — a stricter behavior
than a partial/line-by-line block would give.

Definition of Done items covered:
- [x] Manual execution of a mutating command from within the agent, rejected by the hook
      with exit 2
- [x] The fake Secret's value never appeared anywhere in the transcript
- [x] Cleanup performed (`kubectl delete secret fake-secret`) after the test

### 4.4 Operational note

`.claude/settings.json` in this project is a **local testing scaffold**, not a Role 1
deliverable — it mirrors `hooks/hooks.json` using `${CLAUDE_PROJECT_DIR}` instead of
`${CLAUDE_PLUGIN_ROOT}` so the hooks can be fired in a live session before
`.claude-plugin/plugin.json` exists. It is kept as `.claude/settings.json.disabled` by
default (renamed back only for an active test) because, correctly, it blocks *all*
Bash calls in the session it's active in — including the operator's own admin/cleanup
commands — not only a hypothetical restricted agent's. It should be removed once
`plugin.json` wires `hooks/hooks.json` for real at the integration phase.
