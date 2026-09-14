#!/usr/bin/env python3
import json
import re
import sys

data = json.load(sys.stdin)

if data.get("tool_name") != "Bash":
    sys.exit(0)

command = data.get("tool_input", {}).get("command", "")

# Only guard kubectl/oc invocations specifically — a bare 'cp' or 'exec' in
# unrelated shell usage (file copy, ssh, etc.) must not be blocked.
KUBECTL_BIN = r"(?:kubectl|oc|\bk\b)"
MUTATING_VERBS = (
    r"(?:apply|delete|edit|scale|patch|cp|exec|replace|create"
    r"|annotate|label|drain|cordon|uncordon)"
)
mutation_pattern = re.compile(rf"{KUBECTL_BIN}\b.*\b{MUTATING_VERBS}\b")

# Block ANY interaction with Secret objects via Bash, mutating or not. RBAC
# already denies this for the scoped kubeconfig, but if Bash falls back to an
# unscoped/admin kubeconfig (no KUBECONFIG override), RBAC offers no
# protection at all — this is the only backstop in that case.
secrets_pattern = re.compile(rf"{KUBECTL_BIN}\b.*\bsecrets?\b")

if mutation_pattern.search(command):
    print(
        f"Blocked: '{command}' looks like a mutating kubectl/oc command. "
        "This agent is read-only by design (RBAC + read-only MCP tool surface "
        "+ this hook). Propose a YAML patch instead of applying changes.",
        file=sys.stderr,
    )
    sys.exit(2)

if secrets_pattern.search(command):
    print(
        f"Blocked: '{command}' touches Secret resources directly via kubectl/oc. "
        "This agent must never read Secret values, regardless of which "
        "kubeconfig is active. Use the read-only MCP tools for everything else.",
        file=sys.stderr,
    )
    sys.exit(2)

sys.exit(0)
