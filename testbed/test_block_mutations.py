import json
import subprocess

CASES = [
    ("kubectl apply (should BLOCK, exit 2)",
     {"tool_name": "Bash", "tool_input": {"command": "kubectl apply -f deploy.yaml -n rca-agent-test"}}),
    ("kubectl delete (should BLOCK, exit 2)",
     {"tool_name": "Bash", "tool_input": {"command": "kubectl delete pod nginx-test-abc -n rca-agent-test"}}),
    ("k alias delete (should BLOCK, exit 2)",
     {"tool_name": "Bash", "tool_input": {"command": "k delete deploy nginx-test -n rca-agent-test"}}),
    ("kubectl get (should ALLOW, exit 0)",
     {"tool_name": "Bash", "tool_input": {"command": "kubectl get pods -n rca-agent-test"}}),
    ("unrelated 'cp' shell command (should ALLOW, exit 0 - no false positive)",
     {"tool_name": "Bash", "tool_input": {"command": "cp file1.txt file2.txt"}}),
    ("non-Bash tool (should ALLOW, exit 0 immediately)",
     {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}),
    ("kubectl get secret via ADMIN kubeconfig (should BLOCK, exit 2)",
     {"tool_name": "Bash", "tool_input": {"command": "kubectl get secret fake -n rca-agent-test -o yaml"}}),
    ("kubectl describe secret (should BLOCK, exit 2)",
     {"tool_name": "Bash", "tool_input": {"command": "kubectl describe secret fake -n rca-agent-test"}}),
]

for desc, payload in CASES:
    proc = subprocess.run(
        ["python3", "hooks/scripts/block-mutations.py"],
        input=json.dumps(payload), capture_output=True, text=True,
    )
    print(f"--- {desc} ---")
    print("exit code:", proc.returncode)
    if proc.stderr.strip():
        print("stderr:", proc.stderr.strip())
    print()
