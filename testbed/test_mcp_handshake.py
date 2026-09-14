import subprocess, json

proc = subprocess.Popen(
    ["npx", "-y", "kubernetes-mcp-server@latest", "--read-only", "--disable-destructive",
     "--kubeconfig", "/home/amirmahdi/amg/Hamamooz/RCA/.secrets/rca-agent.kubeconfig",
     "--log-file", "/tmp/mcp-server.log"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
)

def send(msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "test", "version": "1.0"}}})
print("INIT RESPONSE:", proc.stdout.readline().strip()[:300])

send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = json.loads(proc.stdout.readline())
names = sorted(t["name"] for t in tools.get("result", {}).get("tools", []))
print("TOOL COUNT:", len(names))
print("TOOLS:", names)

proc.terminate()
try:
    proc.wait(timeout=5)
except Exception:
    proc.kill()
