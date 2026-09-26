import json
import os
import subprocess

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "attack_corpus.json")
INSPECTOR_PATH = os.path.join(os.path.dirname(__file__), "../module4-semantic/inspector.py")

def run_adversarial_suite():
    with open(CORPUS_PATH, 'r') as f:
        corpus = json.load(f)

    print("=" * 70)
    print("Module 6: Adversarial Attack Suite Runner")
    print("=" * 70)

    caught = 0
    evaded = 0

    for test in corpus:
        # Construct the simulated MCP parsed message
        simulated_msg = {
            "msg_type": "request",
            "method": "tools/call",
            "tool_name": test["tool"],
            "policy_decision": "allow",
            "mcp_payload": {"params": {"arguments": test["payload"]}}
        }

        # Pipe into the semantic inspector
        proc = subprocess.Popen(
            ['python3', INSPECTOR_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, _ = proc.communicate(input=json.dumps(simulated_msg) + "\n")
        
        if not stdout.strip():
            print(f"[ERROR] No output for {test['id']}")
            continue

        res = json.loads(stdout.strip())
        decision = res.get("semantic_decision")
        
        if decision == "flag":
            status = "\033[92mCAUGHT\033[0m"
            caught += 1
        else:
            status = "\033[91mEVADED (BYPASS)\033[0m"
            evaded += 1

        print(f"[{test['id']}] {test['category']:<22} | Status: {status}")
        print(f"      Desc: {test['description']}")
        print(f"      Tool: {test['tool']} -> {test['payload']}")
        print("-" * 70)

    print(f"Summary: {caught} attacks caught, {evaded} successfully evaded the firewall.")
    print("=" * 70)

if __name__ == "__main__":
    run_adversarial_suite()
