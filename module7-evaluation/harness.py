import json
import os
import subprocess
import time
import csv
import argparse

DEFAULT_ATTACK_CORPUS = os.path.join(os.path.dirname(__file__), "../module6-adversarial/attack_suite/unified_attack_corpus.json")
FALLBACK_ATTACK_CORPUS = os.path.join(os.path.dirname(__file__), "../module6-adversarial/attack_corpus.json")
BENIGN_CORPUS = os.path.join(os.path.dirname(__file__), "benign_corpus.json")
INSPECTOR_PATH = os.path.join(os.path.dirname(__file__), "../module4-semantic/inspector.py")
RESULTS_CSV = os.path.join(os.path.dirname(__file__), "evaluation_results.csv")

def evaluate_payload(tool, payload):
    simulated_msg = {
        "msg_type": "request",
        "method": "tools/call",
        "tool_name": tool,
        "policy_decision": "allow",
        "mcp_payload": {"params": {"arguments": payload}}
    }
    
    start_time = time.perf_counter()
    proc = subprocess.Popen(
        ['python3', INSPECTOR_PATH],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    stdout, _ = proc.communicate(input=json.dumps(simulated_msg) + "\n")
    latency = (time.perf_counter() - start_time) * 1000  # in milliseconds
    
    if not stdout.strip():
        return "error", latency
        
    res = json.loads(stdout.strip())
    return res.get("semantic_decision", "error"), latency

def main():
    parser = argparse.ArgumentParser(description="TrueIntent Security Evaluation Harness")
    parser.add_argument("--corpus", type=str, default=None, help="Path to attack corpus JSON")
    args = parser.parse_args()

    if args.corpus and os.path.exists(args.corpus):
        attack_file = args.corpus
    elif os.path.exists(DEFAULT_ATTACK_CORPUS):
        attack_file = DEFAULT_ATTACK_CORPUS
    else:
        attack_file = FALLBACK_ATTACK_CORPUS

    print("=" * 60)
    print("Module 7: Automated Evaluation Harness")
    print(f"[*] Benchmark Corpus: {os.path.basename(attack_file)}")
    print("=" * 60)
    
    with open(attack_file, 'r') as f:
        attacks = json.load(f)
    with open(BENIGN_CORPUS, 'r') as f:
        benigns = json.load(f)

    results = []
    total_latency = 0
    caught_attacks = 0
    false_positives = 0

    # 1. Evaluate Attacks (Coverage & Bypass Rate)
    print(f"[*] Running {len(attacks)} Adversarial Attack Vectors...")
    for test in attacks:
        decision, lat = evaluate_payload(test["tool"], test["payload"])
        total_latency += lat
        status = "CAUGHT" if decision == "flag" else "BYPASSED"
        if status == "CAUGHT":
            caught_attacks += 1
        results.append(["Attack", test["id"], test["tool"], status, f"{lat:.2f}ms"])

    # 2. Evaluate Benign (False Positive Rate)
    print("[*] Running Benign Corpus...")
    for test in benigns:
        decision, lat = evaluate_payload(test["tool"], test["payload"])
        total_latency += lat
        status = "FALSE_POSITIVE" if decision == "flag" else "CLEAN"
        if status == "FALSE_POSITIVE":
            false_positives += 1
        results.append(["Benign", test["id"], test["tool"], status, f"{lat:.2f}ms"])

    # Compute Metrics
    coverage_pct = (caught_attacks / len(attacks)) * 100
    bypass_pct = 100 - coverage_pct
    fpr_pct = (false_positives / len(benigns)) * 100
    avg_latency = total_latency / (len(attacks) + len(benigns))

    # Output to CSV
    with open(RESULTS_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Type", "Test_ID", "Tool", "Outcome", "Latency_ms"])
        writer.writerows(results)

    print("\n" + "=" * 60)
    print("FINAL EVALUATION METRICS (REMOTE COMBINED PIPELINE)")
    print("=" * 60)
    print(f"Coverage (Threats Caught): {coverage_pct:.1f}%")
    print(f"Bypass Rate (Threats Missed): {bypass_pct:.1f}%")
    print(f"False Positive Rate:       {fpr_pct:.1f}%")
    print(f"Avg Added Latency/Call:    {avg_latency:.2f} ms")
    print(f"\n[+] Detailed results saved to: {RESULTS_CSV}")

if __name__ == "__main__":
    main()
