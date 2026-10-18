#!/usr/bin/env bash
# ==============================================================================
# TrueIntent Security Benchmark Suite - Upstream Dataset Downloader
# Fetches gold-standard attack datasets from trusted peer-reviewed GitHub repositories:
# 1. UIUC Kang Lab InjecAgent (Indirect Prompt Injection in Tool-Integrated Agents)
# 2. Microsoft BIPIA (Benchmark for Indirect Prompt Injection Attacks on LLMs)
# 3. Meta AI PurpleLlama CyberSecEval (Cybersecurity Benchmarks for LLMs)
# 4. PayloadsAllTheThings (Swisskyrepo Offensive Security Repository)
# 5. SecLists (Daniel Miessler Definitive Security Fuzzing Dictionaries)
# ==============================================================================

set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "[*] Initializing TrueIntent Benchmark Attack Suite Download..."
echo "======================================================================"

# 1. UIUC InjecAgent
echo "[+] Fetching UIUC InjecAgent datasets..."
mkdir -p "${SUITE_DIR}/01_agent_tool_injections"
curl -sSL "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_ds.jsonl" \
     -o "${SUITE_DIR}/01_agent_tool_injections/attacker_cases_ds.jsonl"
curl -sSL "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_dh.jsonl" \
     -o "${SUITE_DIR}/01_agent_tool_injections/attacker_cases_dh.jsonl"

# 2. Microsoft BIPIA
echo "[+] Fetching Microsoft BIPIA benchmarks..."
mkdir -p "${SUITE_DIR}/02_indirect_prompt_injections"
curl -sSL "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/code_attack_test.json" \
     -o "${SUITE_DIR}/02_indirect_prompt_injections/bipia_code_attacks.json"
curl -sSL "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/text_attack_test.json" \
     -o "${SUITE_DIR}/02_indirect_prompt_injections/bipia_text_attacks.json"

# 3. Meta AI PurpleLlama (CyberSecEval)
echo "[+] Fetching Meta CyberSecEval benchmark datasets..."
mkdir -p "${SUITE_DIR}/03_llm_cybersecurity_evals"
curl -sSL "https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json" \
     -o "${SUITE_DIR}/03_llm_cybersecurity_evals/cyberseceval_prompt_injection.json"
curl -sSL "https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/CybersecurityBenchmarks/datasets/interpreter/interpreter.json" \
     -o "${SUITE_DIR}/03_llm_cybersecurity_evals/cyberseceval_code_execution.json"

# 4. PayloadsAllTheThings & SecLists (Command Injection)
echo "[+] Fetching OS Command Injection suites..."
mkdir -p "${SUITE_DIR}/04_os_command_injections"
curl -sSL "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt" \
     -o "${SUITE_DIR}/04_os_command_injections/unix_command_injections.txt"
curl -sSL "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_exec.txt" \
     -o "${SUITE_DIR}/04_os_command_injections/command_exec_subshells.txt"
curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt" \
     -o "${SUITE_DIR}/04_os_command_injections/seclists_command_injection.txt"

# 5. PayloadsAllTheThings & SecLists (Path Traversal / LFI)
echo "[+] Fetching Path Traversal & LFI vectors..."
mkdir -p "${SUITE_DIR}/05_path_traversal_and_lfi"
curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" \
     -o "${SUITE_DIR}/05_path_traversal_and_lfi/lfi_jhaddix.txt"
curl -sSL "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/traversals-8-deep-exotic-encoding.txt" \
     -o "${SUITE_DIR}/05_path_traversal_and_lfi/exotic_encoding_traversals.txt"
curl -sSL "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt" \
     -o "${SUITE_DIR}/05_path_traversal_and_lfi/directory_traversals.txt"

# 6. Rebuild unified corpus
echo "[+] Compiling unified benchmark JSON corpus..."
python3 "${SUITE_DIR}/generate_unified_corpus.py"

echo "======================================================================"
echo "[✓] All trusted benchmark attack files downloaded and verified."
echo "======================================================================"
