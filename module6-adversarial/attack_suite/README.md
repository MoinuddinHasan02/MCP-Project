# TrueIntent Adversarial Attack Suite & Standardized Benchmarks

This directory contains the standardized evaluation corpora and benchmark suites used to evaluate the **TrueIntent Model Context Protocol (MCP) Intrusion Prevention System**.

To ensure peer-reviewed credibility, repeatability, and alignment with enterprise security frameworks, all attack vectors and test cases are sourced directly from industry-standard, peer-reviewed open-source repositories and AI security benchmarks.

---

## 📁 Repository & Benchmark Provenance

| Benchmark / Repository | Author / Organization | Focus Area | Citations / Reference |
| :--- | :--- | :--- | :--- |
| **[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)** | UIUC Kang Lab | Tool-Integrated Agent Indirect Prompt Injections, Data Stealing & Direct Harm | *Zhang et al., "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents", arXiv:2403.02691* |
| **[BIPIA](https://github.com/microsoft/BIPIA)** | Microsoft Research | Indirect Prompt Injection Attacks on LLMs across Code, QA, Email, and Tables | *Yi et al., "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models", ACM KDD* |
| **[CyberSecEval](https://github.com/meta-llama/PurpleLlama)** | Meta AI (Purple Llama) | Cybersecurity Benchmarks for LLMs, Code Interpreter Execution & Prompt Injections | *Bhatt et al., "CyberSecEval: A Standardized Evaluation Framework for LLM Security", Meta AI Research* |
| **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** | Swisskyrepo | OS Command Injection, Multi-level Directory Traversal, and Subshell Bypasses | Definitive offensive security repository for penetration testing & fuzzing |
| **[SecLists](https://github.com/danielmiessler/SecLists)** | Daniel Miessler | LFI (Local File Inclusion), Command Injection, Canonicalization Bypasses | Industry-standard security tester's companion dictionary |

---

## 🗂️ Directory Structure

```
module6-adversarial/attack_suite/
├── README.md                              # This documentation file
├── download_benchmarks.sh                 # Upstream sync and automated verification script
├── generate_unified_corpus.py             # Normalizer compiling upstream datasets into JSON test cases
├── unified_attack_corpus.json             # 130 standardized attack test vectors formatted for Module 7
├── 01_agent_tool_injections/              # Sourced from uiuc-kang-lab/InjecAgent
│   ├── attacker_cases_ds.jsonl            # Data Stealing (exfiltration via tool calling)
│   └── attacker_cases_dh.jsonl            # Direct Harm (unauthorized modification / deletion)
├── 02_indirect_prompt_injections/          # Sourced from microsoft/BIPIA
│   ├── bipia_code_attacks.json            # Data eavesdropping, reverse tunnels, clipboard exfiltration
│   └── bipia_text_attacks.json            # Text summarization and prompt hijacking
├── 03_llm_cybersecurity_evals/            # Sourced from meta-llama/PurpleLlama (CyberSecEval)
│   ├── cyberseceval_prompt_injection.json # Standardized frontier LLM injection vectors
│   └── cyberseceval_code_execution.json   # Code interpreter exploit vectors
├── 04_os_command_injections/              # Sourced from PayloadsAllTheThings & SecLists
│   ├── unix_command_injections.txt        # Unix shell command injection patterns
│   ├── command_exec_subshells.txt         # Subshell backticks, pipelines, and command separators
│   └── seclists_command_injection.txt     # Comprehensive commix fuzzing payload vectors
└── 05_path_traversal_and_lfi/             # Sourced from SecLists & PayloadsAllTheThings
    ├── lfi_jhaddix.txt                    # Deep path traversals and null byte evasion
    ├── exotic_encoding_traversals.txt     # 8-deep exotic encodings (testing Layer 2 deobfuscation)
    └── directory_traversals.txt           # Standard directory traversal sequences
```

---

## 🎯 Threat Taxonomy & Security Framework Mapping

Each attack vector in `unified_attack_corpus.json` is mapped to three international security taxonomies:

1. **NIST SP 800-94 & NIST SP 800-53 Control Mappings:**
   - `SEC-CMD-INJECT-01`: OS Command Injection Protection (SI-10 Information Input Validation)
   - `SEC-TRAV-01` / `SEC-LFI-01`: Canonical Path & Boundary Protection (AC-3 Access Enforcement)
   - `SEC-EXFIL-02`: Multi-Turn Data Exfiltration Interception (SC-7 Boundary Protection)
   - `SEC-DEOBF-01..04`: Multi-Pass Obfuscation Resilience (SI-3 Malicious Code Protection)
   - `SEC-INDIRECT-INJECT`: Indirect Prompt Injection Defenses

2. **MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems):**
   - **`AML.T0051`**: LLM Prompt Injection
   - **`AML.T0054`**: LLM Jailbreak & Evasion Techniques
   - **`AML.T0043`**: Exfiltration via AI Tool Calling
   - **`AML.T0024`**: Execution via Autonomous Tool Calling

3. **OWASP Top 10 for Large Language Model Applications (2025):**
   - **`LLM01`**: Direct & Indirect Prompt Injection
   - **`LLM02`**: Sensitive Information Disclosure
   - **`LLM07`**: Insecure Plugin & Tool Design
   - **`LLM08`**: Excessive Agency & Unauthorized Execution

---

## 🚀 Running Evaluation Benchmarks

To execute the automated evaluation harness against the unified 130-vector benchmark suite:

```bash
# Run against the unified 130-case benchmark suite
python3 module7-evaluation/harness.py --corpus module6-adversarial/attack_suite/unified_attack_corpus.json
```

Or to resync and redownload the latest datasets from upstream repositories:

```bash
./module6-adversarial/attack_suite/download_benchmarks.sh
```
