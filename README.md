# 🛡️ Agent-Guardrail

A lightweight, multi-layered local security guardrail and audit logging layer for autonomous AI Agents (OpenClaw, AutoGPT, Custom Agents).

## 🚀 Features
- **Multi-Layer Inspection System:**
  - **Layer 1 (Hard Blacklist):** Instantly blocks destructive commands (`rm -rf`, `.env` access, formatting drives).
  - **Layer 2 (Smart Pattern Detection):** Catches obfuscated or embedded code execution (`python -c`, `exec()`, `eval()`, PowerShell encoding).
  - **Layer 3 (Local Ollama AI Audit):** Optionally queries a local LLM (`llama3` via Ollama) for context-aware safety checks (100% free & offline).
- **Interactive Approval:** Prompts user confirmation (`y/N`) for medium-risk system alterations.
- **Structured Audit Logging:** Automatically records execution history with timestamps into `guardrail_audit.log` in JSON format.

## 📦 Quick Start

```bash
# 1. Run a safe command
python guardrail.py "dir"

# 2. Sensitive file access (Instantly Blocked)
python guardrail.py "type .env"

# 3. Obfuscated code execution (Triggers Warning & Interactive Prompt)
python guardrail.py "python -c \"import os; os.remove('test.txt')\""