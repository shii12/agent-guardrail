import re
import subprocess
import json
import argparse
import sys
from datetime import datetime

LOG_FILE = "guardrail_audit.log"

DANGEROUS_PATTERNS = [
    r"rm\s+-rf",
    r"del\s+/s",
    r"\.env",
    r"format\s+[a-z]:",
    r"shutdown",
]

PROMPT_PATTERNS = [
    r"sudo",
    r"chmod",
    r"pip\s+install",
    r"npm\s+install",
]

def log_event(cmd: str, status: str, risk: str, reason: str):
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "command": cmd,
        "status": status,
        "risk_level": risk,
        "reason": reason
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def inspect_command(command: str) -> dict:
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return {
                "status": "BLOCK",
                "risk_level": "CRITICAL",
                "reason": f"Forbidden pattern detected: '{pattern}'"
            }
    
    for pattern in PROMPT_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return {
                "status": "PROMPT",
                "risk_level": "MEDIUM",
                "reason": f"System alteration detected: '{pattern}'"
            }

    return {
        "status": "ALLOW",
        "risk_level": "LOW",
        "reason": "Safe command."
    }

def run_guarded_command(command: str):
    print(f"\n🛡️ [AGENT-GUARDRAIL INSPECING]: {command}")
    analysis = inspect_command(command)
    status = analysis["status"]
    
    if status == "BLOCK":
        print(f"⛔ [BLOCKED]: {analysis['reason']}")
        log_event(command, "BLOCK", analysis["risk_level"], analysis["reason"])
        sys.exit(1)

    if status == "PROMPT":
        print(f"⚠️  [WARNING]: {analysis['reason']}")
        user_choice = input("👉 Allow execution? (y/N): ").strip().lower()
        if user_choice != 'y':
            print("❌ [CANCELLED]: User rejected command execution.")
            log_event(command, "REJECTED_BY_USER", analysis["risk_level"], "User rejected")
            sys.exit(1)
        status = "APPROVED_BY_USER"

    print("✅ [EXECUTING]: Executing command safely...")
    log_event(command, status, analysis["risk_level"], analysis["reason"])
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.stdout:
            print(f"\n--- [STDOUT] ---\n{result.stdout.strip()}")
        if result.stderr:
            print(f"\n--- [STDERR] ---\n{result.stderr.strip()}")
    except Exception as e:
        print(f"❌ [EXECUTION ERROR]: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent-Guardrail: Local Security & Inspection Layer for AI Agents")
    parser.add_argument("command", type=str, help="Command requested by AI Agent")
    args = parser.parse_args()

    run_guarded_command(args.command)