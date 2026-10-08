import re
import subprocess
import json
import argparse
import sys
import urllib.request
from datetime import datetime

LOG_FILE = "guardrail_audit.log"

# 1. Các mẫu cấm tuyệt đối (Blacklist cứng)
DANGEROUS_PATTERNS = [
    r"rm\s+-rf",
    r"del\s+/s",
    r"\.env",
    r"format\s+[a-z]:",
    r"shutdown",
    r"base64",                 # Ngụy trang mã hóa lệnh
    r"powershell.*-enc",       # PowerShell mã hóa lệnh ngầm
]

# 2. Các mẫu phát hiện hành vi thực thi code ẩn (Code Execution)
SUSPICIOUS_PATTERNS = [
    r"python\s+-c",            # Chạy lệnh python trực tiếp từ dòng lệnh
    r"exec\(",
    r"eval\(",
    r"os\.remove",
    r"shutil\.rmtree",
    r"sudo",
    r"pip\s+install",
]

def check_with_local_ollama(command: str) -> dict | None:
    """Gọi Ollama local (miễn phí 100%) để AI đánh giá nếu Ollama đang chạy trên máy"""
    url = "http://localhost:11434/api/generate"
    prompt = f"""You are a security audit system. Analyze this command requested by an AI agent: '{command}'.
Is it dangerous to the system or user privacy?
Reply with ONLY a JSON object: {{"is_dangerous": true/false, "reason": "short explanation"}}"""
    
    payload = json.dumps({"model": "llama3", "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            res_data = json.loads(response.read().decode())
            ai_res = json.loads(res_data.get("response", "{}"))
            if ai_res.get("is_dangerous"):
                return {
                    "status": "BLOCK",
                    "risk_level": "HIGH",
                    "reason": f"[Ollama AI Guard]: {ai_res.get('reason')}"
                }
    except Exception:
        # Nếu Ollama không bật hoặc chưa cài model, bỏ qua và dùng bộ lọc nội bộ
        pass
    return None

def inspect_command(command: str) -> dict:
    """Kiểm duyệt đa tầng: Hard Rules -> Smart Patterns -> Local AI"""
    # Tầng 1: Mẫu cấm trực tiếp
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return {
                "status": "BLOCK",
                "risk_level": "CRITICAL",
                "reason": f"Forbidden pattern detected: '{pattern}'"
            }
    
    # Tầng 2: Mẫu nghi vấn thực thi code lách luật
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return {
                "status": "PROMPT",
                "risk_level": "MEDIUM",
                "reason": f"Suspicious behavior / code execution detected: '{pattern}'"
            }

    # Tầng 3: Thẩm định qua Ollama AI Local (nếu có sẵn)
    ollama_result = check_with_local_ollama(command)
    if ollama_result:
        return ollama_result

    return {
        "status": "ALLOW",
        "risk_level": "LOW",
        "reason": "Safe command."
    }

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

def run_guarded_command(command: str):
    print(f"\n🛡️ [AGENT-GUARDRAIL v0.3 INSPECTING]: {command}")
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
    parser = argparse.ArgumentParser(description="Agent-Guardrail v0.3: Smart Local Security Layer for AI Agents")
    parser.add_argument("command", type=str, help="Command requested by AI Agent")
    args = parser.parse_args()

    run_guarded_command(args.command)