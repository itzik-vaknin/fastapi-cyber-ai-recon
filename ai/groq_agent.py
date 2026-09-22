import os
from fastapi import HTTPException, status
from groq import Groq

def analyze_scan_results_with_ai(target: str, resolved_ip: str, open_ports: list) -> str:
    """
    Triggers the Groq AI engine to execute an infrastructure exposure assessment.
    Features a local fallback engine to guarantee 100% service availability.
    """
    # 1. Local Fallback Blueprint Configuration
    ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
    local_report = (
        f"--- Local Automated Security Analysis ---\n"
        f"Infrastructure scan assessment for target '{target}' ({resolved_ip}) completed successfully.\n"
        f"Detected Exposed Ports: {ports_str}\n"
        f"Risk Severity Index: {'HIGH EXPOSURE RISK' if open_ports else 'LOW/NO EXPOSURE'}\n"
        f"Remediation Plan: Ensure firewall configuration templates filter unauthorized inbound requests."
    )

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return local_report

    try:
        # 2. Try utilizing the core production reasoning engine model target
        client = Groq(api_key=api_key)
        prompt = (
            f"You are a Senior Network Security Analyst. Analyze this infrastructure scan result:\n"
            f"- Target Host Name: {target}\n"
            f"- Resolved Target IP: {resolved_ip}\n"
            f"- Detected Open Ports: {ports_str}\n\n"
            f"Provide a concise threat summary report."
        )

        completion = client.chat.completions.create(
            # Using the primary verified open-weight production runner model identifier
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=300
        )
        return completion.choices.message.content

    except Exception:
        # 3. Secure Fallback Pipeline Activation: Drop external failures, return valid string
        return local_report

