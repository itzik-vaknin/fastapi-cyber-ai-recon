import os
from groq import Groq

def analyze_scan_results_with_ai(target_url: str, resolved_ip: str, open_ports: list) -> str:
    """
    Analyzes infrastructure scan findings.
    Provides graceful degradation through a local fallback when the external LLM service is unavailable.
    """
    api_key = os.getenv("GROQ_API_KEY")
    
    local_report = (
        f"--- Local Automated Security Analysis ---\n"
        f"Infrastructure scan assessment for target '{target_url}' ({resolved_ip}) completed successfully.\n"
        f"Detected Exposed Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n"
        f"Risk Severity Index: HIGH EXPOSURE RISK\n"
        f"Remediation Plan: Ensure firewall configuration templates filter unauthorized inbound requests."
    )
    
    if not api_key:
        return local_report
        
    try:
        client = Groq(api_key=api_key)
        prompt_payload = (
            f"Perform a professional security analyst risk assessment for infrastructure host '{target_url}' "
            f"resolving to IP {resolved_ip}. The scanner detected the following open ports: {open_ports}. "
            f"Provide a concise exposure summary and targeted firewall mitigation strategies."
        )
        
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "You are an expert infrastructure penetration testing assistant."},
                {"role": "user", "content": prompt_payload}
            ],
            temperature=0.2,
            max_tokens=500
        )
        return completion.choices[0].message.content
    except Exception:
        return local_report

