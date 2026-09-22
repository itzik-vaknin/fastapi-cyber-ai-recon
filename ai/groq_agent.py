import os
from fastapi import HTTPException, status
from groq import Groq

def analyze_scan_results_with_ai(target: str, resolved_ip: str, open_ports: list) -> str:
    """
    Triggers the Groq AI Llama-3 Cloud engine to execute a real-time 
    cybersecurity exposure assessment based on technical metrics.
    """
    # Fetch the secret API Key safely from the system environment memory mapping
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "API Key missing. Please set GROQ_API_KEY environment variable to enable AI risk analysis reports."

    try:
        # Initialize the official Groq client pipeline
        client = Groq(api_key=api_key)

        # Structure a clear, hyper-focused system prompt block for the model
        prompt = (
            f"You are a Senior Network Security Analyst. Analyze this infrastructure scan result:\n"
            f"- Target Host Name: {target}\n"
            f"- Resolved Target IP: {resolved_ip}\n"
            f"- Detected Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n\n"
            f"Provide a concise, professional executive risk analysis summary report in clear English. "
            f"Detail potential vulnerabilities for open ports and practical remediation tasks."
        )

        # Execute a low-latency chat completion call to the Llama-3-8b infrastructure
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=500
        )
        return completion.choices[0].message.content

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"❌ AI Infrastructure Error: Failed to fetch report from Groq Cloud cloud broker: {str(e)}"
        )
