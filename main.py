import asyncio
import socket
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

# Import our custom professional enterprise modules
from database.database import init_db, get_db, ScanResult
from core.security import verify_token, check_ssrf_mitigation
from ai.groq_agent import analyze_scan_results_with_ai

# Initialize FastAPI Application profile setup
app = FastAPI(
    title="Secure FastAPI AI Network Recon Agent",
    description="Production-ready asynchronous cybersecurity scanning system with built-in SSRF protection shields and Groq AI analysis metrics.",
    version="2.0.0"
)

@app.on_event("startup")
def on_startup():
    """
    Triggers database schema initialization on system boot.
    """
    init_db()

async def scan_single_port(ip: str, port: int, timeout: float = 0.5) -> int or None:
    """
    Asynchronously probes a single TCP port using pure socket connection pipes.
    """
    try:
        # Run socket connection logic inside an execution loop timeout filter
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=timeout)
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

@app.post("/api/recon", response_model=dict, tags=["Reconnaissence Engine"])
async def run_network_recon_agent(
    target_url: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Core Security API Route: Sanitizes domains, shields against SSRF, 
    executes multi-port socket scanning loops, logs results, and triggers AI analysis reports.
    """
    # 1. Trigger SSRF firewall check and resolve clean IP metrics
    resolved_ip = check_ssrf_mitigation(target_url)

    # 2. Define top targeted enterprise ports to assess
    target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
    
    # 3. Execute fast parallel asynchronous network scanning tasks
    tasks = [scan_single_port(resolved_ip, port) for port in target_ports]
    scan_outputs = await asyncio.gather(*tasks)
    open_ports = [port for port in scan_outputs if port is not None]

    # 4. Trigger cloud AI exposure risk summary analysis report from Groq Cloud
    ai_report = analyze_scan_results_with_ai(target_url, resolved_ip, open_ports)

    # 5. Persist the execution structure cleanly into the SQLite database history ledger
    db_log = ScanResult(
        target=target_url,
        resolved_ip=resolved_ip,
        open_ports=",".join(map(str, open_ports)),
        ai_report=ai_report
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # 6. Return standard structured outputs to the authenticated client interface
    return {
        "status": "Success",
        "target_host": target_url,
        "resolved_ip": resolved_ip,
        "ports_assessed": len(target_ports),
        "detected_open_ports": open_ports,
        "ai_analyst_report": ai_report,
        "logged_entry_id": db_log.id
    }

