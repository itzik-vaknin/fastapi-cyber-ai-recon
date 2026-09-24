import os
import asyncio

from dotenv import load_dotenv

# Load environment variables before importing local modules.
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database.database import init_db, get_db, ScanResult
from core.security import verify_token, check_ssrf_mitigation
from ai.groq_agent import analyze_scan_results_with_ai

# Global target configurations
DEFAULT_PORTS = [80, 443, 22, 21, 8080]

app = FastAPI(
    title="Secure FastAPI Network Recon Agent",
    description="Asynchronous cybersecurity infrastructure scanning framework.",
    version="2.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/token", tags=["Authentication Gateway"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """Authenticate using credentials stored in environment variables."""

    env_username = os.getenv("ADMIN_USERNAME")
    env_password = os.getenv("ADMIN_PASSWORD")
    env_token = os.getenv("API_BEARER_TOKEN")

    if not env_username or not env_password or not env_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication configuration missing.",
        )

    if (
        form_data.username == env_username
        and form_data.password == env_password
    ):
        return {
            "access_token": env_token,
            "token_type": "bearer",
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
    )


async def scan_single_port(
    ip: str,
    port: int,
    timeout: float = 0.5,
) -> int | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        writer.close()
        await writer.wait_closed()

        return port

    except (
        asyncio.TimeoutError,
        ConnectionRefusedError,
        OSError,
    ):
        return None


@app.post(
    "/api/recon",
    response_model=dict,
    tags=["Reconnaissance Engine"],
)
async def run_network_recon_agent(
    target_url: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token),
):
    resolved_ip = check_ssrf_mitigation(target_url)

    tasks = [
        scan_single_port(resolved_ip, port)
        for port in DEFAULT_PORTS
    ]

    scan_outputs = await asyncio.gather(*tasks)

    open_ports = [
        port
        for port in scan_outputs
        if port is not None
    ]

    ai_report = analyze_scan_results_with_ai(
        target_url,
        resolved_ip,
        open_ports,
    )

    db_log = ScanResult(
        target=target_url,
        resolved_ip=resolved_ip,
        open_ports=",".join(map(str, open_ports)),
        ai_report=ai_report,
    )

    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "status": "Success",
        "target_host": target_url,
        "resolved_ip": resolved_ip,
        "ports_assessed": len(DEFAULT_PORTS),
        "detected_open_ports": open_ports,
        "ai_analyst_report": ai_report,
        "logged_entry_id": db_log.id,
    }

