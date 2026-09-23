import os
import ipaddress
import socket

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security_bearer = HTTPBearer()

API_TOKEN = os.getenv("API_BEARER_TOKEN")


def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
):
    """Validate the incoming Bearer token against the environment variable."""
    if not API_TOKEN or credentials.credentials != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing credentials",
        )

    return credentials.credentials


def check_ssrf_mitigation(target_url: str) -> str:
    """Resolve the target and block loopback/private IP addresses."""
    try:
        resolved_ip = socket.gethostbyname(target_url)
        ip_obj = ipaddress.ip_address(resolved_ip)

        if ip_obj.is_loopback or ip_obj.is_private:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: target resolves to a protected network.",
            )

        return resolved_ip

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to resolve target host.",
        )

