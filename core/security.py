import os
import ipaddress
import socket

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security_bearer = HTTPBearer()


def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
):
    """Validate the incoming Bearer token against the environment variable."""
    api_token = os.getenv("API_BEARER_TOKEN")

    if not api_token or credentials.credentials != api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing credentials",
        )

    return credentials.credentials


def check_ssrf_mitigation(target_url: str) -> str:
    """Resolve the target and block loopback, private, link-local, and reserved IP addresses."""
    try:
        resolved_ip = socket.gethostbyname(target_url)
        ip_obj = ipaddress.ip_address(resolved_ip)

        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target resolves to a restricted IP address",
            )

        return resolved_ip

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to resolve target host.",
        )

