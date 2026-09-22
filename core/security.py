import socket
import ipaddress
from fastapi import HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer

# Hardcoded single admin token for the MVP security gateway profile
API_TOKEN = "cyber_recon_agent_secret_token_2026"

# Router authentication protocol instantiation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_token(token: str = Security(oauth2_scheme)) -> str:
    """
    Validates the inbound Bearer Token against the authorization scheme gates.
    """
    if token != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid security token or unauthorized access parameters",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

def check_ssrf_mitigation(target_host: str) -> str:
    """
    SSRF Firewall Core Engine: Resolves inbound domain hostnames 
    and systematically drops requests targeting private or internal networks.
    """
    try:
        # Resolve target to an active IP address using clean DNS sockets
        resolved_ip = socket.gethostbyname(target_host)
        ip_obj = ipaddress.ip_address(resolved_ip)

        # Drop requests targeting local loopback or private ranges (RFC 1918)
        if ip_obj.is_loopback or ip_obj.is_private:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="❌ Security Block (SSRF): Scanning internal or private network IP scopes is strictly forbidden!"
            )
        return resolved_ip

    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="❌ Resolution Error: Invalid host scope target or DNS failure"
        )
    except HTTPException:
        raise  # Bubble up the 403 SSRF security alert directly
