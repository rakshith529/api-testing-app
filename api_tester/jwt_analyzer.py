import base64
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def analyze_jwt(token: str) -> Dict[str, Any]:
    """
    JWT educational analyzer (no signature verification).
    We decode token parts to show interns what header/payload contain,
    and why expiration + algorithm selection matter.
    """
    token = (token or "").strip()
    if not token:
        return {"valid": False, "error": "Token is empty"}

    parts = token.split(".")
    if len(parts) != 3:
        return {"valid": False, "error": "JWT must contain 3 parts separated by '.'"}

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
        return {"valid": False, "error": f"Failed to decode JWT: {exc}"}

    now = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")

    exp_readable = None
    is_expired = None
    if isinstance(exp, (int, float)):
        exp_readable = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        is_expired = now > int(exp)

    iat_readable = None
    if isinstance(iat, (int, float)):
        iat_readable = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()

    alg = header.get("alg")
    alg_warning = None
    if alg == "none":
        alg_warning = "Algorithm 'none' is risky and usually should not be accepted by APIs"

    return {
        "valid": True,
        "header": header,
        "payload": payload,
        "signature_preview": signature_b64[:16] + "..." if signature_b64 else "",
        "algorithm": alg,
        "algorithm_warning": alg_warning,
        "expires_at": exp_readable,
        "issued_at": iat_readable,
        "is_expired": is_expired,
    }
