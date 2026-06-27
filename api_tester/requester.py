import ipaddress
import json
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
]


def _is_private_or_local_host(hostname: str) -> bool:
    """
    Basic SSRF defense for intern labs:
    We block localhost and private/internal IP ranges.
    This helps prevent the toolkit from probing local services by mistake.
    """
    host_lower = hostname.lower().strip()
    if host_lower in {"localhost", "127.0.0.1", "::1"}:
        return True

    if host_lower.endswith(".local"):
        return True

    try:
        ip_obj = ipaddress.ip_address(host_lower)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
    except ValueError:
        pass

    try:
        resolved_ips = socket.gethostbyname_ex(host_lower)[2]
    except socket.gaierror:
        return False

    for ip_text in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_text)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return True
        except ValueError:
            continue

    return False


def validate_target_url(url: str) -> Tuple[bool, str]:
    if not url:
        return False, "URL is required"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http:// and https:// URLs are allowed"

    if not parsed.netloc:
        return False, "Invalid URL"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL hostname could not be parsed"

    if _is_private_or_local_host(hostname):
        return False, "Blocked by SSRF safety rule: local/private/internal target"

    return True, "OK"


def send_api_request(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    json_body: Any,
    auth_token: str,
    timeout_sec: int = 10,
) -> Dict[str, Any]:
    is_valid, message = validate_target_url(url)
    if not is_valid:
        return {
            "method": method,
            "url": url,
            "error": message,
            "status_code": None,
            "response_time_ms": None,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
        }

    request_headers = dict(headers or {})
    if auth_token:
        request_headers.setdefault("Authorization", f"Bearer {auth_token}")

    if isinstance(json_body, dict) and json_body:
        request_headers.setdefault("Content-Type", "application/json")

    start = time.perf_counter()
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=request_headers,
            params=params,
            json=json_body if method in {"POST", "PUT", "PATCH", "DELETE"} else None,
            timeout=max(1, min(timeout_sec, 30)),
            allow_redirects=False,
        )
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        text = resp.text
        try:
            json_obj = resp.json()
            body_text = json.dumps(json_obj, indent=2)
        except ValueError:
            body_text = text

        return {
            "method": method,
            "url": url,
            "status_code": resp.status_code,
            "response_time_ms": elapsed_ms,
            "response_size": len(resp.content),
            "response_headers": dict(resp.headers),
            "response_body": body_text,
            "error": None,
        }
    except requests.Timeout:
        return {
            "method": method,
            "url": url,
            "error": "Request timed out",
            "status_code": None,
            "response_time_ms": None,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
        }
    except requests.RequestException as exc:
        return {
            "method": method,
            "url": url,
            "error": f"Request failed: {exc}",
            "status_code": None,
            "response_time_ms": None,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
        }


def analyze_header_security(response_headers: Dict[str, str], request_headers: Optional[Dict[str, str]] = None) -> List[str]:
    findings: List[str] = []
    normalized = {k.lower(): v for k, v in response_headers.items()}

    for required in SECURITY_HEADERS:
        if required.lower() not in normalized:
            findings.append(f"Missing security header: {required}")

    cors = normalized.get("access-control-allow-origin")
    if cors == "*":
        findings.append("CORS is wide open with '*' (review for sensitive APIs)")

    content_type = normalized.get("content-type", "")
    if content_type and "application/json" not in content_type and "text/" in content_type:
        findings.append("Response content-type is text-based; verify API returns expected JSON when needed")

    if request_headers:
        auth = request_headers.get("Authorization") or request_headers.get("authorization")
        if auth and not auth.lower().startswith(("bearer ", "basic ")):
            findings.append("Authorization header has uncommon format; verify token scheme")

    return findings


def analyze_response_content(response_body: str, status_code: Optional[int]) -> List[str]:
    findings: List[str] = []
    body_lower = (response_body or "").lower()

    if status_code and status_code >= 500:
        findings.append("Server-side error (5xx) observed")

    sensitive_patterns = {
        "possible sql error": r"sql syntax|mysql|postgresql|sqlite error|odbc",
        "possible stack trace": r"traceback \(most recent call last\)|exception in thread|stack trace",
        "possible credential leak": r"api[_-]?key|secret|password|token",
        "debug indicator": r"debug=true|werkzeug debugger|development server",
    }

    for label, pattern in sensitive_patterns.items():
        if re.search(pattern, body_lower, re.IGNORECASE):
            findings.append(f"{label} detected in response body")

    if len(response_body or "") > 200000:
        findings.append("Large response body detected; verify unnecessary data exposure")

    return findings
