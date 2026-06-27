from typing import Any, Dict, List

from api_tester.requester import analyze_response_content, send_api_request


def default_fuzz_payloads(base_value: str) -> List[str]:
    """
    A beginner-friendly payload set used to teach how unexpected input can
    trigger unusual API behavior.
    """
    return [
        base_value,
        "",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../etc/passwd",
        "A" * 512,
        "null",
        "{}",
        "[]",
        "😀",
    ]


def run_parameter_fuzzing(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    json_body: Any,
    target_param: str,
    base_value: str,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for payload in default_fuzz_payloads(base_value):
        used_params = dict(params or {})
        used_body = dict(json_body or {}) if isinstance(json_body, dict) else {}

        # For GET/DELETE, fuzz query params. For POST/PUT, fuzz JSON body.
        if method in {"GET", "DELETE"}:
            used_params[target_param] = payload
        else:
            used_body[target_param] = payload

        response = send_api_request(
            method=method,
            url=url,
            headers=headers,
            params=used_params,
            json_body=used_body,
            auth_token="",
            timeout_sec=10,
        )

        findings = analyze_response_content(response.get("response_body", ""), response.get("status_code"))
        if response.get("status_code") and response["status_code"] >= 500:
            findings.append("Fuzz case triggered server error")

        results.append(
            {
                "payload": payload,
                "status_code": response.get("status_code"),
                "response_time_ms": response.get("response_time_ms"),
                "response_size": response.get("response_size"),
                "response_headers": response.get("response_headers", {}),
                "response_body": response.get("response_body", ""),
                "used_params": used_params,
                "used_body": used_body,
                "findings": findings,
                "error": response.get("error"),
            }
        )

    return results
