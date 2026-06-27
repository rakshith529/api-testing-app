import time
from collections import Counter
from typing import Any, Dict

from api_tester.requester import send_api_request


def run_rate_limit_test(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    count: int = 20,
    delay_ms: int = 100,
) -> Dict[str, Any]:
    count = max(1, min(count, 200))
    delay_ms = max(0, min(delay_ms, 5000))

    status_counts = Counter()
    timings = []
    saw_429 = False
    errors = 0
    last_status = None

    for _ in range(count):
        response = send_api_request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_body={},
            auth_token="",
            timeout_sec=10,
        )

        status_code = response.get("status_code")
        last_status = status_code

        if status_code is None:
            errors += 1
            status_counts["error"] += 1
        else:
            status_counts[str(status_code)] += 1
            if status_code == 429:
                saw_429 = True

        if response.get("response_time_ms") is not None:
            timings.append(float(response["response_time_ms"]))

        time.sleep(delay_ms / 1000)

    findings = []
    if saw_429:
        findings.append("Rate limiting observed (HTTP 429 seen)")
    else:
        findings.append("No HTTP 429 observed; endpoint may not enforce rate limiting")

    if errors > 0:
        findings.append(f"{errors} requests failed (network or validation issue)")

    if len(status_counts) > 3:
        findings.append("Inconsistent response pattern under load")

    avg_response_time = round(sum(timings) / len(timings), 2) if timings else None

    return {
        "total_requests": count,
        "status_counts": dict(status_counts),
        "saw_429": saw_429,
        "errors": errors,
        "avg_response_time_ms": avg_response_time,
        "last_status": last_status,
        "findings": findings,
    }
