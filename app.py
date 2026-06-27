import json
import os
import sqlite3
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from api_tester.fuzzing import run_parameter_fuzzing
from api_tester.jwt_analyzer import analyze_jwt
from api_tester.rate_limit import run_rate_limit_test
from api_tester.reporter import build_html_report, build_json_report
from api_tester.requester import analyze_header_security, analyze_response_content, send_api_request


BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "database"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = DB_DIR / "toolkit.db"

DB_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

# Lightweight per-IP limiter to avoid accidental abuse of this educational tool.
REQUEST_WINDOW_SECONDS = 60
REQUEST_LIMIT_PER_WINDOW = 120
recent_requests: defaultdict[str, deque] = defaultdict(deque)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            headers TEXT,
            params TEXT,
            body TEXT,
            auth_token TEXT,
            status_code INTEGER,
            response_time_ms REAL,
            response_size INTEGER,
            response_headers TEXT,
            response_body TEXT,
            findings TEXT,
            category TEXT DEFAULT 'manual',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_format TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()


@app.before_request
def local_rate_guard() -> Optional[str]:
    """
    Educational safety guard:
    This tool can generate many outbound requests while testing APIs.
    We limit inbound usage per client IP so interns cannot accidentally flood
    this local app while learning.
    """
    client_ip = request.remote_addr or "unknown"
    now = time.time()
    bucket = recent_requests[client_ip]

    while bucket and (now - bucket[0] > REQUEST_WINDOW_SECONDS):
        bucket.popleft()

    if len(bucket) >= REQUEST_LIMIT_PER_WINDOW:
        return "Too many requests to this toolkit. Please wait a minute.", 429

    bucket.append(now)
    return None


def parse_json_field(raw_text: str, default: Any) -> Any:
    if not raw_text or not raw_text.strip():
        return default
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        raise ValueError("Malformed JSON detected. Please provide valid JSON.")


def save_test_result(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    body: Any,
    auth_token: str,
    status_code: Optional[int],
    response_time_ms: Optional[float],
    response_size: Optional[int],
    response_headers: Dict[str, Any],
    response_body: str,
    findings: List[str],
    category: str = "manual",
) -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO tests (
            method, url, headers, params, body, auth_token, status_code,
            response_time_ms, response_size, response_headers, response_body, findings, category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            method,
            url,
            json.dumps(headers),
            json.dumps(params),
            json.dumps(body),
            auth_token,
            status_code,
            response_time_ms,
            response_size,
            json.dumps(response_headers),
            response_body,
            json.dumps(findings),
            category,
        ),
    )
    conn.commit()
    test_id = cur.lastrowid
    conn.close()
    return int(test_id)


@app.route("/")
def index():
    conn = get_db_connection()

    recent = conn.execute(
        "SELECT id, method, url, status_code, response_time_ms, category, created_at FROM tests ORDER BY id DESC LIMIT 10"
    ).fetchall()

    rows = conn.execute("SELECT url, status_code, findings FROM tests").fetchall()
    conn.close()

    endpoint_count = Counter()
    status_buckets = Counter()
    findings_count = 0

    for row in rows:
        endpoint_count[row["url"]] += 1
        status = row["status_code"]
        if status is None:
            status_buckets["No Response"] += 1
        elif status >= 500:
            status_buckets["5xx"] += 1
        elif status >= 400:
            status_buckets["4xx"] += 1
        elif status >= 300:
            status_buckets["3xx"] += 1
        else:
            status_buckets["2xx"] += 1

        try:
            parsed = json.loads(row["findings"] or "[]")
            findings_count += len(parsed)
        except json.JSONDecodeError:
            pass

    return render_template(
        "index.html",
        recent=recent,
        total_tests=len(rows),
        findings_count=findings_count,
        top_endpoints=endpoint_count.most_common(5),
        status_buckets=dict(status_buckets),
    )


@app.route("/tester", methods=["GET", "POST"])
def tester():
    if request.method == "GET":
        return render_template("tester.html")

    method = request.form.get("method", "GET").upper()
    url = request.form.get("url", "").strip()
    auth_token = request.form.get("auth_token", "").strip()
    timeout_sec = int(request.form.get("timeout_sec", "10"))

    try:
        headers = parse_json_field(request.form.get("headers", "{}"), {})
        params = parse_json_field(request.form.get("params", "{}"), {})
        body = parse_json_field(request.form.get("json_body", "{}"), {})
    except ValueError as exc:
        flash(str(exc), "danger")
        return render_template("tester.html")

    result = send_api_request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json_body=body,
        auth_token=auth_token,
        timeout_sec=timeout_sec,
    )

    findings = []
    findings.extend(analyze_header_security(result.get("response_headers", {}), headers))
    findings.extend(analyze_response_content(result.get("response_body", ""), result.get("status_code")))

    test_id = save_test_result(
        method=method,
        url=url,
        headers=headers,
        params=params,
        body=body,
        auth_token=auth_token,
        status_code=result.get("status_code"),
        response_time_ms=result.get("response_time_ms"),
        response_size=result.get("response_size"),
        response_headers=result.get("response_headers", {}),
        response_body=result.get("response_body", ""),
        findings=findings,
        category="manual",
    )

    return render_template("results.html", result=result, findings=findings, test_id=test_id)


@app.route("/history")
def history():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, method, url, status_code, response_time_ms, category, created_at FROM tests ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return render_template("reports.html", tests=rows)


@app.route("/history/<int:test_id>")
def history_item(test_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    conn.close()

    if not row:
        flash("Test not found", "warning")
        return redirect(url_for("history"))

    result = {
        "method": row["method"],
        "url": row["url"],
        "status_code": row["status_code"],
        "response_time_ms": row["response_time_ms"],
        "response_size": row["response_size"],
        "response_headers": json.loads(row["response_headers"] or "{}"),
        "response_body": row["response_body"] or "",
    }
    findings = json.loads(row["findings"] or "[]")
    return render_template("results.html", result=result, findings=findings, test_id=row["id"])


@app.route("/rerun/<int:test_id>")
def rerun(test_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    conn.close()

    if not row:
        flash("Cannot rerun: test not found", "danger")
        return redirect(url_for("history"))

    headers = json.loads(row["headers"] or "{}")
    params = json.loads(row["params"] or "{}")
    body = json.loads(row["body"] or "{}")

    result = send_api_request(
        method=row["method"],
        url=row["url"],
        headers=headers,
        params=params,
        json_body=body,
        auth_token=row["auth_token"] or "",
        timeout_sec=10,
    )

    findings = []
    findings.extend(analyze_header_security(result.get("response_headers", {}), headers))
    findings.extend(analyze_response_content(result.get("response_body", ""), result.get("status_code")))

    new_id = save_test_result(
        method=row["method"],
        url=row["url"],
        headers=headers,
        params=params,
        body=body,
        auth_token=row["auth_token"] or "",
        status_code=result.get("status_code"),
        response_time_ms=result.get("response_time_ms"),
        response_size=result.get("response_size"),
        response_headers=result.get("response_headers", {}),
        response_body=result.get("response_body", ""),
        findings=findings,
        category="rerun",
    )

    return render_template("results.html", result=result, findings=findings, test_id=new_id)


@app.route("/jwt", methods=["GET", "POST"])
def jwt_tools():
    analysis = None
    token = ""

    if request.method == "POST":
        token = request.form.get("jwt_token", "").strip()
        analysis = analyze_jwt(token)

    return render_template("jwt.html", analysis=analysis, token=token)


@app.route("/fuzzing", methods=["GET", "POST"])
def fuzzing():
    summary = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        method = request.form.get("method", "GET").upper()
        target_param = request.form.get("target_param", "input").strip()
        base_value = request.form.get("base_value", "test").strip()

        try:
            headers = parse_json_field(request.form.get("headers", "{}"), {})
            params = parse_json_field(request.form.get("params", "{}"), {})
            body = parse_json_field(request.form.get("json_body", "{}"), {})
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("fuzzing.html", summary=summary)

        fuzz_results = run_parameter_fuzzing(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_body=body,
            target_param=target_param,
            base_value=base_value,
        )

        suspicious = 0
        for item in fuzz_results:
            findings = item.get("findings", [])
            if findings:
                suspicious += 1
            save_test_result(
                method=method,
                url=url,
                headers=headers,
                params=item.get("used_params", params),
                body=item.get("used_body", body),
                auth_token="",
                status_code=item.get("status_code"),
                response_time_ms=item.get("response_time_ms"),
                response_size=item.get("response_size"),
                response_headers=item.get("response_headers", {}),
                response_body=item.get("response_body", ""),
                findings=findings,
                category="fuzzing",
            )

        summary = {
            "total_cases": len(fuzz_results),
            "suspicious_cases": suspicious,
            "results": fuzz_results,
        }

    return render_template("fuzzing.html", summary=summary)


@app.route("/rate-limit", methods=["GET", "POST"])
def rate_limit():
    summary = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        method = request.form.get("method", "GET").upper()
        count = int(request.form.get("count", "20"))
        delay_ms = int(request.form.get("delay_ms", "100"))

        try:
            headers = parse_json_field(request.form.get("headers", "{}"), {})
            params = parse_json_field(request.form.get("params", "{}"), {})
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("rate_limit.html", summary=summary)

        summary = run_rate_limit_test(
            method=method,
            url=url,
            headers=headers,
            params=params,
            count=count,
            delay_ms=delay_ms,
        )

        findings = summary.get("findings", [])
        save_test_result(
            method=method,
            url=url,
            headers=headers,
            params=params,
            body={},
            auth_token="",
            status_code=summary.get("last_status"),
            response_time_ms=summary.get("avg_response_time_ms"),
            response_size=0,
            response_headers={},
            response_body=json.dumps(summary.get("status_counts", {}), indent=2),
            findings=findings,
            category="rate-limit",
        )

    return render_template("rate_limit.html", summary=summary)


@app.route("/reports/generate/<string:fmt>")
def generate_report(fmt: str):
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM tests ORDER BY id DESC LIMIT 300").fetchall()
    conn.close()

    tests = []
    for row in rows:
        tests.append(
            {
                "id": row["id"],
                "method": row["method"],
                "url": row["url"],
                "status_code": row["status_code"],
                "response_time_ms": row["response_time_ms"],
                "category": row["category"],
                "created_at": row["created_at"],
                "findings": json.loads(row["findings"] or "[]"),
            }
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "html":
        file_path = REPORTS_DIR / f"security_report_{timestamp}.html"
        content = build_html_report(tests)
        file_path.write_text(content, encoding="utf-8")
    elif fmt == "json":
        file_path = REPORTS_DIR / f"security_report_{timestamp}.json"
        content = build_json_report(tests)
        file_path.write_text(content, encoding="utf-8")
    else:
        flash("Unsupported report format", "danger")
        return redirect(url_for("history"))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO reports (report_format, file_path) VALUES (?, ?)",
        (fmt, str(file_path)),
    )
    conn.commit()
    conn.close()

    return send_file(file_path, as_attachment=True)


@app.route("/reports")
def report_history():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("report_history.html", reports=rows)


@app.route("/api/health")
def health():
    return {"ok": True, "app": "api-security-toolkit"}


if __name__ == "__main__":
    init_db()
    # host=127.0.0.1 keeps the app local-only for safer learning usage.
    app.run(host="127.0.0.1", port=5000, debug=True)
