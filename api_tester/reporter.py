import json
from datetime import datetime
from html import escape
from typing import Any, Dict, List


def build_json_report(tests: List[Dict[str, Any]]) -> str:
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_tests": len(tests),
        "tests": tests,
    }
    return json.dumps(report, indent=2)


def build_html_report(tests: List[Dict[str, Any]]) -> str:
    rows = []
    for t in tests:
        findings = t.get("findings", [])
        findings_html = "<br>".join(escape(f) for f in findings) if findings else "-"
        rows.append(
            f"""
            <tr>
              <td>{escape(str(t.get('id')))}</td>
              <td>{escape(t.get('created_at', '-'))}</td>
              <td>{escape(t.get('category', '-'))}</td>
              <td>{escape(t.get('method', '-'))}</td>
              <td>{escape(t.get('url', '-'))}</td>
              <td>{escape(str(t.get('status_code', '-')))}</td>
              <td>{escape(str(t.get('response_time_ms', '-')))} ms</td>
              <td>{findings_html}</td>
            </tr>
            """
        )

    return f"""
<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <title>API Security Testing Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; padding: 20px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f2f2f2; }}
  </style>
</head>
<body>
  <h1>API Security Testing Report</h1>
  <p><strong>Generated:</strong> {escape(datetime.utcnow().isoformat() + 'Z')}</p>
  <p><strong>Total Tests:</strong> {len(tests)}</p>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Timestamp</th><th>Category</th><th>Method</th><th>URL</th>
        <th>Status</th><th>Response Time</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
