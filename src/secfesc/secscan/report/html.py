"""HTML export for audit reports."""

from __future__ import annotations

from secfesc.secscan.core.engine import AuditReport

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecScan Audit Report - {hostname}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        h1 {{ margin: 0 0 10px 0; }}
        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .meta-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 4px;
        }}
        .meta-label {{
            font-size: 0.85em;
            color: #aaa;
            text-transform: uppercase;
        }}
        .meta-value {{
            font-size: 1.2em;
            font-weight: bold;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-number {{
            font-size: 2em;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .findings {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid;
            background: #fafafa;
        }}
        .finding.warning {{ border-color: #ffc107; }}
        .finding.error {{ border-color: #dc3545; }}
        .finding.note {{ border-color: #17a2b8; }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity.warning {{ background: #ffc107; color: #000; }}
        .severity.error {{ background: #dc3545; color: #fff; }}
        .severity.note {{ background: #17a2b8; color: #fff; }}
        .category {{
            font-size: 0.8em;
            color: #666;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SecScan Audit Report</h1>
        <p>Generated on {start_time}</p>
        <div class="meta">
            <div class="meta-item">
                <div class="meta-label">Hostname</div>
                <div class="meta-value">{hostname}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Root Access</div>
                <div class="meta-value">{is_root}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Duration</div>
                <div class="meta-value">{duration}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Version</div>
                <div class="meta-value">secscan 1.6.0</div>
            </div>
        </div>
    </div>

    <div class="summary">
        <div class="summary-card">
            <div class="summary-number">{category_count}</div>
            <div>Categories</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">{finding_count}</div>
            <div>Findings</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">{warning_count}</div>
            <div>Warnings</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">{error_count}</div>
            <div>Errors</div>
        </div>
    </div>

    <div class="findings">
        <h2>Findings</h2>
        {findings_html}
    </div>
</body>
</html>
"""


def export_html(report: AuditReport, output_file: str | None = None) -> str:
    """Export audit report as HTML.

    Args:
        report: The audit report to export
        output_file: Optional file path to write to

    Returns:
        HTML string
    """
    from collections import Counter

    severities = Counter(f.severity for f in report.findings)
    warning_count = severities.get("warning", 0) + severities.get("medium", 0)
    error_count = severities.get("error", 0) + severities.get("high", 0)

    findings_html = ""
    for f in report.findings:
        severity_class = (
            "error"
            if f.severity in ("error", "high")
            else "warning"
            if f.severity in ("warning", "medium")
            else "note"
        )
        findings_html += f"""
        <div class="finding {severity_class}">
            <span class="severity {severity_class}">{f.severity}</span>
            <span class="category">{f.category}</span>
            <h3>{f.title}</h3>
            <p>{f.description}</p>
            <p><strong>Solution:</strong> {f.solution}</p>
        </div>
        """

    if not findings_html:
        findings_html = "<p>No findings.</p>"

    duration_str = f"{report.duration:.2f}s" if report.duration else "N/A"
    start_str = report.start_time.strftime("%Y-%m-%d %H:%M:%S")

    html = HTML_TEMPLATE.format(
        hostname=report.hostname,
        start_time=start_str,
        is_root="Yes" if report.is_root else "No",
        duration=duration_str,
        category_count=len(report.categories),
        finding_count=len(report.findings),
        warning_count=warning_count,
        error_count=error_count,
        findings_html=findings_html,
    )

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

    return html
