"""JSON export for audit reports."""

from __future__ import annotations

import json

from secfesc.secscan.core.engine import AuditReport


def export_json(report: AuditReport, output_file: str | None = None) -> str:
    """Export audit report as JSON.

    Args:
        report: The audit report to export
        output_file: Optional file path to write to (default: stdout)

    Returns:
        JSON string
    """
    data = {
        "hostname": report.hostname,
        "start_time": report.start_time.isoformat(),
        "end_time": report.end_time.isoformat() if report.end_time else None,
        "duration_seconds": report.duration,
        "is_root": report.is_root,
        "categories": [
            {
                "name": cat.name,
                "description": cat.description,
                "check_count": len(cat.checks),
            }
            for cat in report.categories
        ],
        "findings": [
            {
                "category": f.category,
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "description": f.description,
                "solution": f.solution,
                "affected": f.affected,
            }
            for f in report.findings
        ],
        "warnings": report.warnings,
        "summary": {
            "total_categories": len(report.categories),
            "total_findings": len(report.findings),
            "total_warnings": len(report.warnings),
        },
    }

    json_str = json.dumps(data, indent=2, default=str)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
