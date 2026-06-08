"""CSV export for audit reports."""

from __future__ import annotations

import csv
import io

from secfesc.secscan.core.engine import AuditReport


def export_csv(report: AuditReport, output_file: str | None = None) -> str:
    """Export audit report as CSV.

    Args:
        report: The audit report to export
        output_file: Optional file path to write to

    Returns:
        CSV string
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "Category",
            "Check ID",
            "Title",
            "Severity",
            "Status",
            "Description",
            "Solution",
            "Affected",
        ]
    )

    # Findings
    for f in report.findings:
        writer.writerow(
            [
                f.category,
                f.check_id,
                f.title,
                f.severity,
                f.status,
                f.description,
                f.solution,
                f.affected,
            ]
        )

    csv_str = output.getvalue()

    if output_file:
        with open(output_file, "w", encoding="utf-8", newline="") as f:
            f.write(csv_str)

    return csv_str
