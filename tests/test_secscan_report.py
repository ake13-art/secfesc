"""Tests for secscan report exporters (json / html / csv)."""

import csv
import io
import json
from datetime import datetime

import pytest

from secfesc.secscan.core.engine import AuditCategory, AuditFinding, AuditReport
from secfesc.secscan.report.csv import export_csv
from secfesc.secscan.report.html import export_html
from secfesc.secscan.report.json import export_json


@pytest.fixture
def report():
    r = AuditReport(
        hostname="testhost",
        start_time=datetime(2026, 6, 3, 12, 0, 0),
        end_time=datetime(2026, 6, 3, 12, 0, 1),
        is_root=False,
    )
    r.categories = [AuditCategory(name="ssh", description="Category: ssh")]
    r.findings = [
        AuditFinding("ssh", "SSH-7412", "Root login permitted", "high", "found", "desc1", "sol1"),
        AuditFinding("ssh", "SSH-7414", "Password auth", "medium", "found", "desc2", "sol2"),
    ]
    r.warnings = ["Skipped 'kernel' (run as root to include it)"]
    return r


class TestJSON:
    def test_structure_and_counts(self, report):
        data = json.loads(export_json(report))
        assert data["hostname"] == "testhost"
        assert data["summary"]["total_findings"] == 2
        assert {f["check_id"] for f in data["findings"]} == {"SSH-7412", "SSH-7414"}
        assert data["warnings"] == ["Skipped 'kernel' (run as root to include it)"]

    def test_writes_file(self, report, tmp_path):
        target = tmp_path / "report.json"
        export_json(report, str(target))
        assert json.loads(target.read_text())["summary"]["total_findings"] == 2


class TestCSV:
    def test_header_and_rows(self, report):
        rows = list(csv.reader(io.StringIO(export_csv(report))))
        assert rows[0] == [
            "Category", "Check ID", "Title", "Severity",
            "Status", "Description", "Solution", "Affected",
        ]
        assert len(rows) == 3  # header + 2 findings
        assert rows[1][1] == "SSH-7412"

    def test_writes_file(self, report, tmp_path):
        target = tmp_path / "report.csv"
        export_csv(report, str(target))
        assert "SSH-7414" in target.read_text()


class TestHTML:
    def test_contains_findings_and_counts(self, report):
        html = export_html(report)
        assert "Root login permitted" in html
        assert "testhost" in html
        # one high (error) and one medium (warning) -> the summary cards show 1 each
        assert '<div class="summary-number">1</div>' in html  # error_count card
        assert 'class="finding error"' in html
        assert 'class="finding warning"' in html

    def test_empty_report(self):
        empty = AuditReport(hostname="h", start_time=datetime(2026, 6, 3, 12, 0, 0))
        html = export_html(empty)
        assert "No findings." in html

    def test_writes_file(self, report, tmp_path):
        target = tmp_path / "report.html"
        export_html(report, str(target))
        assert "Root login permitted" in target.read_text()
