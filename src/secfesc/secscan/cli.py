"""secscan CLI entry point."""

from __future__ import annotations

import argparse
import sys

from secfesc.shared import log_info


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="secscan - Comprehensive Linux security audit (Lynis-like)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secscan               Basic audit (no root required)
  secscan --full        Complete audit (requires root)
  secscan --quick       Fast scan with key checks only
  secscan --category    Specific category to audit
  secscan --report json Export report as JSON
  secscan --verbose     Enable verbose output
        """,
    )
    parser.add_argument("--version", action="version", version="secscan 1.6.1")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full audit with all checks (requires root)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick audit with essential checks only",
    )
    parser.add_argument(
        "--category",
        metavar="NAME",
        help="Run only the specified category (e.g., ssh, users)",
    )
    parser.add_argument(
        "--report",
        metavar="FORMAT",
        choices=["json", "html", "csv"],
        help="Export report in specified format",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write report to FILE (default: stdout)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    from secfesc.secscan.core.engine import AuditEngine

    if args.verbose:
        log_info("Verbose mode enabled")

    engine = AuditEngine(verbose=args.verbose)

    if args.full:
        log_info("Running full audit")
        report = engine.run_full_audit()
    elif args.category:
        log_info(f"Running category: {args.category}")
        report = engine.run_categories([args.category])
    elif args.quick:
        log_info("Running quick audit")
        report = engine.run_quick_audit()
    else:
        log_info("Running basic audit (default)")
        report = engine.run_quick_audit()

    # When exporting machine-readable output to stdout, suppress the human
    # summary so it doesn't pollute the report stream.
    exporting_to_stdout = bool(args.report) and not args.output
    if not exporting_to_stdout and not args.quiet:
        engine.print_summary(report)

    if args.report:
        log_info(f"Exporting report as {args.report}")
        output_file = args.output

        if args.report == "json":
            from secfesc.secscan.report.json import export_json

            output = export_json(report, output_file)
        elif args.report == "html":
            from secfesc.secscan.report.html import export_html

            output = export_html(report, output_file)
        elif args.report == "csv":
            from secfesc.secscan.report.csv import export_csv

            output = export_csv(report, output_file)
        else:
            log_info(f"Unknown export format: {args.report}")
            return 1

        if not output_file:
            print(output)

    # Exit code reflects the worst finding severity (useful in CI):
    #   0 = clean, 1 = warnings, 2 = errors. Fatal errors return 3 (below).
    counts = engine._severity_counts(report)
    if counts["errors"]:
        return 2
    if counts["warnings"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # fatal, unexpected error
        print(f"secscan: fatal error: {exc}", file=sys.stderr)
        sys.exit(3)
