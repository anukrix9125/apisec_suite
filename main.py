import sys
from parsers.swagger_parser import OpenAPIParser
from core_executor import SecurityExecutor
from reporters_markdown_reporter import MarkdownReporter

def main():
    print("=== APISec-Suite Framework v0.1 — Audit & Reporting Engine ===")
    if len(sys.argv) < 3:
        print("Usage: python main.py <spec_path> <target_base_url>")
        sys.exit(1)

    spec_path = sys.argv[1]
    target_url = sys.argv[2]

    parser = OpenAPIParser(spec_path)
    endpoints = parser.parse_schema()
    print(f"[+] Loaded {len(endpoints)} endpoints from schema.")

    executor = SecurityExecutor(target_url)
    vulns = executor.audit_unauthenticated_access(endpoints)
    print(f"\n[=] Scan Complete. Found {len(vulns)} potential issue(s).")

    reporter = MarkdownReporter(target_url, vulns)
    reporter.generate_report("audit_report.md")

if __name__ == "__main__":
    main()