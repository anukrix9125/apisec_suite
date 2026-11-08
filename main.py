from core_cli import parse_arguments
from parsers.swagger_parser import OpenAPIParser
from core_executor import SecurityExecutor
from reporters_markdown_reporter import MarkdownReporter

def main():
    print("=== APISec-Suite Framework v0.1 — Professional Security Engine ===")

    # Parse CLI arguments cleanly
    args = parse_arguments()

    parser = OpenAPIParser(args.spec)
    endpoints = parser.parse_schema()
    print(f"[+] Loaded {len(endpoints)} endpoints from schema: {args.spec}")

    executor = SecurityExecutor(args.target)
    vulns = executor.audit_unauthenticated_access(endpoints)
    print(f"\n[=] Scan Complete. Found {len(vulns)} potential issue(s).")

    reporter = MarkdownReporter(args.target, vulns)
    reporter.generate_report(args.output)

if __name__ == "__main__":
    main()