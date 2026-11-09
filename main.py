from core_cli import parse_arguments
from parsers.swagger_parser import OpenAPIParser
from core_executor import SecurityExecutor
from reporters_markdown_reporter import MarkdownReporter

def main():
    print("=== APISec-Suite Framework v0.1 — Professional Security Engine ===")

    args = parse_arguments()

    parser = OpenAPIParser(args.spec)
    endpoints = parser.parse_schema()
    print(f"[+] Loaded {len(endpoints)} endpoints from schema: {args.spec}")

    # Initialize executor with optional bearer token
    executor = SecurityExecutor(args.target, token=args.token)
    vulns = executor.audit_endpoints(endpoints)
    print(f"\n[=] Scan Complete. Found {len(vulns)} potential issue(s).")

    reporter = MarkdownReporter(args.target, vulns)
    reporter.generate_report(args.output)

if __name__ == "__main__":
    main()