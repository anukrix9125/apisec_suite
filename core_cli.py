import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="APISec-Suite: Automated REST & GraphQL API Penetration Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--spec", required=True, help="Path to OpenAPI / Swagger spec file")
    parser.add_argument("--target", required=True, help="Target API base URL")
    parser.add_argument("--token", default=None, help="Optional Bearer token")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent worker threads (default: 10)")
    parser.add_argument("--output", default="apisec_assessment_report.md", help="Report filename")
    return parser.parse_args()