import argparse

def parse_arguments():
    """Configures professional CLI option flags for APISec-Suite framework."""
    parser = argparse.ArgumentParser(
        description="APISec-Suite: Automated REST & GraphQL API Penetration Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--spec", 
        required=True, 
        help="Path to OpenAPI / Swagger spec file (JSON or YAML)"
    )
    parser.add_argument(
        "--target", 
        required=True, 
        help="Target API base URL (e.g., https://api.staging-target.com)"
    )
    parser.add_argument(
        "--token", 
        default=None, 
        help="Optional Bearer token for authenticated vulnerability checks"
    )
    parser.add_argument(
        "--output", 
        default="apisec_assessment_report.md", 
        help="Filename for exported executive Markdown report"
    )

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    print(f"[+] CLI parser configured for target: {args.target}")