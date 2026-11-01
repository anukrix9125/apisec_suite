import sys
from parsers.swagger_parser import OpenAPIParser

def main():
    print("=== APISec-Suite Framework v0.1 ===")
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_openapi_spec>")
        sys.exit(1)

    spec_path = sys.argv[1]
    parser = OpenAPIParser(spec_path)
    endpoints = parser.parse_schema()
    print(f"[+] Loaded {len(endpoints)} endpoint definitions from schema.")

if __name__ == "__main__":
    main()