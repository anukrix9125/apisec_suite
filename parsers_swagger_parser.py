import yaml
import json

class OpenAPIParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.endpoints = []

    def parse_schema(self):
        """Parses JSON or YAML OpenAPI spec files to extract defined endpoints."""
        try:
            with open(self.filepath, 'r') as file:
                if self.filepath.endswith('.json'):
                    data = json.load(file)
                else:
                    data = yaml.safe_load(file)

            paths = data.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    self.endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "summary": details.get("summary", "")
                    })
            return self.endpoints
        except Exception as e:
            print(f"[-] Parsing error: {e}")
            return []

if __name__ == "__main__":
    print("[+] OpenAPIParser module ready.")