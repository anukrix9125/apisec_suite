import requests

class SecurityExecutor:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.vulnerabilities = []

    def audit_unauthenticated_access(self, endpoints):
        """Tests if endpoints defined in the schema allow unauthenticated HTTP calls."""
        print(f"[*] Starting Unauthenticated Access Audit on {len(endpoints)} endpoints...")

        for item in endpoints:
            path = item["path"]
            method = item["method"]
            url = f"{self.base_url}{path}"

            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers={"User-Agent": "APISec-Suite/0.1"},
                    timeout=5
                )

                if response.status_code in [200, 201]:
                    vuln = {
                        "type": "BFLA / Unauthenticated Access",
                        "endpoint": path,
                        "method": method,
                        "status_code": response.status_code,
                        "severity": "HIGH"
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] VULNERABLE: [{method}] {path} returned HTTP {response.status_code} without Auth header!")
                else:
                    print(f"[+] SECURE: [{method}] {path} returned HTTP {response.status_code}")

            except requests.RequestException as e:
                print(f"[-] Execution error on [{method}] {path}: {e}")

        return self.vulnerabilities