import requests

class SecurityExecutor:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.vulnerabilities = []

    def get_default_headers(self):
        headers = {"User-Agent": "APISec-Suite/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def audit_endpoints(self, endpoints):
        """Performs security checks across endpoints, evaluating both unauthenticated and authenticated states."""
        print(f"[*] Starting Security Audit on {len(endpoints)} endpoints (Auth Token Provided: {bool(self.token)})...")

        for item in endpoints:
            path = item["path"]
            method = item["method"]
            url = f"{self.base_url}{path}"

            try:
                # Test with standard/configured headers
                response = requests.request(
                    method=method,
                    url=url,
                    headers=self.get_default_headers(),
                    timeout=5
                )

                # Detect potential BFLA / Broken Object Level Auth indicators
                if not self.token and response.status_code in [200, 201]:
                    vuln = {
                        "type": "BFLA / Unauthenticated Endpoint Access",
                        "endpoint": path,
                        "method": method,
                        "status_code": response.status_code,
                        "severity": "HIGH"
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] VULNERABLE: [{method}] {path} returned HTTP {response.status_code} without authentication!")
                elif self.token and response.status_code == 200:
                    print(f"[+] AUTHENTICATED ACCESS OK: [{method}] {path}")
                else:
                    print(f"[-] PROTECTED / SECURE: [{method}] {path} returned HTTP {response.status_code}")

            except requests.RequestException as e:
                print(f"[-] Execution error on [{method}] {path}: {e}")

        return self.vulnerabilities