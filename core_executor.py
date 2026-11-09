import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class SecurityExecutor:
    def __init__(self, base_url, token=None, max_workers=10):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.max_workers = max_workers
        self.vulnerabilities = []

    def get_default_headers(self):
        headers = {"User-Agent": "APISec-Suite/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _audit_single_endpoint(self, item):
        path = item["path"]
        method = item["method"]
        url = f"{self.base_url}{path}"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.get_default_headers(),
                timeout=5
            )

            if not self.token and response.status_code in [200, 201]:
                return {
                    "type": "BFLA / Unauthenticated Endpoint Access",
                    "endpoint": path,
                    "method": method,
                    "status_code": response.status_code,
                    "severity": "HIGH"
                }
            elif self.token and response.status_code == 200:
                return None # Authorized access successful
        except requests.RequestException:
            pass
        return None

    def audit_endpoints(self, endpoints):
        """Executes multi-threaded vulnerability scans across extracted endpoints."""
        print(f"[*] Starting Concurrent Security Audit ({self.max_workers} threads) on {len(endpoints)} endpoints...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._audit_single_endpoint, item): item for item in endpoints}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.vulnerabilities.append(result)
                    print(f"[!] VULNERABLE: [{result['method']}] {result['endpoint']} returned HTTP {result['status_code']}")

        return self.vulnerabilities