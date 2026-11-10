import requests

class MassAssignmentAuditor:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.escalation_payloads = [
            {"role": "admin", "isAdmin": True, "is_admin": True, "permissions": ["all"]},
            {"group": "administrators", "privilege": 99, "access_level": "superuser"}
        ]

    def get_headers(self):
        headers = {"Content-Type": "application/json", "User-Agent": "APISec-Suite/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def test_endpoint_mass_assignment(self, endpoint_path, method="POST", base_payload=None):
        """Tests if an endpoint improperly binds hidden privilege parameters."""
        url = f"{self.base_url}{endpoint_path}"
        base_data = base_payload or {"name": "Test User", "email": "test@security.local"}

        findings = []
        print(f"[*] Testing Mass Assignment on [{method}] {endpoint_path}...")

        for payload_mod in self.escalation_payloads:
            test_data = {**base_data, **payload_mod}
            try:
                if method.upper() == "POST":
                    response = requests.post(url, json=test_data, headers=self.get_headers(), timeout=5)
                elif method.upper() == "PUT":
                    response = requests.put(url, json=test_data, headers=self.get_headers(), timeout=5)
                else:
                    continue

                # If status indicates success or accepted binding of injected keys
                if response.status_code in [200, 201, 202]:
                    findings.append({
                        "endpoint": endpoint_path,
                        "method": method,
                        "injected_payload": payload_mod,
                        "status_code": response.status_code
                    })
                    print(f"[!] POTENTIAL MASS ASSIGNMENT: Endpoint accepted keys {list(payload_mod.keys())} with HTTP {response.status_code}")
            except requests.RequestException as e:
                print(f"[-] Request error during mass assignment test: {e}")

        return findings

if __name__ == "__main__":
    print("[+] Mass Assignment Auditor module loaded.")