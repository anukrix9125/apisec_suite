import datetime

class MarkdownReporter:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_report(self, output_filename="apisec_assessment_report.md"):
        """Compiles scan telemetry into a professional freelance security report."""
        report_content = f"""# API Security Assessment Report

## Executive Summary
- **Target URL:** {self.target_url}
- **Assessment Timestamp:** {self.timestamp}
- **Total Vulnerabilities Identified:** {len(self.vulnerabilities)}
- **Framework:** APISec-Suite v0.1 (Automated REST/GraphQL Security Engine)

## Identified Findings
"""
        if not self.vulnerabilities:
            report_content += "\nNo critical unauthenticated vulnerabilities detected during baseline sweep.\n"
        else:
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                report_content += f"""
### {idx}. {vuln['type']}
- **Endpoint:** `{vuln['endpoint']}`
- **HTTP Method:** {vuln['method']}
- **Response Status:** {vuln['status_code']}
- **Severity Level:** {vuln['severity']}
- **Recommendation:** Enforce strict authentication middleware and role-based access control (RBAC) validation on this route.
"""

        try:
            with open(output_filename, 'w') as f:
                f.write(report_content)
            print(f"[+] Client-ready report successfully generated: {output_filename}")
        except Exception as e:
            print(f"[-] Failed to generate report: {e}")