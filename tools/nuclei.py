"""
Nuclei tool wrapper for vulnerability scanning
Includes Python-based fallback using vulnerability databases and pattern matching
"""

import json
import re
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime

from tools.base_tool import BaseTool


# Common security checks that can be performed without nuclei CLI
SECURITY_CHECKS = {
    # Security headers
    "missing-x-frame-options": {
        "name": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": "X-Frame-Options header is not set, which may allow clickjacking attacks.",
        "type": "misconfiguration",
        "check": lambda headers: "x-frame-options" not in {k.lower() for k in headers.keys()},
    },
    "missing-csp": {
        "name": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "description": "Content-Security-Policy header is not set, which may allow XSS attacks.",
        "type": "misconfiguration",
        "check": lambda headers: "content-security-policy"
        not in {k.lower() for k in headers.keys()},
    },
    "missing-hsts": {
        "name": "Missing Strict-Transport-Security Header",
        "severity": "low",
        "description": "HSTS header is not set, which may allow downgrade attacks.",
        "type": "misconfiguration",
        "check": lambda headers: "strict-transport-security"
        not in {k.lower() for k in headers.keys()},
    },
    "missing-x-content-type-options": {
        "name": "Missing X-Content-Type-Options Header",
        "severity": "low",
        "description": "X-Content-Type-Options header is not set.",
        "type": "misconfiguration",
        "check": lambda headers: "x-content-type-options"
        not in {k.lower() for k in headers.keys()},
    },
    "missing-x-xss-protection": {
        "name": "Missing X-XSS-Protection Header",
        "severity": "info",
        "description": "X-XSS-Protection header is not set.",
        "type": "misconfiguration",
        "check": lambda headers: "x-xss-protection" not in {k.lower() for k in headers.keys()},
    },
    "server-header-disclosure": {
        "name": "Server Header Information Disclosure",
        "severity": "info",
        "description": "Server header reveals server software information.",
        "type": "exposure",
        "check": lambda headers: "server" in {k.lower() for k in headers.keys()},
    },
    "x-powered-by-disclosure": {
        "name": "X-Powered-By Header Information Disclosure",
        "severity": "info",
        "description": "X-Powered-By header reveals technology information.",
        "type": "exposure",
        "check": lambda headers: "x-powered-by" in {k.lower() for k in headers.keys()},
    },
}

# Path-based checks
PATH_CHECKS = [
    {
        "path": "/.git/config",
        "name": "Git Config Exposure",
        "severity": "high",
        "description": "Git configuration file is exposed, which may leak repository information.",
        "pattern": r"\[core\]|\[remote",
    },
    {
        "path": "/.env",
        "name": "Environment File Exposure",
        "severity": "critical",
        "description": ".env file is exposed, which may contain sensitive credentials.",
        "pattern": r"(DB_|API_|SECRET|PASSWORD|KEY)=",
    },
    {
        "path": "/robots.txt",
        "name": "Robots.txt Exposure",
        "severity": "info",
        "description": "robots.txt file found, may reveal hidden paths.",
        "pattern": r"(Disallow|Allow):",
    },
    {
        "path": "/.htaccess",
        "name": "Htaccess File Exposure",
        "severity": "medium",
        "description": ".htaccess file is exposed.",
        "pattern": r"(RewriteRule|RewriteCond|AuthType)",
    },
    {
        "path": "/wp-config.php.bak",
        "name": "WordPress Config Backup",
        "severity": "critical",
        "description": "WordPress configuration backup file is exposed.",
        "pattern": r"(DB_NAME|DB_USER|DB_PASSWORD)",
    },
    {
        "path": "/server-status",
        "name": "Apache Server Status Exposure",
        "severity": "medium",
        "description": "Apache server-status page is exposed.",
        "pattern": r"Apache Server Status",
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Info Exposure",
        "severity": "medium",
        "description": "PHP info page is exposed.",
        "pattern": r"PHP Version|phpinfo\(\)",
    },
    {
        "path": "/debug",
        "name": "Debug Endpoint",
        "severity": "medium",
        "description": "Debug endpoint is accessible.",
        "pattern": r"(debug|stack|trace|error)",
    },
    {
        "path": "/admin",
        "name": "Admin Panel Detection",
        "severity": "info",
        "description": "Admin panel found.",
        "pattern": r"(login|admin|dashboard)",
    },
    {
        "path": "/backup.sql",
        "name": "SQL Backup Exposure",
        "severity": "critical",
        "description": "SQL backup file is exposed.",
        "pattern": r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
    },
    {
        "path": "/config.json",
        "name": "Config JSON Exposure",
        "severity": "high",
        "description": "Configuration JSON file is exposed.",
        "pattern": r'("password"|"secret"|"api_key")',
    },
    {
        "path": "/.DS_Store",
        "name": "DS_Store File Exposure",
        "severity": "low",
        "description": "macOS .DS_Store file is exposed, may reveal directory structure.",
        "pattern": r"Bud1",
    },
]

# Known CVE patterns in responses
CVE_PATTERNS = [
    {
        "pattern": r"Apache/(2\.4\.[0-9]|2\.4\.[1-3][0-9]|2\.4\.4[0-8])\b",
        "cve": "CVE-2021-44790",
        "name": "Apache HTTP Server Buffer Overflow",
        "severity": "high",
        "description": "Apache HTTP Server versions before 2.4.52 are vulnerable to buffer overflow.",
    },
    {
        "pattern": r"nginx/(1\.1[0-8]|1\.19\.[0-9]|1\.20\.0)\b",
        "cve": "CVE-2021-23017",
        "name": "nginx DNS Resolver Vulnerability",
        "severity": "high",
        "description": "nginx versions before 1.20.1 are vulnerable to DNS resolver issues.",
    },
    {
        "pattern": r"PHP/(5\.|7\.[0-3]\.|7\.4\.[0-9]|7\.4\.[1][0-9]|7\.4\.2[0-5])\b",
        "cve": "CVE-2022-31626",
        "name": "PHP Buffer Overflow",
        "severity": "high",
        "description": "PHP versions are vulnerable to buffer overflow in mysqlnd.",
    },
    {
        "pattern": r"WordPress/(4\.|5\.[0-7]\.)",
        "cve": "CVE-2022-21661",
        "name": "WordPress SQL Injection",
        "severity": "high",
        "description": "WordPress versions before 5.8.3 are vulnerable to SQL injection.",
    },
    {
        "pattern": r"jQuery/(1\.|2\.|3\.[0-4]\.)",
        "cve": "CVE-2020-11023",
        "name": "jQuery XSS Vulnerability",
        "severity": "medium",
        "description": "jQuery versions before 3.5.0 are vulnerable to XSS.",
    },
    {
        "pattern": r"OpenSSL/(1\.0\.|1\.1\.0|1\.1\.1[a-j])\b",
        "cve": "CVE-2022-0778",
        "name": "OpenSSL Infinite Loop",
        "severity": "high",
        "description": "OpenSSL versions are vulnerable to infinite loop causing DoS.",
    },
]


class NucleiTool(BaseTool):
    """Nuclei vulnerability scanner wrapper with Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "nuclei"
        self._cli_available = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if nuclei CLI is installed"""
        return shutil.which("nuclei") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nuclei command"""
        if not self._cli_available:
            return ["echo", "Using Python fallback scanner"]

        config = self.config.get("tools", {}).get("nuclei", {})

        command = ["nuclei"]

        # Target
        if kwargs.get("from_file"):
            command.extend(["-l", kwargs["from_file"]])
        else:
            command.extend(["-u", target])

        # JSON output
        command.extend(["-jsonl"])

        # Severity filtering
        severities = config.get("severity", ["critical", "high", "medium"])
        if severities:
            command.extend(["-severity", ",".join(severities)])

        # Templates path
        templates_path = config.get("templates_path")
        if templates_path:
            command.extend(["-t", templates_path])

        # Silent mode
        command.append("-silent")

        # Rate limit
        command.extend(["-rate-limit", "150"])

        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute nuclei - uses Python fallback if CLI not available"""
        if self._cli_available:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_scanner(target, **kwargs)

    async def _execute_python_scanner(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute vulnerability checks using Python httpx"""
        import httpx

        start_time = datetime.now()

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        vulnerabilities = []

        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,  # Allow self-signed certs for testing
            ) as client:
                # Get main page
                try:
                    response = await client.get(target)
                    headers = response.headers
                    content = response.text

                    # Check security headers
                    for check_id, check in SECURITY_CHECKS.items():
                        if check["check"](headers):
                            vulnerabilities.append(
                                {
                                    "template": f"python-{check_id}",
                                    "name": check["name"],
                                    "severity": check["severity"],
                                    "matched_at": target,
                                    "type": check["type"],
                                    "description": check["description"],
                                    "reference": [],
                                }
                            )

                    # Check for CVE patterns in headers and content
                    combined_text = str(headers) + content
                    for cve_check in CVE_PATTERNS:
                        if re.search(cve_check["pattern"], combined_text, re.IGNORECASE):
                            vulnerabilities.append(
                                {
                                    "template": f"python-{cve_check['cve'].lower()}",
                                    "name": cve_check["name"],
                                    "severity": cve_check["severity"],
                                    "matched_at": target,
                                    "type": "cve",
                                    "description": cve_check["description"],
                                    "reference": [
                                        f"https://nvd.nist.gov/vuln/detail/{cve_check['cve']}"
                                    ],
                                    "cve": cve_check["cve"],
                                }
                            )

                except httpx.HTTPError:
                    pass

                # Check sensitive paths
                for path_check in PATH_CHECKS:
                    try:
                        path_url = target.rstrip("/") + path_check["path"]
                        path_response = await client.get(path_url)

                        if path_response.status_code == 200:
                            if re.search(path_check["pattern"], path_response.text, re.IGNORECASE):
                                vulnerabilities.append(
                                    {
                                        "template": f"python-{path_check['name'].lower().replace(' ', '-')}",
                                        "name": path_check["name"],
                                        "severity": path_check["severity"],
                                        "matched_at": path_url,
                                        "type": "exposure",
                                        "description": path_check["description"],
                                        "reference": [],
                                    }
                                )
                    except httpx.HTTPError:
                        continue

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"python_vuln_scan({target})",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": str(e),
                "parsed": {},
            }

        duration = (datetime.now() - start_time).total_seconds()

        # Count by severity
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln["severity"]
            if sev in by_severity:
                by_severity[sev] += 1

        parsed = {
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "by_severity": by_severity,
            "scan_method": "python_httpx",
        }

        # Build human-readable output
        output_lines = [
            f"Python Vulnerability Scan for {target}",
            f"Found {len(vulnerabilities)} potential issues in {duration:.2f}s",
            "",
        ]

        for vuln in vulnerabilities:
            severity_badge = f"[{vuln['severity'].upper()}]"
            output_lines.append(f"{severity_badge} {vuln['name']}")
            output_lines.append(f"    └─ {vuln['matched_at']}")

        raw_output = "\n".join(output_lines)

        return {
            "tool": self.tool_name,
            "target": target,
            "command": f"python_vuln_scan({target})",
            "exit_code": 0,
            "duration": duration,
            "timestamp": start_time.isoformat(),
            "raw_output": raw_output,
            "error": None,
            "parsed": parsed,
        }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei JSON output"""
        results = {
            "vulnerabilities": [],
            "count": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        # Parse JSON lines
        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                vuln = {
                    "template": data.get("template-id", "unknown"),
                    "name": data.get("info", {}).get("name", "Unknown"),
                    "severity": data.get("info", {}).get("severity", "info").lower(),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", []),
                }

                results["vulnerabilities"].append(vuln)
                results["count"] += 1

                # Count by severity
                severity = vuln["severity"]
                if severity in results["by_severity"]:
                    results["by_severity"][severity] += 1

            except json.JSONDecodeError:
                continue

        return results
