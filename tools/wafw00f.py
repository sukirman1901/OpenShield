"""
WAF Detection Tool
Supports external wafw00f CLI and Python httpx fallback
"""

import re
import subprocess
from typing import Dict, Any, List
from datetime import datetime

from tools.base_tool import BaseTool


class Wafw00fTool(BaseTool):
    """Web Application Firewall detection wrapper with Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "wafw00f"
        self._has_cli = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if wafw00f CLI is available"""
        try:
            result = subprocess.run(["wafw00f", "-h"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build wafw00f command"""
        if not self._has_cli:
            return ["echo", "Using Python WAF detection"]

        command = ["wafw00f"]
        command.append("-v")

        if kwargs.get("find_all", True):
            command.append("-a")

        command.append(target)
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute WAF detection"""
        if self._has_cli:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_detection(target, **kwargs)

    async def _execute_python_detection(self, target: str, **kwargs) -> Dict[str, Any]:
        """Detect WAF using Python httpx and header analysis"""
        import httpx

        start_time = datetime.now()

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=30.0, follow_redirects=True, verify=True
            ) as client:
                response = await client.get(target)

                headers = dict(response.headers)
                header_str = str(headers).lower()
                cookies = headers.get("set-cookie", "").lower()

                waf_detected = False
                waf_type = None
                waf_vendor = None
                confidence = "low"
                details = []

                # WAF detection signatures
                waf_signatures = {
                    "Cloudflare": {
                        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
                        "server": ["cloudflare"],
                        "cookies": ["__cfduid", "_cf_bm", "cf_clearance"],
                        "vendor": "Cloudflare, Inc.",
                    },
                    "AWS WAF": {
                        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
                        "server": ["awselb", "amazon"],
                        "cookies": ["awsalb", "awsalbcors"],
                        "vendor": "Amazon Web Services",
                    },
                    "Akamai": {
                        "headers": ["akamai", "x-akamai"],
                        "server": ["akamai", "ghost"],
                        "cookies": ["ak_bmsc", "bm_sz"],
                        "vendor": "Akamai Technologies",
                    },
                    "Imperva/Incapsula": {
                        "headers": ["x-iinfo", "x-cdn"],
                        "server": ["incapsula"],
                        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
                        "vendor": "Imperva, Inc.",
                    },
                    "Sucuri": {
                        "headers": ["x-sucuri-id", "x-sucuri-cache"],
                        "server": ["sucuri"],
                        "cookies": ["sucuri"],
                        "vendor": "Sucuri Inc.",
                    },
                    "F5 BIG-IP": {
                        "headers": ["x-wa-info"],
                        "server": ["big-ip", "bigip", "f5"],
                        "cookies": ["bigipserver", "ts", "f5_cspm"],
                        "vendor": "F5 Networks",
                    },
                    "Barracuda": {
                        "headers": ["barra_counter_session"],
                        "server": ["barracuda"],
                        "cookies": ["barra_counter_session"],
                        "vendor": "Barracuda Networks",
                    },
                    "ModSecurity": {
                        "headers": ["mod_security", "modsecurity"],
                        "server": ["mod_security"],
                        "cookies": [],
                        "vendor": "Trustwave/OWASP",
                    },
                    "Fortinet FortiWeb": {
                        "headers": ["fortiwafsid"],
                        "server": ["fortiweb"],
                        "cookies": ["fortiwafsid"],
                        "vendor": "Fortinet",
                    },
                    "Citrix NetScaler": {
                        "headers": ["ns_af"],
                        "server": ["netscaler"],
                        "cookies": ["ns_af", "citrix_ns_id", "nsc_"],
                        "vendor": "Citrix Systems",
                    },
                    "DDoS-Guard": {
                        "headers": [],
                        "server": ["ddos-guard"],
                        "cookies": ["__ddg1", "__ddg2"],
                        "vendor": "DDoS-Guard",
                    },
                    "Fastly": {
                        "headers": ["x-fastly-request-id", "fastly-io-info"],
                        "server": ["fastly"],
                        "cookies": [],
                        "vendor": "Fastly, Inc.",
                    },
                    "Varnish": {
                        "headers": ["x-varnish", "via"],
                        "server": ["varnish"],
                        "cookies": [],
                        "vendor": "Varnish Software",
                    },
                    "StackPath": {
                        "headers": ["x-sp-url", "x-sp-waf"],
                        "server": ["stackpath"],
                        "cookies": [],
                        "vendor": "StackPath",
                    },
                    "Wordfence": {
                        "headers": ["x-wordfence"],
                        "server": [],
                        "cookies": ["wfwaf-authcookie"],
                        "vendor": "Wordfence (WordPress)",
                    },
                }

                # Check for each WAF
                detected_wafs = []
                for waf_name, signatures in waf_signatures.items():
                    score = 0

                    # Check headers
                    for header in signatures["headers"]:
                        if header in header_str:
                            score += 2
                            details.append(f"Header match: {header}")

                    # Check server
                    server = headers.get("server", "").lower()
                    for srv in signatures["server"]:
                        if srv in server:
                            score += 3
                            details.append(f"Server match: {srv}")

                    # Check cookies
                    for cookie in signatures["cookies"]:
                        if cookie in cookies:
                            score += 2
                            details.append(f"Cookie match: {cookie}")

                    if score >= 2:
                        detected_wafs.append(
                            {
                                "name": waf_name,
                                "vendor": signatures["vendor"],
                                "score": score,
                                "confidence": "high" if score >= 4 else "medium",
                            }
                        )

                # Get the most likely WAF
                if detected_wafs:
                    detected_wafs.sort(key=lambda x: x["score"], reverse=True)
                    best_match = detected_wafs[0]
                    waf_detected = True
                    waf_type = best_match["name"]
                    waf_vendor = best_match["vendor"]
                    confidence = best_match["confidence"]

                duration = (datetime.now() - start_time).total_seconds()

                parsed = {
                    "waf_detected": waf_detected,
                    "waf_type": waf_type,
                    "waf_vendor": waf_vendor,
                    "confidence": confidence,
                    "all_detected": detected_wafs,
                    "details": details,
                    "http_status": response.status_code,
                    "server_header": headers.get("server", "Unknown"),
                }

                return {
                    "tool": self.tool_name,
                    "target": target,
                    "command": f"httpx.get({target}) + WAF signature matching",
                    "exit_code": 0,
                    "duration": duration,
                    "timestamp": start_time.isoformat(),
                    "raw_output": f"WAF: {waf_type or 'None detected'} ({confidence})",
                    "error": None,
                    "parsed": parsed,
                }

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"httpx.get({target})",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": str(e),
                "parsed": {},
            }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse wafw00f CLI output"""
        results = {
            "waf_detected": False,
            "waf_type": None,
            "waf_vendor": None,
            "confidence": "unknown",
            "details": [],
        }

        if "is behind" in output.lower():
            results["waf_detected"] = True

            waf_match = re.search(r"is behind ([^\(]+)", output, re.IGNORECASE)
            if waf_match:
                results["waf_type"] = waf_match.group(1).strip()

            vendor_match = re.search(r"\(([^)]+)\)", output)
            if vendor_match:
                results["waf_vendor"] = vendor_match.group(1).strip()

        elif "no waf detected" in output.lower():
            results["waf_detected"] = False
            results["confidence"] = "high"

        for line in output.split("\n"):
            if line.strip() and not line.startswith("["):
                results["details"].append(line.strip())

        return results
