"""
Subfinder tool wrapper for subdomain discovery
Supports external subfinder CLI and Python crt.sh/DNS fallback
"""

import subprocess
import socket
from typing import Dict, Any, List
from datetime import datetime

from tools.base_tool import BaseTool


class SubfinderTool(BaseTool):
    """Subfinder subdomain enumeration wrapper with Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "subfinder"
        self._has_cli = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if subfinder CLI is available"""
        try:
            result = subprocess.run(
                ["subfinder", "-version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build subfinder command"""
        if not self._has_cli:
            return ["echo", "Using Python subdomain enumeration"]

        config = self.config.get("tools", {}).get("subfinder", {})

        command = ["subfinder"]
        command.extend(["-d", target])
        command.append("-json")
        command.append("-silent")

        sources = config.get("sources", [])
        if sources:
            command.extend(["-sources", ",".join(sources)])

        if kwargs.get("all_sources"):
            command.append("-all")

        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute subdomain enumeration"""
        if self._has_cli:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_enum(target, **kwargs)

    async def _execute_python_enum(self, target: str, **kwargs) -> Dict[str, Any]:
        """Enumerate subdomains using Python (crt.sh, DNS, etc.)"""
        import httpx

        start_time = datetime.now()

        # Clean domain
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            target = urlparse(target).hostname or target

        subdomains = set()
        sources = {}

        try:
            # 1. Certificate Transparency Logs (crt.sh)
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        f"https://crt.sh/?q=%.{target}&output=json", follow_redirects=True
                    )
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            for subdomain in name.split("\n"):
                                subdomain = subdomain.strip().lower()
                                if subdomain.endswith(target) and "*" not in subdomain:
                                    if subdomain not in subdomains:
                                        subdomains.add(subdomain)
                                        sources["crt.sh"] = sources.get("crt.sh", 0) + 1
            except Exception:
                pass

            # 2. DNS Brute Force (common subdomains)
            common_subdomains = [
                "www",
                "mail",
                "ftp",
                "localhost",
                "webmail",
                "smtp",
                "pop",
                "ns1",
                "ns2",
                "ns3",
                "ns4",
                "dns",
                "dns1",
                "dns2",
                "mx",
                "mx1",
                "mx2",
                "exchange",
                "vpn",
                "remote",
                "admin",
                "administrator",
                "portal",
                "api",
                "dev",
                "development",
                "staging",
                "test",
                "testing",
                "beta",
                "alpha",
                "demo",
                "sandbox",
                "app",
                "apps",
                "mobile",
                "m",
                "blog",
                "news",
                "shop",
                "store",
                "secure",
                "cdn",
                "static",
                "assets",
                "img",
                "images",
                "media",
                "docs",
                "doc",
                "help",
                "support",
                "status",
                "login",
                "signin",
                "sso",
                "auth",
                "dashboard",
                "panel",
                "cpanel",
                "webmin",
                "git",
                "gitlab",
                "github",
                "svn",
                "jenkins",
                "ci",
                "cd",
                "build",
                "db",
                "database",
                "mysql",
                "postgres",
                "mongo",
                "redis",
                "cloud",
                "aws",
                "azure",
                "gcp",
                "intranet",
                "internal",
                "private",
                "corp",
                "office",
                "old",
                "new",
                "legacy",
                "backup",
                "bak",
            ]

            for sub in common_subdomains:
                subdomain = f"{sub}.{target}"
                try:
                    socket.gethostbyname(subdomain)
                    if subdomain not in subdomains:
                        subdomains.add(subdomain)
                        sources["dns_bruteforce"] = sources.get("dns_bruteforce", 0) + 1
                except socket.gaierror:
                    pass

            # 3. Hackertarget API (free)
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.get(
                        f"https://api.hackertarget.com/hostsearch/?q={target}"
                    )
                    if response.status_code == 200 and "error" not in response.text.lower():
                        for line in response.text.split("\n"):
                            if "," in line:
                                subdomain = line.split(",")[0].strip().lower()
                                if subdomain.endswith(target):
                                    if subdomain not in subdomains:
                                        subdomains.add(subdomain)
                                        sources["hackertarget"] = sources.get("hackertarget", 0) + 1
            except Exception:
                pass

            # 4. Threatcrowd API
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.get(
                        f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        for subdomain in data.get("subdomains", []):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(target):
                                if subdomain not in subdomains:
                                    subdomains.add(subdomain)
                                    sources["threatcrowd"] = sources.get("threatcrowd", 0) + 1
            except Exception:
                pass

            duration = (datetime.now() - start_time).total_seconds()

            # Sort subdomains
            sorted_subdomains = sorted(list(subdomains))

            parsed = {
                "subdomains": sorted_subdomains,
                "count": len(sorted_subdomains),
                "sources": sources,
                "domain": target,
            }

            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"Python subdomain enumeration (crt.sh, dns, APIs)",
                "exit_code": 0,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": f"Found {len(sorted_subdomains)} subdomains for {target}",
                "error": None,
                "parsed": parsed,
            }

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"Python subdomain enumeration",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": str(e),
                "parsed": {"subdomains": [], "count": 0},
            }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse subfinder JSON output"""
        import json

        results = {"subdomains": [], "count": 0, "sources": {}}

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                subdomain = data.get("host", "")

                if subdomain and subdomain not in results["subdomains"]:
                    results["subdomains"].append(subdomain)
                    results["count"] += 1

                    source = data.get("source", "unknown")
                    if source not in results["sources"]:
                        results["sources"][source] = 0
                    results["sources"][source] += 1

            except json.JSONDecodeError:
                subdomain = line.strip()
                if subdomain and subdomain not in results["subdomains"]:
                    results["subdomains"].append(subdomain)
                    results["count"] += 1

        return results
