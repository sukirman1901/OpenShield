"""
DNS Reconnaissance Tool
Supports external dnsrecon CLI and Python dns.resolver fallback
"""

import subprocess
import socket
from typing import List, Dict, Any
from datetime import datetime

from tools.base_tool import BaseTool


class DnsReconTool(BaseTool):
    """Wrapper for DNS Reconnaissance - supports CLI and Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "dnsrecon"
        self._has_cli = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if dnsrecon CLI is available"""
        try:
            result = subprocess.run(["dnsrecon", "-h"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build dnsrecon command"""
        if not self._has_cli:
            return ["echo", "Using Python DNS resolver"]

        cmd = ["dnsrecon", "-d", target]

        # Tool options
        if kwargs.get("type"):
            cmd.extend(["-t", kwargs["type"]])  # std, rvl, brt, etc.

        if kwargs.get("dictionary"):
            cmd.extend(["-D", kwargs["dictionary"]])

        if kwargs.get("threads"):
            cmd.extend(["--threads", str(kwargs["threads"])])

        return cmd

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute DNS reconnaissance"""
        if self._has_cli:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_dns(target, **kwargs)

    async def _execute_python_dns(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute using Python dns.resolver library"""
        import asyncio

        start_time = datetime.now()

        # Clean target (remove http:// etc)
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            target = urlparse(target).hostname or target

        try:
            import dns.resolver
            import dns.reversename

            records = []
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    for rdata in answers:
                        records.append(
                            {
                                "type": rtype,
                                "name": target,
                                "value": str(rdata),
                                "ttl": answers.rrset.ttl if answers.rrset else None,
                            }
                        )
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    break
                except Exception:
                    pass

            # Try to get IP and reverse DNS
            try:
                ip = socket.gethostbyname(target)
                records.append({"type": "A", "name": target, "value": ip, "resolved": True})

                # Reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    records.append({"type": "PTR", "name": ip, "value": hostname})
                except socket.herror:
                    pass
            except socket.gaierror:
                pass

            duration = (datetime.now() - start_time).total_seconds()

            parsed = {
                "records": records,
                "total_records": len(records),
                "record_types_found": list(set(r["type"] for r in records)),
                "domain": target,
            }

            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"dns.resolver.resolve({target})",
                "exit_code": 0,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": f"Found {len(records)} DNS records for {target}",
                "error": None,
                "parsed": parsed,
            }

        except ImportError:
            # dnspython not installed, use basic socket
            return await self._execute_basic_dns(target, start_time)
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"dns.resolver.resolve({target})",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": str(e),
                "parsed": {},
            }

    async def _execute_basic_dns(self, target: str, start_time: datetime) -> Dict[str, Any]:
        """Basic DNS lookup using socket (no external dependencies)"""
        records = []

        try:
            # Get all IPs
            ips = socket.gethostbyname_ex(target)
            hostname = ips[0]
            aliases = ips[1]
            addresses = ips[2]

            for ip in addresses:
                records.append({"type": "A", "name": target, "value": ip})

            for alias in aliases:
                records.append({"type": "CNAME", "name": target, "value": alias})

            # Try MX lookup via external service
            try:
                import subprocess

                result = subprocess.run(
                    ["host", "-t", "MX", target], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "mail" in line.lower():
                            records.append({"type": "MX", "name": target, "value": line.strip()})
            except Exception:
                pass

        except socket.gaierror as e:
            records.append({"type": "ERROR", "name": target, "value": str(e)})

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "tool": self.tool_name,
            "target": target,
            "command": f"socket.gethostbyname_ex({target})",
            "exit_code": 0 if records else 1,
            "duration": duration,
            "timestamp": start_time.isoformat(),
            "raw_output": f"Found {len(records)} records using basic DNS",
            "error": None,
            "parsed": {
                "records": records,
                "total_records": len(records),
                "domain": target,
                "method": "socket (basic)",
            },
        }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse dnsrecon CLI output"""
        result = {"records": [], "raw_output": output}

        # Try to parse as structured output
        for line in output.split("\n"):
            if "[*]" in line or "[-]" in line:
                result["records"].append({"raw": line.strip()})

        return result
