"""
httpx tool wrapper for HTTP probing
Supports both ProjectDiscovery httpx CLI and Python httpx library
"""

import json
import subprocess
import re
from typing import Dict, Any, List
from datetime import datetime

from tools.base_tool import BaseTool


class HttpxTool(BaseTool):
    """httpx HTTP probing wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "httpx"
        self._is_projectdiscovery = self._detect_httpx_type()

    def _detect_httpx_type(self) -> bool:
        """Detect if httpx is ProjectDiscovery version"""
        try:
            result = subprocess.run(
                ["httpx", "-version"], capture_output=True, text=True, timeout=5
            )
            # ProjectDiscovery httpx supports -version and shows version info
            output = result.stdout.lower() + result.stderr.lower()
            return "projectdiscovery" in output or "current version" in output
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build httpx command (only for ProjectDiscovery version)"""
        if not self._is_projectdiscovery:
            # Return dummy command - we'll use Python library instead
            return ["echo", "Using Python httpx library"]

        config = self.config.get("tools", {}).get("httpx", {})
        return self._get_pd_command(target, config, **kwargs)

    def _get_pd_command(self, target: str, config: dict, **kwargs) -> List[str]:
        """Build ProjectDiscovery httpx command"""
        command = ["httpx"]

        # JSON output for easy parsing
        command.extend(["-j"])

        # Threads
        threads = config.get("threads", 50)
        command.extend(["-threads", str(threads)])

        # Timeout
        timeout = config.get("timeout", 10)
        command.extend(["-timeout", str(timeout)])

        # Tech detection
        command.append("-tech-detect")

        # Status code
        command.append("-status-code")

        # Title
        command.append("-title")

        # Target (from stdin or direct)
        if kwargs.get("from_file"):
            command.extend(["-l", kwargs["from_file"]])
        else:
            command.extend(["-u", target])

        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute httpx - uses library for Python version"""
        if self._is_projectdiscovery:
            # Use CLI version
            return await super().execute(target, **kwargs)
        else:
            # Use Python httpx library
            return await self._execute_python_httpx(target, **kwargs)

    async def _execute_python_httpx(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute using Python httpx library"""
        import httpx

        start_time = datetime.now()

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=30.0, follow_redirects=True, verify=kwargs.get("verify", True)
            ) as client:
                response = await client.get(target)

                duration = (datetime.now() - start_time).total_seconds()

                # Extract useful info
                parsed = {
                    "urls": [str(response.url)],
                    "status_codes": {str(response.url): response.status_code},
                    "titles": {},
                    "technologies": [],
                    "headers": dict(response.headers),
                    "http_version": str(response.http_version),
                    "content_length": len(response.content),
                }

                # Try to extract title from HTML
                if "text/html" in response.headers.get("content-type", ""):
                    content = response.text
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", content, re.IGNORECASE)
                    if title_match:
                        parsed["titles"][str(response.url)] = title_match.group(1).strip()

                # Detect some technologies from headers
                server = response.headers.get("server", "")
                if server:
                    parsed["technologies"].append(server)

                powered_by = response.headers.get("x-powered-by", "")
                if powered_by:
                    parsed["technologies"].append(powered_by)

                return {
                    "tool": self.tool_name,
                    "target": target,
                    "command": f"httpx.get({target})",
                    "exit_code": 0,
                    "duration": duration,
                    "timestamp": start_time.isoformat(),
                    "raw_output": f"Status: {response.status_code}, URL: {response.url}",
                    "error": None,
                    "parsed": parsed,
                }

        except httpx.TimeoutException as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"httpx.get({target})",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": f"Timeout: {str(e)}",
                "parsed": {},
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
        """Parse httpx output (for ProjectDiscovery version)"""
        results = {
            "urls": [],
            "technologies": [],
            "status_codes": {},
            "titles": {},
        }

        # Parse JSON lines
        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                url = data.get("url", "")

                if url:
                    results["urls"].append(url)
                    results["status_codes"][url] = data.get("status_code") or data.get(
                        "status-code"
                    )
                    results["titles"][url] = data.get("title", "")

                    # Extract technologies
                    if "tech" in data:
                        for tech in data["tech"]:
                            if tech not in results["technologies"]:
                                results["technologies"].append(tech)

            except json.JSONDecodeError:
                continue

        return results
