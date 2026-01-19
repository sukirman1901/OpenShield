"""
Arjun tool wrapper for HTTP parameter discovery
Includes Python-based fallback using common parameter wordlist and response analysis
"""

import json
import os
import re
import shutil
import time
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

from tools.base_tool import BaseTool


# Common parameter names to test
COMMON_PARAMS = [
    # Authentication & User
    "id",
    "user",
    "username",
    "login",
    "email",
    "password",
    "pass",
    "passwd",
    "user_id",
    "userid",
    "uid",
    "member",
    "account",
    "token",
    "auth",
    "key",
    "api_key",
    "apikey",
    "access_token",
    "session",
    "sessionid",
    "csrf",
    # Data & Content
    "name",
    "title",
    "content",
    "body",
    "text",
    "message",
    "description",
    "data",
    "value",
    "type",
    "category",
    "tag",
    "status",
    "state",
    # Pagination & Filtering
    "page",
    "p",
    "limit",
    "offset",
    "size",
    "count",
    "num",
    "start",
    "end",
    "sort",
    "order",
    "orderby",
    "filter",
    "search",
    "query",
    "q",
    "keyword",
    # File & Path
    "file",
    "filename",
    "path",
    "url",
    "uri",
    "src",
    "source",
    "dest",
    "destination",
    "dir",
    "folder",
    "download",
    "upload",
    "image",
    "img",
    # Actions & Operations
    "action",
    "cmd",
    "command",
    "do",
    "func",
    "function",
    "method",
    "mode",
    "op",
    "operation",
    "task",
    "step",
    "process",
    "callback",
    "return",
    # Format & Output
    "format",
    "output",
    "response",
    "view",
    "template",
    "layout",
    "theme",
    "lang",
    "language",
    "locale",
    "debug",
    "verbose",
    "raw",
    "json",
    "xml",
    # Redirect & Navigation
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "prev",
    "back",
    "return_url",
    "returnurl",
    "goto",
    "target",
    "ref",
    "referer",
    # Common IDs
    "item",
    "item_id",
    "product",
    "product_id",
    "post",
    "post_id",
    "article",
    "article_id",
    "blog",
    "comment",
    "comment_id",
    "order",
    "order_id",
    # Security sensitive
    "admin",
    "role",
    "permission",
    "priv",
    "privilege",
    "level",
    "group",
    "access",
    "allow",
    "deny",
    "grant",
    "revoke",
    "secret",
    "private",
    # Misc
    "date",
    "time",
    "timestamp",
    "version",
    "v",
    "code",
    "hash",
    "signature",
    "sig",
    "nonce",
    "random",
    "salt",
    "iv",
    "from",
    "to",
    "cc",
    "bcc",
]

# Extended wordlist for thorough scans
EXTENDED_PARAMS = COMMON_PARAMS + [
    # API parameters
    "api",
    "api_version",
    "client_id",
    "client_secret",
    "grant_type",
    "scope",
    "state",
    "response_type",
    "code",
    "refresh_token",
    # Database
    "table",
    "column",
    "field",
    "row",
    "db",
    "database",
    "schema",
    "select",
    "where",
    "join",
    "group",
    "having",
    "distinct",
    # Network
    "host",
    "port",
    "ip",
    "domain",
    "subdomain",
    "protocol",
    "scheme",
    "proxy",
    "timeout",
    "retry",
    "max",
    "min",
    # File operations
    "read",
    "write",
    "append",
    "delete",
    "remove",
    "create",
    "update",
    "copy",
    "move",
    "rename",
    "chmod",
    "chown",
    "exec",
    "execute",
    # System
    "system",
    "shell",
    "bash",
    "sh",
    "powershell",
    "ps",
    "run",
    "include",
    "require",
    "import",
    "load",
    "module",
    "plugin",
    # More IDs
    "cat",
    "cat_id",
    "parent",
    "parent_id",
    "child",
    "children",
    "menu",
    "nav",
    "sidebar",
    "header",
    "footer",
    "widget",
]


class ArjunTool(BaseTool):
    """Wrapper for Arjun - HTTP Parameter Discovery Tool with Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "arjun"
        self._cli_available = self._check_cli_available()
        self.output_file = None

    def _check_cli_available(self) -> bool:
        """Check if arjun CLI is installed"""
        return shutil.which("arjun") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build arjun command"""
        if not self._cli_available:
            return ["echo", "Using Python fallback parameter discovery"]

        cmd = ["arjun", "-u", target, "--json"]

        # Add optional arguments
        if kwargs.get("method"):
            cmd.extend(["-m", kwargs["method"]])

        if kwargs.get("threads"):
            cmd.extend(["-t", str(kwargs["threads"])])

        if kwargs.get("delay"):
            cmd.extend(["--delay", str(kwargs["delay"])])

        # Output to a temporary JSON file
        self.output_file = f"arjun_{self._get_timestamp()}.json"
        cmd.extend(["-oJ", self.output_file])

        return cmd

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute arjun - uses Python fallback if CLI not available"""
        if self._cli_available:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_discovery(target, **kwargs)

    async def _execute_python_discovery(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute parameter discovery using Python httpx"""
        import httpx

        start_time = datetime.now()

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        method = kwargs.get("method", "GET").upper()
        thorough = kwargs.get("thorough", False)

        # Select parameter list
        params_to_test = EXTENDED_PARAMS if thorough else COMMON_PARAMS

        found_params = []
        tested_count = 0

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                # Get baseline response
                try:
                    if method == "GET":
                        baseline = await client.get(target)
                    else:
                        baseline = await client.request(method, target)

                    baseline_length = len(baseline.content)
                    baseline_status = baseline.status_code
                except httpx.HTTPError as e:
                    return {
                        "tool": self.tool_name,
                        "target": target,
                        "command": f"python_param_discovery({target})",
                        "exit_code": 1,
                        "duration": 0,
                        "timestamp": start_time.isoformat(),
                        "raw_output": "",
                        "error": f"Failed to get baseline: {str(e)}",
                        "parsed": {},
                    }

                # Test parameters in batches
                batch_size = 10
                semaphore = asyncio.Semaphore(5)  # Limit concurrent requests

                async def test_param(param: str) -> Optional[str]:
                    async with semaphore:
                        try:
                            # Use a unique test value to detect real reflection
                            test_value = f"xyztest{param[:3]}789"

                            if method == "GET":
                                test_url = f"{target}?{param}={test_value}"
                                response = await client.get(test_url)
                            else:
                                response = await client.request(
                                    method, target, data={param: test_value}
                                )

                            # Check if parameter has an effect
                            response_length = len(response.content)
                            response_text = response.text.lower()

                            # Parameter is likely valid if:
                            # 1. Response length differs significantly (> 10% and > 100 bytes)
                            # 2. Response contains our unique test value (not just param name)
                            # 3. Different status code indicating the param was processed

                            length_diff = abs(response_length - baseline_length)

                            # Check for value reflection (stronger signal than name reflection)
                            has_value_reflection = test_value.lower() in response_text

                            # Check for error messages mentioning the param (validation errors)
                            has_error_mention = (
                                f'"{param}"' in response_text
                                or f"'{param}'" in response_text
                                or f"parameter {param}" in response_text
                                or f"field {param}" in response_text
                            )

                            status_diff = response.status_code != baseline_status
                            significant_length_change = length_diff > max(
                                100, baseline_length * 0.10
                            )

                            # Skip if this looks like a generic API that reflects everything
                            # (like httpbin.org)
                            if has_value_reflection and "args" in response_text:
                                # Likely a debug/echo endpoint - not a real param
                                return None

                            if (
                                significant_length_change
                                or has_error_mention
                                or (status_diff and response.status_code in [400, 422])
                            ):
                                return param

                            return None

                        except (httpx.HTTPError, asyncio.TimeoutError):
                            return None

                        except (httpx.HTTPError, asyncio.TimeoutError):
                            return None

                # Test all parameters concurrently
                tasks = [test_param(param) for param in params_to_test]
                results = await asyncio.gather(*tasks)

                tested_count = len(params_to_test)
                found_params = [p for p in results if p is not None]

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"python_param_discovery({target})",
                "exit_code": 1,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": str(e),
                "parsed": {},
            }

        duration = (datetime.now() - start_time).total_seconds()

        parsed = {
            "params": found_params,
            "method": method,
            "tested_count": tested_count,
            "found_count": len(found_params),
            "scan_method": "python_httpx",
        }

        # Build human-readable output
        output_lines = [
            f"Python Parameter Discovery for {target}",
            f"Method: {method}",
            f"Tested {tested_count} parameters in {duration:.2f}s",
            f"Found {len(found_params)} potential parameters:",
            "",
        ]

        if found_params:
            for param in found_params:
                output_lines.append(f"  • {param}")
        else:
            output_lines.append("  (no parameters found)")

        raw_output = "\n".join(output_lines)

        return {
            "tool": self.tool_name,
            "target": target,
            "command": f"python_param_discovery({target}, method={method})",
            "exit_code": 0,
            "duration": duration,
            "timestamp": start_time.isoformat(),
            "raw_output": raw_output,
            "error": None,
            "parsed": parsed,
        }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse arjun output"""
        result = {"params": [], "method": "GET", "raw_output": output}

        if self.output_file and os.path.exists(self.output_file):
            try:
                with open(self.output_file, "r") as f:
                    data = json.load(f)

                # Arjun JSON format varies slightly by version, handle common structures
                # Typical: {"url": "...", "params": ["id", "user"], "method": "GET"}
                # Or dictionary of results

                if isinstance(data, dict):
                    # Check if it's the direct result format
                    if "params" in data:
                        result["params"] = data["params"]
                        result["method"] = data.get("method", "GET")
                    else:
                        # Iterate through keys (URLs) if it's a multi-target result
                        for url, info in data.items():
                            if isinstance(info, dict) and "params" in info:
                                result["params"].extend(info["params"])
                                result["method"] = info.get("method", "GET")

                # Cleanup
                os.remove(self.output_file)
            except Exception as e:
                self.logger.error(f"Error parsing Arjun JSON: {e}")

        return result

    def _get_timestamp(self):
        return int(time.time())
