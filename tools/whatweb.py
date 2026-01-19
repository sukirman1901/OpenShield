"""
WhatWeb tool wrapper for web technology fingerprinting
Supports external whatweb CLI and Python httpx fallback
"""

import re
import subprocess
from typing import Dict, Any, List
from datetime import datetime

from tools.base_tool import BaseTool


class WhatWebTool(BaseTool):
    """WhatWeb technology fingerprinting wrapper with Python fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "whatweb"
        self._has_cli = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if whatweb CLI is available"""
        try:
            result = subprocess.run(
                ["whatweb", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build whatweb command"""
        if not self._has_cli:
            return ["echo", "Using Python technology detection"]

        command = ["whatweb"]
        command.extend(["--log-json=-"])

        aggression = kwargs.get("aggression", 1)
        command.extend(["-a", str(aggression)])

        if kwargs.get("follow_redirects", True):
            command.append("--follow-redirect=always")

        user_agent = kwargs.get("user_agent", "OpenShield-Scanner")
        command.extend(["--user-agent", user_agent])

        command.append(target)
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute technology detection"""
        if self._has_cli:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_detection(target, **kwargs)

    async def _execute_python_detection(self, target: str, **kwargs) -> Dict[str, Any]:
        """Detect technologies using Python httpx and pattern matching"""
        import httpx

        start_time = datetime.now()

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=30.0, follow_redirects=True, verify=True
            ) as client:
                response = await client.get(target)

                technologies = []
                web_server = None
                cms = None
                programming_languages = []
                javascript_frameworks = []

                headers = dict(response.headers)
                content = response.text.lower()

                # Detect from headers
                server = headers.get("server", "")
                if server:
                    technologies.append({"name": server, "source": "header"})
                    web_server = server

                powered_by = headers.get("x-powered-by", "")
                if powered_by:
                    technologies.append({"name": powered_by, "source": "header"})
                    if "php" in powered_by.lower():
                        programming_languages.append("PHP")
                    elif "asp" in powered_by.lower():
                        programming_languages.append("ASP.NET")

                # Detect from cookies
                cookies = headers.get("set-cookie", "")
                if "phpsessid" in cookies.lower():
                    programming_languages.append("PHP")
                if "asp.net" in cookies.lower():
                    programming_languages.append("ASP.NET")
                if "jsessionid" in cookies.lower():
                    programming_languages.append("Java")

                # Detect CMS from content
                cms_patterns = {
                    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
                    "Joomla": [r"joomla", r"/components/com_"],
                    "Drupal": [r"drupal", r"sites/default/files"],
                    "Shopify": [r"shopify", r"cdn.shopify.com"],
                    "Wix": [r"wix.com", r"wixstatic.com"],
                    "Squarespace": [r"squarespace"],
                    "Webflow": [r"webflow"],
                    "Ghost": [r"ghost.io", r'"ghost"'],
                    "Magento": [r"magento", r"mage/"],
                }

                for cms_name, patterns in cms_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            cms = cms_name
                            technologies.append(
                                {"name": cms_name, "source": "content", "type": "CMS"}
                            )
                            break
                    if cms:
                        break

                # Detect JS frameworks
                js_patterns = {
                    "React": [r"react", r"_reactRoot", r"__NEXT_DATA__"],
                    "Vue.js": [r"vue\.js", r"v-bind", r"v-on", r"nuxt"],
                    "Angular": [r"angular", r"ng-app", r"ng-controller"],
                    "jQuery": [r"jquery", r"\$\(document\)"],
                    "Bootstrap": [r"bootstrap\.css", r"bootstrap\.js"],
                    "Tailwind": [r"tailwindcss", r"tailwind\.css"],
                    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
                    "Gatsby": [r"gatsby", r"___gatsby"],
                }

                for framework, patterns in js_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            javascript_frameworks.append(framework)
                            technologies.append(
                                {"name": framework, "source": "content", "type": "JS Framework"}
                            )
                            break

                # Detect CDN/WAF
                cdn_patterns = {
                    "Cloudflare": ["cf-ray", "cloudflare"],
                    "Akamai": ["akamai"],
                    "Fastly": ["fastly"],
                    "AWS CloudFront": ["cloudfront", "x-amz-cf"],
                    "Vercel": ["vercel", "x-vercel"],
                    "Netlify": ["netlify"],
                }

                for cdn, patterns in cdn_patterns.items():
                    header_str = str(headers).lower()
                    for pattern in patterns:
                        if pattern in header_str or pattern in content:
                            technologies.append(
                                {"name": cdn, "source": "header", "type": "CDN/WAF"}
                            )
                            break

                # Detect analytics
                if "google-analytics" in content or "gtag" in content or "ga.js" in content:
                    technologies.append(
                        {"name": "Google Analytics", "source": "content", "type": "Analytics"}
                    )
                if "facebook.com/tr" in content or "fbevents" in content:
                    technologies.append(
                        {"name": "Facebook Pixel", "source": "content", "type": "Analytics"}
                    )

                duration = (datetime.now() - start_time).total_seconds()

                parsed = {
                    "technologies": [t["name"] for t in technologies],
                    "technologies_detailed": technologies,
                    "web_server": web_server,
                    "cms": cms,
                    "programming_languages": list(set(programming_languages)),
                    "javascript_frameworks": list(set(javascript_frameworks)),
                    "http_status": response.status_code,
                    "url": str(response.url),
                    "headers": headers,
                }

                return {
                    "tool": self.tool_name,
                    "target": target,
                    "command": f"httpx.get({target}) + pattern matching",
                    "exit_code": 0,
                    "duration": duration,
                    "timestamp": start_time.isoformat(),
                    "raw_output": f"Detected {len(technologies)} technologies",
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
        """Parse whatweb JSON output"""
        import json

        results = {
            "technologies": [],
            "web_server": None,
            "programming_languages": [],
            "cms": None,
            "javascript_frameworks": [],
            "http_status": None,
            "plugins": [],
        }

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                if "http_status" in data:
                    results["http_status"] = data["http_status"]

                plugins = data.get("plugins", {})

                for plugin_name, plugin_data in plugins.items():
                    tech = {"name": plugin_name, "version": None, "categories": []}

                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version")
                        if version:
                            tech["version"] = version[0] if isinstance(version, list) else version

                    results["plugins"].append(tech)
                    results["technologies"].append(plugin_name)

            except json.JSONDecodeError:
                continue

        return results
