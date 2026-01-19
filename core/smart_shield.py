"""
Guardian Smart Agent - True Agentic Flow for Security Analysis
Inspired by Pulse-CLI SmartAgent

Flow:
1. User message -> Parse intent & extract targets
2. Execute Security Tools (Nmap, Httpx, etc.)
3. Build Context from Scan Results
4. AI Analyzes with Full Context
5. Return Insight to User
"""

import re
import asyncio
import json
import importlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import get_logger
from ai.factory import create_client
from core.workflow import WorkflowEngine


@dataclass
class AgentContext:
    """Context built from real security data for AI analysis."""

    target: Optional[str] = None
    intent: str = "general"
    scan_results: Optional[Dict[str, Any]] = None
    recon_data: Optional[Dict[str, Any]] = None
    vuln_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class AgentResponse:
    """Response from agent execution."""

    message: str
    context: Optional[AgentContext] = None
    raw_data: Optional[Dict[str, Any]] = None


class OpenShieldSmartAgent:
    """
    Smart agent that executes scans FIRST, then uses AI for analysis.
    """

    # Intent patterns for ALL supported tools
    INTENT_PATTERNS = {
        # Core Workflows
        "scan": [
            r"scan\s+(.+)",
            r"port\s+scan\s+(.+)",
            r"check\s+ports\s+(.+)",
        ],
        "recon": [
            r"recon\s+(.+)",
            r"reconnaissance\s+(.+)",
            r"enumerate\s+(.+)",
            r"subdomains\s+(.+)",
        ],
        "web": [
            r"web\s+scan\s+(.+)",
            r"check\s+web\s+(.+)",
            r"vuln\s+scan\s+(.+)",
            r"apa\s+celah\s+(?:dari|di)?\s+(.+)",
            r"analisakan\s+(?:vuln|celah)\s+(.+)",
            r"cari\s+vuln\s+(?:di)?\s+(.+)",
        ],
        "explain": [
            r"explain\s+(.+)",
            r"what\s+is\s+(.+)",
            r"jelaskan\s+(.+)",
            r"apa\s+itu\s+(.+)",
        ],
        "discovery": [
            r"find\s+(.+)",
            r"search\s+(.+)",
            r"carikan\s+(.+)",
            r"screening\s+(.+)",
        ],
        "dorking": [
            r"dork(?:ing)?\s*(.*)",
            r"google\s+dork\s*(.*)",
            r"cari\s+target\s*(.*)",
            r"find\s+vulnerable\s*(.*)",
        ],
        # Specific Tools
        "nmap": [r"nmap\s+(.+)", r"/nmap\s+(.+)"],
        "masscan": [r"masscan\s+(.+)", r"/masscan\s+(.+)"],
        "httpx": [r"httpx\s+(.+)", r"http\s+probe\s+(.+)", r"/httpx\s+(.+)"],
        "subfinder": [r"subfinder\s+(.+)", r"/subfinder\s+(.+)"],
        "amass": [r"amass\s+(.+)", r"/amass\s+(.+)"],
        "nuclei": [r"nuclei\s+(.+)", r"/nuclei\s+(.+)"],
        "whatweb": [r"whatweb\s+(.+)", r"/whatweb\s+(.+)"],
        "wafw00f": [r"wafw00f\s+(.+)", r"check\s+waf\s+(.+)", r"/wafw00f\s+(.+)"],
        "nikto": [r"nikto\s+(.+)", r"/nikto\s+(.+)"],
        "sqlmap": [r"sqlmap\s+(.+)", r"sql\s+injection\s+(.+)", r"sqli\s+(.+)", r"/sqlmap\s+(.+)"],
        "wpscan": [r"wpscan\s+(.+)", r"wordpress\s+scan\s+(.+)", r"/wpscan\s+(.+)"],
        "testssl": [r"testssl\s+(.+)", r"/testssl\s+(.+)"],
        "sslyze": [r"sslyze\s+(.+)", r"ssl\s+check\s+(.+)", r"/sslyze\s+(.+)"],
        "gobuster": [r"gobuster\s+(.+)", r"/gobuster\s+(.+)"],
        "ffuf": [r"ffuf\s+(.+)", r"/ffuf\s+(.+)"],
        "arjun": [r"arjun\s+(.+)", r"param\s+discovery\s+(.+)", r"/arjun\s+(.+)"],
        "xsstrike": [r"xsstrike\s+(.+)", r"xss\s+scan\s+(.+)", r"/xsstrike\s+(.+)"],
        "gitleaks": [r"gitleaks\s+(.+)", r"secret\s+scan\s+(.+)", r"/gitleaks\s+(.+)"],
        "cmseek": [r"cmseek\s+(.+)", r"cms\s+detect\s+(.+)", r"/cmseek\s+(.+)"],
        "dnsrecon": [r"dnsrecon\s+(.+)", r"dns\s+enum\s+(.+)", r"/dnsrecon\s+(.+)"],
    }

    # Map intents to tool class names and modules
    TOOL_MAPPING = {
        "nmap": ("tools.nmap", "NmapTool"),
        "masscan": ("tools.masscan", "MasscanTool"),
        "httpx": ("tools.httpx", "HttpxTool"),
        "subfinder": ("tools.subfinder", "SubfinderTool"),
        "amass": ("tools.amass", "AmassTool"),
        "nuclei": ("tools.nuclei", "NucleiTool"),
        "whatweb": ("tools.whatweb", "WhatWebTool"),
        "wafw00f": ("tools.wafw00f", "Wafw00fTool"),
        "nikto": ("tools.nikto", "NiktoTool"),
        "sqlmap": ("tools.sqlmap", "SQLMapTool"),
        "wpscan": ("tools.wpscan", "WPScanTool"),
        "testssl": ("tools.testssl", "TestSSLTool"),
        "sslyze": ("tools.sslyze", "SSLyzeTool"),
        "gobuster": ("tools.gobuster", "GobusterTool"),
        "ffuf": ("tools.ffuf", "FfufTool"),
        "arjun": ("tools.arjun", "ArjunTool"),
        "xsstrike": ("tools.xsstrike", "XSStrikeTool"),
        "gitleaks": ("tools.gitleaks", "GitleaksTool"),
        "cmseek": ("tools.cmseek", "CMSeekTool"),
        "dnsrecon": ("tools.dnsrecon", "DnsReconTool"),
        "dorking": ("tools.dorking", "DorkingTool"),
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.ai_client = create_client(config)

        # Memory / Context State
        self.conversation_history: List[Dict[str, str]] = []
        self.knowledge_base: Dict[str, Any] = {
            "target": None,
            "infrastructure": {},
            "vulnerabilities": [],
            "recon_data": {},
            "raw_scans": {},
        }

        # Legacy/Helper state needed for logic compatibility
        self._last_target: Optional[str] = None
        self._last_context: Optional[AgentContext] = None

    # ... (existing methods _extract_target, _detect_intent, _run_scan) ...

    def _update_knowledge(self, new_context: AgentContext):
        """Merge new scan results into long-term knowledge base."""
        if new_context.target:
            self.knowledge_base["target"] = new_context.target

        if new_context.scan_results:
            tool = new_context.scan_results.get("tool", "unknown")
            findings = new_context.scan_results.get("findings", [])

            # Store raw output
            self.knowledge_base["raw_scans"][tool] = new_context.scan_results

            # Consolidate vulnerabilities
            if isinstance(findings, list):
                self.knowledge_base["vulnerabilities"].extend(findings)

            # Update specific sections based on tool
            if tool == "nmap":
                self.knowledge_base["infrastructure"]["ports"] = findings
            elif tool in ["whatweb", "wappalyzer"]:
                self.knowledge_base["infrastructure"]["technologies"] = findings

    def _build_analysis_prompt(self, user_message: str, context: AgentContext) -> str:
        """Build prompt with full accumulated knowledge."""
        parts = []
        parts.append("You are OpenShield, a Senior Security Analyst Agent.")
        parts.append(
            "Your goal is to assist the user in penetration testing and security analysis."
        )

        # 0. Agent Capabilities
        available_tools = list(self.TOOL_MAPPING.keys())
        parts.append(f"AVAILABLE TOOLS: {', '.join(available_tools)}")
        parts.append(
            "CAPABILITIES: Web Exploit Generation, Browser-based Analysis (Playwright), Deep Research (CVE/Exa), Remediation."
        )

        parts.append("Use the gathered INTELLIGENCE below to answer the user's request.")
        parts.append("")

        # 1. Target Intelligence (Accumulated)
        if self.knowledge_base["target"]:
            parts.append(f"=== TARGET INTELLIGENCE: {self.knowledge_base['target']} ===")

            if self.knowledge_base["infrastructure"]:
                parts.append("Infrastructure:")
                parts.append(json.dumps(self.knowledge_base["infrastructure"], indent=2))

            if self.knowledge_base["vulnerabilities"]:
                parts.append(
                    f"Known Vulnerabilities ({len(self.knowledge_base['vulnerabilities'])}):"
                )
                # Summarize vulns to save tokens
                for v in self.knowledge_base["vulnerabilities"][:10]:
                    parts.append(f"- {str(v)[:200]}...")
            parts.append("")

        # 2. Current Scan Context (Fresh)
        if context.scan_results:
            parts.append(f"=== NEW SCAN RESULTS ({context.intent}) ===")
            parts.append(json.dumps(context.scan_results, indent=2))
            parts.append("")

        parts.append("=== USER REQUEST ===")
        parts.append(user_message)
        parts.append("")
        parts.append("=== RESPONSE GUIDELINES ===")
        parts.append("1. Answer purely based on the Security Intelligence provided.")
        parts.append("2. If the user asks about previous results, refer to TARGET INTELLIGENCE.")
        parts.append("3. If a new scan happened, analyze the NEW SCAN RESULTS.")
        parts.append("4. Be concise, professional, and actionable.")

        return "\n".join(parts)

    async def run(self, user_message: str) -> AgentResponse:
        """Main agent loop with memory."""
        self.logger.info(f"Agent processing: {user_message}")
        query = ""  # Prevent UnboundLocalError

        # 1. Detect Intent
        intent, target = self._detect_intent(user_message)

        # FORCE Tool Intent if message starts with tool name
        # This makes "nmap target.com" behave exactly like "/nmap target.com"
        # This has HIGHEST priority - if first word is a tool, use it
        first_word = user_message.split()[0].lower()
        tool_intent_forced = False
        if first_word in self.TOOL_MAPPING:
            self.logger.info(f"Hard forcing intent to Tool: {first_word}")
            intent = first_word
            tool_intent_forced = True
            # If target wasn't detected by regex, try to take the second word
            if not target and len(user_message.split()) > 1:
                potential_target = user_message.split()[1]
                # Basic validation (simple dot check)
                if "." in potential_target:
                    target = potential_target

        # FORCE Discovery for explicit search queries
        # ONLY if not already forced to a tool intent
        if not tool_intent_forced and any(
            w in user_message.lower()
            for w in ["carikan", "cari", "find vulnerable", "search for", "dork"]
        ):
            self.logger.info("Hard forcing intent to Discovery (target cleared)")
            intent = "discovery"
            target = None

        # Context-aware target resolution
        if not target and self.knowledge_base["target"] and intent != "discovery":
            # If user implies "this target"
            if any(
                w in user_message.lower()
                for w in ["it", "this", "target", "web", "server", "situ", "sana"]
            ):
                target = self.knowledge_base["target"]

        # Handling Ambiguous Intent (Scan intent but no target)
        # Ef a user says "analyze vulnerable web" without URL, treat as discovery or ask for target
        if intent in ["web", "scan", "recon"] and not target:
            if any(
                w in user_message.lower()
                for w in ["cari", "find", "search", "carikan", "yang", "list", "daftar"]
            ):
                intent = "discovery"
                self.logger.info(f"Ambiguous intent redirected to Discovery: {user_message}")
            else:
                return AgentResponse(
                    message="Target URL or IP not found. Please specify the target (e.g., 'scan example.com') or ask me to find one (e.g., 'find vulnerable websites')."
                )

        # Handling Discovery (Dorking)
        if intent == "discovery" and not target:
            # Extract query early to avoid scope issues
            self.logger.info(f"Processing Discovery Intent for message: {user_message}")
            query = (
                user_message.replace("find", "")
                .replace("search", "")
                .replace("carikan", "")
                .replace("analisakan", "")
                .strip()
            )

            # Only if Exa is configured
            from core.mcp.exa_client import ExaClient

            exa = ExaClient(self.config)

            # ... (Rest of discovery logic is fine) ...
            if exa.api_key:
                try:
                    # ... Exa Logic ...
                    self.logger.info(f"Running Exa discovery for: {query}")
                    results = await exa.search(
                        f"vulnerable websites related to {query} or dork: {query}",
                        num_results=5,
                        use_autoprompt=True,
                    )
                    # ... processing results ...
                    msg = [f"Found {len(results)} potential targets using Exa AI for '{query}':\n"]
                    for idx, res in enumerate(results):
                        msg.append(f"{idx + 1}. {res.get('url')} - {res.get('title')}")
                    msg.append("\nTip: Type 'scan <url>' to start investigating one of these.")
                    return AgentResponse(message="\n".join(msg))
                except Exception as e:
                    self.logger.error(f"Exa Discovery failed: {e}")
                    # Fallback to browser below

            # Smart Fallback: Use Browser Agent for Real Dorking
            from core.browser_agent import BrowserAgent

            self.logger.info("Exa Key missing or failed. Falling back to Browser Agent Dorking...")

            # 1. Ask AI for the best Dork first
            dork_prompt = f"Generate ONE highly effective Google Dork to find: {query}. Return ONLY the dork string."
            dork = await self.ai_client.generate(dork_prompt)
            dork = dork.strip().strip('"')

            # 2. Execute Dork with Browser
            browser = BrowserAgent(
                self.config, self.ai_client, None
            )  # Memory not strictly needed for this

            self.logger.info(f"Navigating Browser to search: {dork}")
            search_results = await browser.google_dork_search(dork, num_results=5)

            if search_results:
                msg = [f"🔍 I have browsed Google for dork: `{dork}` and found:\n"]
                for idx, res in enumerate(search_results):
                    msg.append(f"{idx + 1}. {res.get('url')} ({res.get('title')})")
                msg.append(
                    "\n💡 Action: I can scan any of these. Just type 'scan <number>' or 'scan <url>'."
                )

                # Store in knowledge base for easier reference (e.g. "scan #1")
                self.knowledge_base["recon_data"]["search_results"] = search_results

                return AgentResponse(message="\n".join(msg))
            else:
                return AgentResponse(
                    message=f"I tried browsing for '{dork}' but Google blocked the automation or found nothing. You can try searching manually."
                )

        # 2. Execution Phase
        context = AgentContext(target=target, intent=intent)

        # Run Scanning Tools if intent requires it
        valid_intents = list(self.TOOL_MAPPING.keys()) + ["scan", "recon", "web"]

        if intent in valid_intents:
            if target:
                try:
                    self.logger.info(f"Executing action: {intent} on {target}")
                    results = await self._run_scan(target, intent)
                    context.scan_results = results
                    self._update_knowledge(context)
                except Exception as e:
                    return AgentResponse(message=f"Execution error: {e}")

        # 3. AI Analysis Phase

        # Add to history
        self.conversation_history.append({"role": "user", "content": user_message})

        prompt = self._build_analysis_prompt(user_message, context)

        # CRITICAL: Enforce Identity in System Prompt
        system_instructions = (
            "You are OPENSHIELD (NOT Antigravity). You are an advanced AI Security Agent."
            "\nNEVER identify as Antigravity or Google DeepMind."
            "\nYour job is to scan, analyze, and exploit targets."
            "\nIf no scan results are present, ask for a target."
        )

        response_text = await self.ai_client.generate(prompt, system_prompt=system_instructions)

        # Save response
        self.conversation_history.append({"role": "assistant", "content": response_text})

        return AgentResponse(message=response_text, context=context, raw_data=context.scan_results)

    def _extract_target(self, message: str) -> Optional[str]:
        """Extract domain or IP from message."""
        domain_regex = (
            r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\b"
        )
        ip_regex = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

        match = re.search(domain_regex, message.lower())
        if match:
            return match.group(1)

        match = re.search(ip_regex, message)
        if match:
            return match.group(0)

        return None

    def _detect_intent(self, message: str) -> Tuple[str, Optional[str]]:
        """Detect user intent and target."""
        message_lower = message.lower().strip()
        target = self._extract_target(message)

        for intent, patterns in self.INTENT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    return intent, target

        if target:
            return "scan", target  # Default to scan

        return "general", None

    async def _run_scan(self, target: str, scan_type: str) -> Dict[str, Any]:
        """Execute scan with resilient retry logic."""

        max_retries = 2
        attempt = 0
        last_error = None

        while attempt <= max_retries:
            attempt += 1

            # Check if it matches a specific tool
            if scan_type in self.TOOL_MAPPING:
                module_name, class_name = self.TOOL_MAPPING[scan_type]
                try:
                    module = importlib.import_module(module_name)
                    tool_class = getattr(module, class_name)
                    tool = tool_class(self.config)

                    self.logger.info(f"Running tool: {scan_type} on {target} (Attempt {attempt})")
                    result = await tool.execute(target)

                    if result.get("error"):
                        # If tool returned an explicit error dict
                        raise Exception(result["error"])

                    # Normalize result
                    return {
                        "findings": result.get("parsed", {}),
                        "raw": result.get("raw_output"),
                        "tool": scan_type,
                    }
                except ImportError:
                    return {"error": f"Tool wrapper not found: {scan_type}"}
                except Exception as e:
                    last_error = str(e)
                    self.logger.warning(f"Attempt {attempt} failed for {scan_type}: {e}")

                    # RETRY STRATEGY
                    if attempt <= max_retries:
                        self.logger.info("Applying fallback strategy...")

                        # Example: If Nmap fails, try disabling ping scan (-Pn) via config override
                        if scan_type == "nmap":
                            self.config.setdefault("tools", {}).setdefault("nmap", {})[
                                "default_args"
                            ] = "-Pn -sV"

                        # If Web scan fails, increase timeout
                        elif scan_type in ["httpx", "nuclei", "web"]:
                            self.config.setdefault("tools", {}).setdefault(scan_type, {})[
                                "timeout"
                            ] = 60

                        await asyncio.sleep(1)  # Cooldown
                        continue

            # Fallback to Workflows
            else:
                try:
                    engine = WorkflowEngine(self.config, target)
                    workflow_map = {
                        "scan": "network",
                        "recon": "recon",
                        "web": "web",
                    }
                    wf_name = workflow_map.get(scan_type, "network")
                    results = await engine.run_workflow(wf_name)
                    return results
                except Exception as e:
                    last_error = str(e)
                    self.logger.error(f"Workflow failed: {e}")
                    break

        # If all retries failed
        return {
            "error": f"Tool {scan_type} failed after {attempt} attempts. Last error: {last_error}",
            "findings": [],
        }
