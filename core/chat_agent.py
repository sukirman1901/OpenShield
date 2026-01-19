"""
Chat Agent for Guardian
Handles natural language processing and intent classification
"""

import json
import asyncio
from typing import Dict, Any, Optional
from rich.console import Console

from ai.factory import create_client
from core.workflow import WorkflowEngine
from utils.logger import get_logger


class ChatAgent:
    """Agent for handling natural language interaction"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = create_client(config)
        self.logger = get_logger(config)
        self.console = Console()

    async def process_message(self, message: str) -> str:
        """Process a user message and return response"""

        system_prompt = """
        You are Guardian, an AI Penetration Testing Orchestrator.
        Your job is to understand user intent and map it to a specific workflow or provide a chat response.
        
        Available Actions:
        1. RECON: Run reconnaissance on a target (domains, emails, etc.)
        2. WEB_SCAN: Run web application security scan
        3. NETWORK_SCAN: Run network/port scan
        4. GENERAL: General chat about security or capabilities
        
        Output strictly JSON in this format:
        {
            "action": "RECON" | "WEB_SCAN" | "NETWORK_SCAN" | "GENERAL",
            "target": "extracted_target_domain_or_ip",
            "response": "Reply to user if action is GENERAL, or brief confirmation for others"
        }
        """

        try:
            # Get AI decision
            response = await self.client.generate(message, system_prompt=system_prompt)

            # Parse JSON
            intent = self._parse_json(response)

            action = intent.get("action")
            target = intent.get("target")
            reply = intent.get("response", "")

            # Execute action
            if action in ["RECON", "WEB_SCAN", "NETWORK_SCAN"] and target:
                execution_msg = f"🚀 Executing {action} on {target}..."

                # We return this message immediately.
                # The TUI should handle the async execution or we do it here?
                # For TUI, it's better to return a generator or callback.
                # But for now, let's just run it and return the result log.

                workflow_map = {"RECON": "recon", "WEB_SCAN": "web", "NETWORK_SCAN": "network"}
                workflow_name = workflow_map.get(action)

                # Execute workflow
                engine = WorkflowEngine(self.config, target)

                # This might take time, so we should probably notify the user
                # But since this is a simple port, we await it.
                await engine.run_workflow(workflow_name)

                return f"{reply}\n\n✅ Workflow {workflow_name} completed on {target}."

            return reply

        except Exception as e:
            self.logger.error(f"Chat processing error: {e}")
            return f"Error: {str(e)}"

    def _parse_json(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON from text"""
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback
            return {"action": "GENERAL", "response": text}
