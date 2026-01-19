"""
Command Registry for Guardian CLI
Handles slash commands like /scan, /help, /models
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, Dict, List, Optional
import asyncio

if TYPE_CHECKING:
    from cli.tui import GuardianApp

from utils.logger import get_logger
from core.workflow import WorkflowEngine

log = get_logger(__name__)


class Command:
    """Represents a slash command."""

    def __init__(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        usage: str = "",
        aliases: List[str] = None,
    ):
        self.name = name
        self.handler = handler
        self.description = description
        self.usage = usage or f"/{name}"
        self.aliases = aliases or []


class CommandRegistry:
    """Registry for slash commands."""

    def __init__(self, app: "GuardianApp"):
        self.app = app
        self._commands: Dict[str, Command] = {}
        self._register_builtin_commands()

    def register(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        usage: str = "",
        aliases: List[str] = None,
    ):
        cmd = Command(name, handler, description, usage, aliases)
        self._commands[name.lower()] = cmd
        for alias in aliases or []:
            self._commands[alias.lower()] = cmd

    def get(self, name: str) -> Optional[Command]:
        return self._commands.get(name.lower())

    def list_commands(self) -> List[Command]:
        seen = set()
        commands = []
        for cmd in self._commands.values():
            if cmd.name not in seen:
                seen.add(cmd.name)
                commands.append(cmd)
        return sorted(commands, key=lambda c: c.name)

    async def execute(self, command_str: str) -> Optional[str]:
        """Execute a command string like '/scan google.com'"""
        parts = command_str.strip().split(maxsplit=1)
        cmd_name = parts[0].lstrip("/").lower()
        args = parts[1] if len(parts) > 1 else ""

        cmd = self.get(cmd_name)

        if not cmd:
            return f"Unknown command: /{cmd_name}. Type /help for available commands."

        try:
            return await cmd.handler(args)
        except Exception as e:
            log.error(f"Command {cmd_name} failed: {e}")
            return f"Error executing command: {e}"

    def _register_builtin_commands(self):
        """Register default commands"""
        self.register(
            "help", self._cmd_help, "Show available commands", "/help [command]", aliases=["h", "?"]
        )
        self.register(
            "models", self._cmd_models, "Switch AI Model", "/models", aliases=["model", "ai"]
        )
        self.register("scan", self._cmd_scan, "Run Port Scan", "/scan <target>", aliases=["s"])
        # self.register("recon", self._cmd_recon, "Run Full Recon", "/recon <target>", aliases=["r"])
        self.register("web", self._cmd_web, "Run Web Scan", "/web <target>", aliases=["w"])
        self.register("clear", self._cmd_clear, "Clear chat history", "/clear", aliases=["cls"])
        self.register(
            "compact",
            self._cmd_compact,
            "Summarize & compress context",
            "/compact",
            aliases=["c", "summarize"],
        )
        self.register(
            "context",
            self._cmd_context,
            "Show current context info",
            "/context",
            aliases=["ctx", "status"],
        )

        # Dyna-register all tools from Agent
        if hasattr(self.app, "agent") and hasattr(self.app.agent, "TOOL_MAPPING"):
            for tool_name, tool_info in self.app.agent.TOOL_MAPPING.items():
                # tool_info is tuple: (module_path, class_name)
                class_name = tool_info[1]
                self.register(
                    tool_name,
                    lambda args, t=tool_name: self._cmd_tool_wrapper(t, args),
                    f"Run {class_name} Security Scanner",
                    f"/{tool_name} <target>",
                )

    async def _cmd_tool_wrapper(self, tool_name: str, args: str) -> str:
        if not args:
            return f"Usage: `/{tool_name} <target>` (e.g., `/{tool_name} example.com`)"

        target = args.strip()
        self.app._add_response(f"🛠️ Executing **{tool_name}** on `{target}`...")

        try:
            # Direct call to agent's scan logic
            # We access the internal _run_scan for direct tool usage
            results = await self.app.agent._run_scan(target, tool_name)

            # Update knowledge base
            from core.smart_shield import AgentContext

            ctx = AgentContext(target=target, intent=tool_name, scan_results=results)
            self.app.agent._update_knowledge(ctx)

            import json

            return f"✅ **{tool_name}** Finished.\n```json\n{json.dumps(results, indent=2)}\n```"
        except Exception as e:
            return f"❌ Tool execution failed: {e}"

    async def _cmd_help(self, args: str) -> str:
        if args:
            cmd = self.get(args.strip())
            if cmd:
                return f"**/{cmd.name}**\n\n{cmd.description}\nUsage: `{cmd.usage}`"
            return f"Unknown command: {args}"

        lines = ["**Available Commands**\n"]
        # Group by type
        core_cmds = []
        tool_cmds = []

        for cmd in self.list_commands():
            if cmd.name in self.app.agent.TOOL_MAPPING:
                tool_cmds.append(f"`/{cmd.name}`")
            else:
                core_cmds.append(f"- `/{cmd.name}`: {cmd.description}")

        lines.extend(core_cmds)
        lines.append("\n**Tools:**")
        lines.append(", ".join(tool_cmds))

        return "\n".join(lines)

    async def _cmd_models(self, args: str) -> Optional[str]:
        # This triggers the UI modal, returns None so nothing prints to chat
        self.app.show_models_modal()
        return None

    async def _cmd_clear(self, args: str) -> Optional[str]:
        self.app.action_clear()
        return None

    async def _cmd_compact(self, args: str) -> str:
        """Compact/summarize the conversation to save context space."""
        self.app._add_response("🗜️ Compacting conversation...")

        try:
            summary = await self.app.agent.compact()

            # Show summary in chat
            result = [
                "✅ **Conversation Compacted**",
                "",
                "**Session Summary:**",
                summary,
                "",
                f"💡 Context reduced. Token usage: ~{self.app.agent._get_context_token_count()} tokens",
            ]
            return "\n".join(result)
        except Exception as e:
            return f"❌ Compact failed: {e}"

    async def _cmd_context(self, args: str) -> str:
        """Show current context information."""
        agent = self.app.agent
        token_count = agent._get_context_token_count()
        context_limit = agent.config.get("ai", {}).get("context_limit", 32000)
        usage_percent = (token_count / context_limit) * 100

        lines = [
            "📊 **Current Context Status**",
            "",
            f"🎯 **Target:** {agent.knowledge_base.get('target', 'None')}",
            f"💬 **Messages:** {len(agent.conversation_history)}",
            f"🔢 **Tokens:** ~{token_count:,} / {context_limit:,} ({usage_percent:.1f}%)",
            f"🔍 **Vulnerabilities:** {len(agent.knowledge_base.get('vulnerabilities', []))}",
            f"🛠️ **Scans Done:** {list(agent.knowledge_base.get('raw_scans', {}).keys()) or 'None'}",
        ]

        # Show warning if approaching limit
        if usage_percent >= 80:
            lines.append("")
            lines.append(
                "⚠️ **Warning:** Context approaching limit. Consider using `/compact` to summarize."
            )

        return "\n".join(lines)

    async def _cmd_scan(self, args: str) -> str:
        if not args:
            return "Usage: /scan <target>"
        # Map /scan to nmap for simplicity in this context or workflow
        return await self._cmd_tool_wrapper("nmap", args)

    async def _cmd_web(self, args: str) -> str:
        if not args:
            return "Usage: /web <target>"
        # Map /web to simple scanner or browser agent?
        # For now let's map to whatweb + nikto sequence?
        # Or just browser agent if available?
        # Let's use 'browser_agent' logic via intent routing if possible.
        # But here we are in direct command.
        return await self._cmd_tool_wrapper("whatweb", args)
