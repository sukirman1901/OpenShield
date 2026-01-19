"""
OpenShield TUI - Agentic AI Security Assistant
Powered by Textual

This is an AGENTIC interface - just chat naturally and the AI will:
1. Understand your intent
2. Automatically select and run the right tools
3. Analyze results and provide insights
4. Suggest next steps
"""

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import Footer, Input, Markdown, Static, OptionList, LoadingIndicator, Button
from textual.widgets.option_list import Option
from textual.screen import ModalScreen
from textual.message import Message

from utils.helpers import load_config
from core.smart_shield import OpenShieldSmartAgent
from cli.commands.registry import CommandRegistry


class CommandPalette(OptionList):
    """Command dropdown that appears when typing /."""

    DEFAULT_CSS = """
    CommandPalette {
        layer: overlay;
        dock: bottom;
        height: auto;
        max-height: 12;
        margin: 0 2 4 2;
        background: #161b22;
        border: solid #30363d;
        display: none;
    }
    
    CommandPalette:focus {
        border: solid #58a6ff;
    }
    
    CommandPalette > .option-list--option {
        padding: 0 1;
    }
    
    CommandPalette > .option-list--option-highlighted {
        background: #21262d;
        color: #58a6ff;
    }
    """

    class Selected(Message):
        """Command was selected."""

        def __init__(self, command: str) -> None:
            super().__init__()
            self.command = command


class ToolsModal(ModalScreen):
    """Modal for selecting security tools."""

    DEFAULT_CSS = """
    ToolsModal {
        align: center middle;
    }
    
    ToolsModal > Vertical {
        width: 70;
        height: auto;
        max-height: 25;
        background: #161b22;
        border: solid #30363d;
        padding: 1 2;
    }
    
    ToolsModal .modal-title {
        text-align: center;
        color: #58a6ff;
        text-style: bold;
        margin-bottom: 1;
    }
    
    ToolsModal .modal-subtitle {
        text-align: center;
        color: #8b949e;
        margin-bottom: 1;
    }
    
    ToolsModal OptionList {
        height: auto;
        max-height: 15;
        background: #0d1117;
        border: none;
    }
    
    ToolsModal OptionList > .option-list--option {
        padding: 0 1;
    }
    
    ToolsModal OptionList > .option-list--option-highlighted {
        background: #21262d;
        color: #58a6ff;
    }
    
    ToolsModal #target-input {
        margin-top: 1;
        height: 3;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, tools: dict, current_target: str = ""):
        super().__init__()
        self.tools = tools
        self.current_target = current_target
        self.selected_tool = None

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("🔧 Select Security Tool", classes="modal-title")
            yield Static("Choose a tool, then enter target", classes="modal-subtitle")
            option_list = OptionList(id="tool-list")

            # Group tools by category
            categories = {
                "🔍 Reconnaissance": ["httpx", "whatweb", "wafw00f", "dnsrecon", "subfinder"],
                "🎯 Vulnerability": ["nuclei", "nikto", "sqlmap", "xsstrike"],
                "🌐 Web Analysis": ["gobuster", "ffuf", "arjun", "wpscan"],
                "🔒 SSL/Crypto": ["testssl", "sslyze"],
                "📡 Network": ["nmap", "masscan"],
            }

            for category, tool_names in categories.items():
                option_list.add_option(Option(f"── {category} ──", disabled=True))
                for tool_name in tool_names:
                    if tool_name in self.tools:
                        class_name = self.tools[tool_name][1]
                        option_list.add_option(
                            Option(f"  {tool_name} - {class_name}", id=tool_name)
                        )

            yield option_list
            yield Input(
                placeholder="Enter target (e.g., example.com)",
                id="target-input",
                value=self.current_target,
            )
            yield Static("Enter: Run Tool | Esc: Cancel", classes="modal-hint")

    def on_mount(self) -> None:
        self.query_one("#tool-list", OptionList).focus()

    @on(OptionList.OptionSelected, "#tool-list")
    def on_tool_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.selected_tool = event.option.id
            self.query_one("#target-input", Input).focus()

    @on(Input.Submitted, "#target-input")
    def on_target_submitted(self, event: Input.Submitted) -> None:
        if self.selected_tool and event.value:
            self.dismiss((self.selected_tool, event.value))
        elif not self.selected_tool:
            self.notify("Please select a tool first", severity="warning")
        else:
            self.notify("Please enter a target", severity="warning")

    def action_cancel(self) -> None:
        self.dismiss(None)


class ModelsModal(ModalScreen):
    """Modal for selecting AI models."""

    DEFAULT_CSS = """
    ModelsModal {
        align: center middle;
    }
    
    ModelsModal > Vertical {
        width: 60;
        height: auto;
        max-height: 20;
        background: #161b22;
        border: solid #30363d;
        padding: 1 2;
    }
    
    ModelsModal .modal-title {
        text-align: center;
        color: #58a6ff;
        text-style: bold;
        margin-bottom: 1;
    }
    
    ModelsModal OptionList {
        height: auto;
        max-height: 12;
        background: #0d1117;
        border: none;
    }
    
    ModelsModal OptionList > .option-list--option {
        padding: 0 1;
    }
    
    ModelsModal OptionList > .option-list--option-highlighted {
        background: #21262d;
        color: #58a6ff;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, models: list, current: str):
        super().__init__()
        self.models = models
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("Select Model", classes="modal-title")
            option_list = OptionList(id="model-list")
            for model in self.models:
                marker = "> " if model["id"] == self.current else "  "
                label = f"{marker}{model['name']}"
                option_list.add_option(Option(label, id=model["id"]))
            yield option_list
            yield Static("Enter: Select | Esc: Cancel", classes="modal-hint")

    def on_mount(self) -> None:
        self.query_one("#model-list", OptionList).focus()

    @on(OptionList.OptionSelected, "#model-list")
    def on_model_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ThinkingWidget(Static):
    """Thinking bubble with loading animation."""

    def compose(self) -> ComposeResult:
        yield LoadingIndicator()


class QuickActionButton(Button):
    """Quick action button for common operations."""

    DEFAULT_CSS = """
    QuickActionButton {
        min-width: 12;
        height: 3;
        margin: 0 1;
        background: #21262d;
        color: #c9d1d9;
        border: solid #30363d;
    }
    
    QuickActionButton:hover {
        background: #30363d;
        border: solid #58a6ff;
    }
    
    QuickActionButton:focus {
        background: #388bfd;
        color: white;
    }
    """


class OpenShieldApp(App):
    """OpenShield - Agentic AI Security Assistant."""

    TITLE = "OpenShield AI"

    CSS = """
    /* Modern Theme - Deep Dark & Neon Accents */
    Screen {
        background: #11111b;
    }
    
    #main-container {
        height: 1fr;
    }
    
    #chat {
        height: 1fr;
        padding: 1 2;
        margin-bottom: 5;
        scrollbar-size: 1 1;
        scrollbar-color: #45475a;
        overflow-y: auto;
    }
    
    /* Welcome message */
    .welcome {
        color: #a6e3a1;
        background: #1e1e2e;
        padding: 1 2;
        margin: 1 2;
        border: solid #a6e3a1;
        text-align: center;
    }
    
    /* USER MESSAGES */
    .user-msg {
        text-align: right;
        color: #89b4fa;
        background: #1e1e2e;
        padding: 1 2;
        margin: 1 0 1 8;
        border-right: thick #89b4fa;
        text-style: bold;
    }
    
    /* AI MESSAGES */
    .ai-msg {
        color: #cdd6f4;
        background: #181825;
        padding: 1 2;
        margin: 1 8 1 0;
        border-left: thick #a6e3a1;
    }
    
    /* Tool execution messages */
    .tool-msg {
        color: #f9e2af;
        background: #1e1e2e;
        padding: 1 2;
        margin: 1 4;
        border-left: thick #f9e2af;
        text-style: italic;
    }
    
    .thinking {
        color: #f5e0dc;
        text-style: italic;
        padding: 1 2;
        margin-top: 1;
        opacity: 0.7;
        height: 3;
        width: 100%;
    }
    
    /* Quick Actions Bar */
    #quick-actions {
        dock: bottom;
        height: 5;
        padding: 1 2;
        background: #161b22;
        border-top: solid #30363d;
    }
    
    #quick-actions-row {
        height: 3;
        align: center middle;
    }
    
    /* INPUT AREA */
    #input-area {
        dock: bottom;
        height: auto;
        padding: 1 2;
        background: #11111b;
    }
    
    #input {
        height: 3;
        background: #1e1e2e;
        border: solid #45475a;
        color: #cdd6f4;
    }
    
    #input:focus {
        border: solid #89b4fa;
        background: #1e1e2e;
    }
    
    #status {
        height: 1;
        background: transparent;
        color: #6c7086;
        padding: 0 1;
        text-align: right;
        text-style: italic;
    }
    
    Footer {
        background: #181825;
        color: #89b4fa;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear", "Clear"),
        Binding("ctrl+t", "show_tools", "Tools"),
        Binding("escape", "close_palette", "Close Palette", show=False),
    ]

    def __init__(self, config_path="openshield.yaml"):
        super().__init__()
        self.config_path = config_path
        self.config = load_config(self.config_path)
        self.agent = OpenShieldSmartAgent(self.config)
        self.command_registry = CommandRegistry(self)
        self._palette_visible = False
        self._current_target = ""

        # Connect Logger to TUI
        from utils.logger import get_logger

        logger = get_logger(self.config)
        logger.add_callback(self.on_log_event)

    def on_log_event(self, level: str, message: str):
        """Handle log events from background threads"""
        self.call_from_thread(self._display_log, level, message)

    def _display_log(self, level: str, message: str):
        """Display log in chat window"""
        if level not in ["TOOL", "AI", "ERROR", "WARNING"]:
            if "Executing" not in message and "Running" not in message:
                return

        icon = "ℹ️"
        css_class = "tool-msg"

        if level == "TOOL":
            icon = "🛠️"
        elif level == "AI":
            icon = "🧠"
        elif level == "ERROR":
            icon = "❌"
        elif level == "WARNING":
            icon = "⚠️"

        formatted = f"{icon} {message}"

        chat = self.query_one("#chat", VerticalScroll)
        chat.mount(Static(formatted, classes=css_class))
        self.call_later(self._scroll_chat_end)

    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="chat")
        yield CommandPalette(id="palette")

        # Quick Actions Bar
        with Horizontal(id="quick-actions"):
            with Horizontal(id="quick-actions-row"):
                yield QuickActionButton("🔧 Tools", id="btn-tools")
                yield QuickActionButton("🔍 Full Scan", id="btn-fullscan")
                yield QuickActionButton("🌐 Web Audit", id="btn-webaudit")
                yield QuickActionButton("🗜️ Compact", id="btn-compact")
                yield QuickActionButton("🤖 Models", id="btn-models")

        with Vertical(id="input-area"):
            yield Input(
                placeholder="💬 Chat naturally - e.g., 'analyze example.com for vulnerabilities'",
                id="input",
            )
            model_name = self.agent.ai_client.model_name
            yield Static(f"🔐 OpenShield AI | {model_name} | Ctrl+T: Tools", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#input", Input).focus()
        chat = self.query_one("#chat", VerticalScroll)

        # Welcome message
        welcome_text = """🔐 **OpenShield AI** - Agentic Security Assistant

**Just chat naturally!** I'll automatically:
• Understand your security goals
• Select and run the right tools
• Analyze results and find vulnerabilities
• Suggest next steps

**Try saying:**
• "Scan example.com for vulnerabilities"
• "Check what technologies example.com uses"
• "Find subdomains for example.com"
• "Is there a WAF protecting example.com?"

**Quick Actions:** Use buttons below or press `Ctrl+T` for tools menu
**Commands:** Type `/` to see all available commands"""

        chat.mount(Markdown(welcome_text, classes="welcome"))
        self._populate_palette()

    def _populate_palette(self, filter_text: str = "") -> None:
        palette = self.query_one("#palette", CommandPalette)
        palette.clear_options()

        for cmd in self.command_registry.list_commands():
            cmd_text = f"/{cmd.name}"
            if filter_text and not cmd_text.startswith(filter_text):
                continue

            aliases = f" ({', '.join(cmd.aliases)})" if cmd.aliases else ""
            label = f"/{cmd.name}{aliases} - {cmd.description}"
            palette.add_option(Option(label, id=cmd.name))

    def _show_palette(self) -> None:
        if not self._palette_visible:
            palette = self.query_one("#palette", CommandPalette)
            palette.styles.display = "block"
            self._palette_visible = True

    def _hide_palette(self) -> None:
        if self._palette_visible:
            palette = self.query_one("#palette", CommandPalette)
            palette.styles.display = "none"
            self._palette_visible = False

    def action_close_palette(self) -> None:
        self._hide_palette()
        self.query_one("#input", Input).focus()

    def action_show_tools(self) -> None:
        """Show tools selection modal"""
        self.show_tools_modal()

    @on(Input.Changed, "#input")
    def on_input_changed(self, event: Input.Changed) -> None:
        value = event.value
        if value.startswith("/"):
            self._populate_palette(value)
            self._show_palette()
        else:
            self._hide_palette()

    @on(OptionList.OptionSelected, "#palette")
    def on_palette_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            cmd = self.command_registry.get(event.option.id)
            if cmd:
                input_widget = self.query_one("#input", Input)
                input_widget.value = f"/{cmd.name} "
                input_widget.focus()
                self._hide_palette()

    @on(Button.Pressed, "#btn-tools")
    def on_tools_pressed(self) -> None:
        self.show_tools_modal()

    @on(Button.Pressed, "#btn-fullscan")
    def on_fullscan_pressed(self) -> None:
        input_widget = self.query_one("#input", Input)
        input_widget.value = "Run a full security scan on "
        input_widget.focus()

    @on(Button.Pressed, "#btn-webaudit")
    def on_webaudit_pressed(self) -> None:
        input_widget = self.query_one("#input", Input)
        input_widget.value = "Audit the web security of "
        input_widget.focus()

    @on(Button.Pressed, "#btn-models")
    def on_models_pressed(self) -> None:
        self.show_models_modal()

    @on(Button.Pressed, "#btn-compact")
    def on_compact_pressed(self) -> None:
        self._run_command("/compact")

    def _add_user(self, text: str) -> None:
        chat = self.query_one("#chat", VerticalScroll)
        chat.mount(Static(text, classes="user-msg"))
        self.call_later(self._scroll_chat_end)

    def _add_response(self, text: str) -> None:
        chat = self.query_one("#chat", VerticalScroll)
        chat.mount(Markdown(text, classes="ai-msg"))
        self.call_later(self._scroll_chat_end)

    def _add_thinking(self) -> None:
        chat = self.query_one("#chat", VerticalScroll)
        chat.mount(ThinkingWidget(classes="thinking", id="thinking"))
        self.call_later(self._scroll_chat_end)

    def _remove_thinking(self) -> None:
        try:
            thinking = self.query_one("#thinking")
            thinking.remove()
        except Exception:
            pass

    def _scroll_chat_end(self) -> None:
        try:
            chat = self.query_one("#chat", VerticalScroll)
            chat.scroll_end(animate=False)
        except Exception:
            pass

    def _update_status(self) -> None:
        model_name = self.agent.ai_client.model_name
        target_info = f" | 🎯 {self._current_target}" if self._current_target else ""
        self.query_one("#status", Static).update(f"🔐 OpenShield AI | {model_name}{target_info}")

    def show_tools_modal(self) -> None:
        """Show tools selection modal"""

        def on_select(result) -> None:
            if result:
                tool_name, target = result
                self._current_target = target
                self._update_status()
                # Run the tool via natural language
                self._add_user(f"Run {tool_name} on {target}")
                self._add_thinking()
                self._handle_chat(f"{tool_name} {target}")
            self.query_one("#input", Input).focus()

        self.push_screen(ToolsModal(self.agent.TOOL_MAPPING, self._current_target), on_select)

    def show_models_modal(self) -> None:
        models = self.agent.ai_client.list_models()
        current = self.agent.ai_client.model_name

        def on_select(model_id: str | None) -> None:
            if model_id:
                self.agent.ai_client.set_model(model_id)
                self._add_response(f"✅ Switched to model: **{model_id}**")
                self._update_status()
            self.query_one("#input", Input).focus()

        self.push_screen(ModelsModal(models, current), on_select)

    @on(Input.Submitted, "#input")
    def on_submit(self, event: Input.Submitted) -> None:
        msg = event.value.strip()
        if not msg:
            return

        event.input.value = ""
        self._hide_palette()
        self._add_user(msg)

        # Extract target from message for status
        words = msg.split()
        for word in words:
            if "." in word and not word.startswith("/"):
                self._current_target = word
                self._update_status()
                break

        # Check for slash commands
        if msg.startswith("/"):
            self._run_command(msg)
        else:
            self._add_thinking()
            self._handle_chat(msg)

    @work(exclusive=True)
    async def _run_command(self, cmd: str) -> None:
        try:
            result = await self.command_registry.execute(cmd)
            if result:
                self._add_response(result)
        except Exception as e:
            self._add_response(f"❌ Error: {e}")

    @work(exclusive=True)
    async def _handle_chat(self, msg: str) -> None:
        try:
            result = await self.agent.run(msg)
            self._remove_thinking()
            self._add_response(result.message)
        except Exception as e:
            self._remove_thinking()
            self._add_response(f"❌ Error: {e}")

    def action_clear(self) -> None:
        chat = self.query_one("#chat", VerticalScroll)
        chat.remove_children()

        # Re-add welcome
        welcome = "🔐 **OpenShield AI** - Chat cleared. Ready for new session!"
        chat.mount(Markdown(welcome, classes="welcome"))


if __name__ == "__main__":
    app = OpenShieldApp()
    app.run()
