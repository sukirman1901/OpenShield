"""
OpenShield CLI - Main entry point
AI-Powered Penetration Testing Automation Tool
"""

import typer
from rich.console import Console
from rich.panel import Panel
from typing import Optional
from pathlib import Path
import sys

# Import command groups
from cli.commands import init, scan, recon, analyze, report, workflow, ai_explain, chat, exploit

# Initialize Typer app
app = typer.Typer(
    name="openshield",
    help="🔐 OpenShield - AI-Powered Penetration Testing CLI Tool",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()

# Register command groups
app.command(name="init")(init.init_command)
app.command(name="scan")(scan.scan_command)
app.command(name="recon")(recon.recon_command)
app.command(name="analyze")(analyze.analyze_command)
app.command(name="report")(report.report_command)
app.command(name="workflow")(workflow.workflow_command)
app.command(name="ai")(ai_explain.explain_command)
app.command(name="chat")(chat.chat_command)
app.command(name="exploit")(exploit.exploit_command)


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    """
    OpenShield - AI-Powered Penetration Testing CLI Tool

    Leverage Google Gemini AI to orchestrate intelligent penetration testing workflows.
    """
    if ctx.invoked_subcommand is None:
        # Launch TUI by default
        try:
            from cli.tui import OpenShieldApp
            from pathlib import Path

            # Search order for config:
            # 1. Local openshield.yaml
            # 2. config/openshield.yaml
            # 3. ~/.openshield/openshield.yaml
            
            config_path = Path("openshield.yaml")
            
            if not config_path.exists():
                config_path = Path("config/openshield.yaml")
            
            if not config_path.exists():
                config_path = Path.home() / ".openshield" / "openshield.yaml"

            app = OpenShieldApp(str(config_path))
            app.run()
        except Exception as e:
            console.print(f"[bold red]Error launching TUI:[/bold red] {e}")
            # Fallback to help
            # ctx.get_help() ? No, just pass


def version_callback(value: bool):
    """Print version and exit"""
    if value:
        console.print("[bold green]OpenShield[/bold green] v0.1.0")
        console.print("AI-Powered Penetration Testing Tool")
        raise typer.Exit()


@app.command()
def version(
    show: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
):
    """Show OpenShield version"""
    pass


def main():
    """Main entry point"""
    try:
        # Display banner
        banner = """
╔═══════════════════════════════════════════╗
║   🔐 OPENSHIELD - AI Pentest Automation  ║
║   Powered by AI & LangChain              ║
╚═══════════════════════════════════════════╝
"""
        console.print(banner, style="bold cyan")

        # Run app
        app()

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
