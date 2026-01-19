"""
OpenShield Chat - Natural Language Interface
"""

import typer
from pathlib import Path
from rich.console import Console

console = Console()


def chat_command(
    config_file: Path = typer.Option(
        "openshield.yaml", "--config", "-c", help="Configuration file path"
    ),
):
    """
    Start interactive AI chat mode (TUI)
    """
    try:
        from cli.tui import OpenShieldApp

        app = OpenShieldApp(str(config_file))
        app.run()
    except ImportError as e:
        console.print(f"[bold red]Error loading TUI:[/bold red] {e}")
        console.print("Make sure 'textual' is installed: pip install textual")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
