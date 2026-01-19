<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AI-Gemini%20%7C%20OpenAI%20%7C%20Cliproxy-orange?logo=google&logoColor=white" alt="AI">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
</p>

<h1 align="center">🔐 OpenShield</h1>
<h3 align="center">AI-Powered Penetration Testing Automation Tool</h3>

<p align="center">
  <b>Leverage AI to orchestrate intelligent penetration testing workflows</b><br>
  Automated reconnaissance, vulnerability scanning, exploit generation, and remediation
</p>

---

## 📖 Overview

**OpenShield** is an AI-powered penetration testing CLI tool that uses Large Language Models (Gemini, OpenAI, Cliproxy) to intelligently orchestrate security assessments. Instead of manually running individual tools, simply describe what you want to do in natural language, and OpenShield will:

1. **Understand** your security objectives
2. **Select** the appropriate tools automatically
3. **Execute** scans with optimal configurations
4. **Analyze** results using AI
5. **Generate** exploits and remediation code
6. **Report** findings in professional formats

## ✨ Features

### 🤖 AI-Powered Intelligence
- **Natural Language Interface** - Chat with the AI to run security assessments
- **Smart Tool Selection** - AI automatically selects the best tools for your objectives
- **Intelligent Analysis** - AI interprets scan results and identifies vulnerabilities
- **Exploit Generation** - Automatic PoC exploit code generation
- **Remediation Code** - AI-generated fix recommendations with code samples

### 🛠️ 20+ Integrated Security Tools

| Category | Tools |
|----------|-------|
| **Reconnaissance** | `subfinder`, `amass`, `dnsrecon`, `httpx`, `whatweb`, `wafw00f` |
| **Port Scanning** | `nmap`, `masscan` |
| **Vulnerability Scanning** | `nuclei`, `nikto` |
| **Web Application** | `gobuster`, `ffuf`, `arjun`, `wpscan`, `cmseek` |
| **Injection Testing** | `sqlmap`, `xsstrike` |
| **SSL/TLS Analysis** | `testssl`, `sslyze` |
| **Secret Detection** | `gitleaks` |

### 📊 Professional Reporting
- **Markdown** - Clean, readable reports
- **HTML** - Styled reports for presentations
- **JSON** - Machine-readable output for integration
- **AI Decision Trace** - Full transparency of AI reasoning

### 🎨 Modern TUI Interface
- Beautiful terminal UI powered by Textual
- Real-time scan progress
- Interactive tool selection
- Quick action buttons

## 🏗️ Architecture

```
OpenShield/
├── cli/                    # CLI & TUI interface
│   ├── main.py            # Entry point
│   ├── tui.py             # Terminal UI
│   └── commands/          # CLI commands
├── core/                   # Core AI agents
│   ├── workflow.py        # Workflow orchestration
│   ├── planner.py         # Strategic planning agent
│   ├── tool_agent.py      # Tool selection & execution
│   ├── analyst_agent.py   # Result analysis agent
│   ├── reporter_agent.py  # Report generation
│   ├── chat_agent.py      # Natural language processing
│   ├── smart_shield.py    # Agentic AI controller
│   └── memory.py          # Session state management
├── tools/                  # Security tool wrappers
│   ├── base_tool.py       # Base tool class
│   ├── nmap.py            # Nmap wrapper
│   ├── nuclei.py          # Nuclei wrapper
│   └── ...                # 20+ tool wrappers
├── ai/                     # AI client implementations
│   ├── factory.py         # Client factory
│   ├── gemini_client.py   # Google Gemini
│   └── openai_client.py   # OpenAI/Compatible
├── config/                 # Configuration
│   └── openshield.yaml    # Default config
├── reports/               # Generated reports
└── workflows/             # Workflow definitions
```

## 📋 Requirements

### System Requirements
- **Python** 3.11 or higher
- **Operating System**: Linux, macOS, or Windows (WSL recommended)

### AI Provider (Choose One)
- **Google Gemini** - Requires `GOOGLE_API_KEY`
- **OpenAI** - Requires `OPENAI_API_KEY`
- **Cliproxy** - OpenAI-compatible proxy for accessing multiple AI models (Recommended)
  - Supports Gemini, Claude, GPT, and other models through a unified API
  - Configure with `base_url` in config

### External Security Tools (Optional but Recommended)

OpenShield wraps these external tools. Install the ones you need:

```bash
# Debian/Ubuntu
sudo apt install nmap

# macOS (Homebrew)
brew install nmap

# Go-based tools (requires Go 1.21+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/ffuf@latest
go install github.com/OJ/gobuster/v3@latest

# Python tools
pip install sqlmap

# Other tools - refer to their official documentation
# - testssl.sh: https://github.com/drwetter/testssl.sh
# - nikto: https://github.com/sullo/nikto
# - wpscan: https://github.com/wpscanteam/wpscan
```

> **Note**: OpenShield includes Python-based fallbacks for some tools (e.g., nmap port scanning) when CLI tools are not installed.

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/sukirman1901/OpenShield.git
cd OpenShield
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
.\venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` doesn't exist, install core dependencies:

```bash
pip install typer rich textual langchain langchain-google-genai langchain-openai \
            python-dotenv pyyaml playwright aiohttp beautifulsoup4
```

### 4. Install Playwright Browsers (for web analysis)

```bash
playwright install chromium
```

### 5. Configure API Keys

Create a `.env` file in the project root:

```bash
# For Google Gemini (direct API)
GOOGLE_API_KEY=your_gemini_api_key_here

# For OpenAI (direct API)
OPENAI_API_KEY=your_openai_api_key_here

# For Cliproxy (Recommended - supports multiple models)
# No API key needed if running locally, or set your Cliproxy key
CLIPROXY_API_KEY=your_cliproxy_key_here
```

### 6. Configure OpenShield

Edit `openshield.yaml` or `config/openshield.yaml`:

```yaml
ai:
  # Provider options: gemini, openai, cliproxy
  provider: cliproxy
  
  # Model to use (depends on provider)
  model: gemini-3-pro-preview
  
  # For Cliproxy: specify the base URL of your proxy
  base_url: http://localhost:8317/v1
  
  temperature: 0.2
  max_tokens: 8000
  rate_limit: 2  # Requests per minute

pentest:
  safe_mode: true
  require_confirmation: true
  max_parallel_tools: 3
  tool_timeout: 300

output:
  format: markdown
  save_path: ./reports
```

#### Cliproxy Configuration Example

If using Cliproxy (recommended for flexibility):

```yaml
ai:
  provider: cliproxy
  model: gemini-3-pro-preview  # or claude-3-opus, gpt-4-turbo, etc.
  base_url: http://localhost:8317/v1
  temperature: 0.2
  max_tokens: 8000
  rate_limit: 2
  
  # Optional: List available models for TUI model switcher
  available_models:
    - id: gemini-3-pro-preview
      name: Gemini 3 Pro
    - id: gemini-3-flash-preview
      name: Gemini 3 Flash
    - id: claude-3-opus
      name: Claude 3 Opus
    - id: gpt-4-turbo
      name: GPT-4 Turbo
```

## 💻 Usage

### Launch TUI (Recommended)

```bash
python -m cli.main
```

Or if installed as a package:

```bash
openshield
```

This opens the interactive TUI where you can chat naturally with the AI.

### CLI Commands

#### Quick Port Scan
```bash
python -m cli.main scan --target example.com --ports 80,443,8080
```

#### Reconnaissance Workflow
```bash
python -m cli.main recon --domain example.com
```

#### Full Exploitation Workflow
```bash
python -m cli.main exploit https://example.com
```

#### Run Predefined Workflow
```bash
python -m cli.main workflow --name recon --target example.com
python -m cli.main workflow --name web --target https://example.com
python -m cli.main workflow --name network --target 192.168.1.0/24
```

#### Generate Report
```bash
python -m cli.main report --session-id 20260119_120000 --format html
```

#### Interactive Chat Mode
```bash
python -m cli.main chat
```

### TUI Quick Actions

In the TUI, you can:

- **Chat naturally**: "Scan example.com for vulnerabilities"
- **Use quick buttons**: Tools, Full Scan, Web Audit, Models
- **Slash commands**: Type `/` to see available commands
- **Keyboard shortcuts**:
  - `Ctrl+T` - Open tools menu
  - `Ctrl+L` - Clear chat
  - `Ctrl+C` - Quit

### Example Conversations

```
You: Check what technologies example.com uses
AI: I'll run whatweb and httpx to detect technologies...
    [Running tools...]
    Found: Apache 2.4, PHP 7.4, WordPress 6.0, MySQL

You: Are there any known vulnerabilities?
AI: Based on the detected technologies, I'll run nuclei with 
    relevant templates...
    [Running nuclei...]
    Found 3 vulnerabilities:
    - [HIGH] WordPress < 6.1 XSS vulnerability
    - [MEDIUM] PHP 7.4 EOL
    - [LOW] Apache version disclosure

You: Generate an exploit for the XSS vulnerability
AI: Here's a PoC exploit for the WordPress XSS:
    [Generates Python exploit code with payload]

You: How do I fix this?
AI: Here's the remediation:
    1. Update WordPress to 6.1 or later
    2. [Provides code patches and configuration changes]
```

## 📁 Output & Reports

Reports are saved to the `reports/` directory:

```
reports/
├── session_20260119_120000.json     # Session state
├── report_20260119_120000.md        # Markdown report
├── exploitation_report_20260119.md  # Exploitation details
└── exploitation_results_20260119.json
```

### Report Sections

1. **Executive Summary** - High-level overview for management
2. **Findings Summary** - Vulnerabilities by severity
3. **Technical Findings** - Detailed vulnerability descriptions
4. **Remediation Plan** - Prioritized fix recommendations
5. **AI Decision Trace** - Transparency of AI reasoning
6. **Tools Executed** - Complete tool execution log

## ⚙️ Configuration Reference

### `openshield.yaml`

```yaml
# AI Configuration
ai:
  provider: cliproxy         # gemini, openai, cliproxy (recommended)
  model: gemini-3-pro-preview # Model name
  base_url: http://localhost:8317/v1  # Cliproxy endpoint
  temperature: 0.2          # Creativity (0.0-1.0)
  max_tokens: 8000          # Max response length
  timeout: 60               # API timeout (seconds)
  rate_limit: 2             # Requests per minute

# Penetration Testing Settings
pentest:
  safe_mode: true           # Prevent destructive operations
  max_parallel_tools: 3     # Concurrent tool executions
  require_confirmation: true # Confirm before executing
  max_depth: 3              # Recursive scan depth
  tool_timeout: 300         # Tool execution timeout

# Output Settings
output:
  format: markdown          # markdown, html, json
  save_path: ./reports      # Report output directory
  include_reasoning: true   # Include AI reasoning in reports
  verbosity: normal         # quiet, normal, verbose, debug

# Scope Validation
scope:
  blacklist:                # Never scan these ranges
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
  require_scope_file: false
  max_targets: 100

# Tool-Specific Configuration
tools:
  nmap:
    enabled: true
    default_args: "-sV -sC"
    timing: T4
  nuclei:
    enabled: true
    severity: ["critical", "high", "medium"]
    templates_path: ~/nuclei-templates

# Workflow Settings
workflows:
  timeout: 3600             # Max workflow duration
  save_intermediate: true   # Save results after each step
  resume_on_failure: true   # Continue from checkpoint

# Logging
logging:
  enabled: true
  path: ./logs/openshield.log
  level: INFO
  log_ai_decisions: true
```

## 🔒 Security Considerations

1. **Authorization**: Only scan systems you have explicit permission to test
2. **Safe Mode**: Keep `safe_mode: true` to prevent destructive operations
3. **API Keys**: Never commit `.env` files or API keys to version control
4. **Scope Validation**: Configure blacklist to prevent scanning sensitive networks
5. **Legal Compliance**: Ensure compliance with local laws and regulations

## 🛠️ Development

### Project Structure

```
core/
├── agent.py           # Base agent class
├── planner.py         # Strategic decision agent
├── tool_agent.py      # Tool selection & execution
├── analyst_agent.py   # Result interpretation
├── reporter_agent.py  # Report generation
├── memory.py          # Session state management
└── workflow.py        # Workflow orchestration

tools/
├── base_tool.py       # Base tool wrapper class
├── nmap.py            # Each tool has its own wrapper
└── ...
```

### Adding New Tools

1. Create a new file in `tools/`:

```python
from tools.base_tool import BaseTool

class MyTool(BaseTool):
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "mytool"
    
    def get_command(self, target: str, **kwargs) -> list:
        return ["mytool", target]
    
    def parse_output(self, output: str) -> dict:
        # Parse tool output
        return {"results": [...]}
```

2. Register in `tools/__init__.py`:

```python
from .mytool import MyTool
__all__.append("MyTool")
```

3. Add to `tool_agent.py` available_tools dictionary.

### Running Tests

```bash
python -m pytest tests/
```

## 📝 Changelog

### v0.1.0 (Initial Release)
- Core AI agent system
- 20+ security tool integrations
- TUI interface
- Exploitation workflow
- Report generation

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**OpenShield is intended for authorized security testing only.**

- Always obtain proper authorization before testing any systems
- The developers are not responsible for misuse of this tool
- Use responsibly and ethically
- Comply with all applicable laws and regulations

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) - For nuclei, subfinder, httpx
- [Google](https://ai.google.dev/) - For Gemini AI
- [OpenAI](https://openai.com/) - For GPT models
- [LangChain](https://langchain.com/) - For AI orchestration framework
- All the security tool authors and maintainers

---

<p align="center">
  <b>Built with ❤️ for the security community</b><br>
  <a href="https://github.com/sukirman1901/OpenShield">GitHub</a> •
  <a href="https://github.com/sukirman1901/OpenShield/issues">Issues</a> •
  <a href="https://github.com/sukirman1901/OpenShield/discussions">Discussions</a>
</p>
