# MCP Security Suite 🛡️

**Unified security framework for Model Context Protocol (MCP) servers**

📖 **[Quick Start Guide](QUICKSTART.md)** - Get up and running in 3 minutes!

⚠️ **Important Note for Scanning This Project**: This repository contains intentionally malicious test files in `mcp_test_cases/` and `tests/` directories to validate our detection capabilities. When scanning this project:
- **To exclude test files**: `python3 mighty_mcp.py check . --profile production`
- **To force fresh scan (bypass cache)**: `python3 mighty_mcp.py check . --profile production --no-cache`
- **To see detection working**: `python3 mighty_mcp.py check .` (will show CRITICAL risk - this is expected!)
- **To debug LLM responses**: `python3 mighty_mcp.py check . --deep --debug`
- The malicious test files prove our scanner works correctly

## What is this?

A comprehensive security analysis tool that protects against malicious MCP (Model Context Protocol) servers and tools. MCP servers give AI assistants powerful capabilities - but with that power comes serious security risks. This tool helps identify and prevent those risks.

## Why do you need this?

MCP servers are becoming critical infrastructure for AI applications, but recent research shows:
- **43% of MCP servers have command injection vulnerabilities**
- **30% allow unrestricted URL fetches (SSRF attacks)**
- **22% leak files outside intended directories**
- The GitHub MCP vulnerability showed how prompt injection can leak private repositories

## Recent Improvements

### 🎯 **Context-Aware Detection** (NEW)
- **Smart filtering**: Automatically detects security tools, test files, and examples
- **Reduced false positives**: 70-90% reduction in false positives for security tooling code
- **DRY pattern management**: Unified pattern configuration in `patterns_config.py`
- **Cache control**: New `--no-cache` flag for fresh scans
- **Debug mode**: New `--debug` flag for troubleshooting LLM responses
- **Scan profiles**: Choose between `production`, `development`, or `security-tool` profiles

## Features

### 🔍 **Multi-Layer Analysis**
- **Static Analysis**: Pattern matching for known vulnerabilities
- **Taint Analysis**: Tracks data flow from sources to sinks
- **ML-Powered Detection**: Machine learning models identify sophisticated threats
- **LLM Deep Analysis**: Optional Cerebras GPT-120B for semantic understanding

### 🛡️ **Real-Time Protection**
- **Runtime Monitoring**: Proxy server intercepts and analyzes MCP calls
- **Policy Enforcement**: Define and enforce security policies
- **Session Tracking**: Monitor tool usage patterns and detect anomalies

### 📊 **Comprehensive Reporting**
- **Web Dashboard**: FastAPI-powered dashboard for visual analysis
- **Threat Scoring**: Risk assessment with CWE categorization
- **Actionable Insights**: Specific remediation recommendations

## Quick Start

```bash
# 1. Install dependencies (Python 3.13+ required)
uv sync

# 2. Activate the virtual environment
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows

# 3. Scan your entire system for MCP vulnerabilities
python3 mighty_mcp.py check

# 4. Launch the web dashboard
python3 src/dashboard/app.py
# Then open http://localhost:8080 in your browser
```

## Installation

### Prerequisites
- Python 3 or higher
- Git

### Step-by-Step Installation

```bash
# 1. Clone repository
git clone https://github.com/NineSunsInc/mighty-security.git
cd secure-toolings

# 2. Install UV package manager (recommended)
# macOS with Homebrew:
brew install uv

# Or use pip to install UV:
pip install uv

# 3. Install project dependencies
uv sync

# 4. Activate the virtual environment
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows

# 5. Verify installation
python3 mighty_mcp.py --help
```

### Optional: Enable AI-Powered Analysis

```bash
# Add your Cerebras API key for enhanced LLM analysis
echo "CEREBRAS_API_KEY=your_key_here" > .env
```

### First-Time Setup Notes

- **Database**: The analysis database auto-initializes on first use
- **Dashboard**: Accessible at http://localhost:8080 after running `python3 src/dashboard/app.py`
- **Updates**: The tool includes auto-update functionality

## Project Structure

```
secure-toolings/
├── mighty_mcp.py          # 🎯 SINGLE ENTRY POINT for all operations
├── src/
│   ├── analyzers/         # Analysis engines
│   │   ├── comprehensive/ # Core analysis suite
│   │   ├── llm/          # LLM-powered analysis
│   │   ├── security/     # Security rule engines
│   │   └── taint/        # Data flow tracking
│   ├── core/             # Core unified analyzer
│   ├── runtime/          # Real-time monitoring
│   ├── policies/         # Policy engine
│   └── dashboard/        # Web interface
├── tests/                # Test suite
└── examples/            # Example vulnerable code
```

## Usage Examples

### Basic Scanning

```bash
# IMPORTANT: Always activate the virtual environment first!
source .venv/bin/activate

# Scan a GitHub repository before installing
python3 mighty_mcp.py check https://github.com/modelcontextprotocol/servers

# Scan local directory
python3 mighty_mcp.py check /path/to/mcp-tool

# Quick system scan (finds all MCP configs)
python3 mighty_mcp.py check
```

### Using the Web Dashboard

```bash
# Start the dashboard (runs on http://localhost:8080)
python3 src/dashboard/app.py

# Dashboard will be available at:
http://localhost:8080
```

### Advanced Analysis

```bash
# Deep analysis with LLM (requires Cerebras API key)
# First, set up your API key:
echo "CEREBRAS_API_KEY=your_api_key_here" > .env

# Then run deep analysis (includes LLM):
python3 mighty_mcp.py check https://github.com/example/tool --deep

# Debug mode (shows LLM responses for troubleshooting)
python3 mighty_mcp.py check <target> --deep --debug

# Force fresh scan (bypass cache)
python3 mighty_mcp.py check <target> --no-cache

# Scan with specific profile
python3 mighty_mcp.py check <target> --profile production  # Excludes test files
python3 mighty_mcp.py check <target> --profile development  # Includes everything

# Note: When using the analyzer directly, use --llm instead:
# python3 src/analyzers/comprehensive_mcp_analyzer.py <target> --llm

# Real-time monitoring on custom port
python3 mighty_mcp.py check --realtime --port 9090

# Generate detailed report
python3 mighty_mcp.py check --output report.json --format json
```

### Testing with Built-in Examples

```bash
# Test detection capabilities with known vulnerabilities
python3 mighty_mcp.py check examples/super_evals/ssrf_unguarded
python3 mighty_mcp.py check examples/super_evals/command_injection
python3 mighty_mcp.py check examples/super_evals/creds_flow
```

### Running the Test Suite

```bash
# Run all tests to verify the analyzer is working correctly
cd tests/
./run_all_tests.sh

# Or from the project root:
bash tests/run_all_tests.sh

# Run specific test categories:
python3 tests/comprehensive_test_suite.py  # Main detection accuracy test
python3 tests/test_mcp_prompt_injection.py  # Prompt injection tests
python3 tests/test_context_filtering.py    # Context-aware filtering tests
```

## Troubleshooting

### Common Issues

**Scanning shows this project as CRITICAL risk**
```bash
# This is EXPECTED! We have malicious test files to validate detection
# To scan excluding test files:
python3 mighty_mcp.py check . --profile production

# The test files are in mcp_test_cases/ and tests/
# They contain real malicious patterns to ensure our scanner works
```

**Module not found errors**
```bash
# Make sure you've activated the virtual environment
source .venv/bin/activate
# Then reinstall dependencies
uv sync
```

**Permission errors on macOS/Linux**
```bash
# Make scripts executable
chmod +x mighty_mcp.py
```

**Dashboard won't start**
```bash
# The dashboard now auto-finds an available port if 8080 is in use!
python3 src/dashboard/app.py

# Or manually specify a port:
python3 src/dashboard/app.py --port 8081
```

**Database errors**
```bash
# The database auto-initializes, but if you have issues:
rm analysis_cache.db  # Remove old database
python3 mighty_mcp.py check  # Will recreate it
```

## Detection Capabilities

### What We Detect Well ✅
- **Command Injection**: `exec()`, `eval()`, `compile()` usage
- **Credential Theft**: Environment variable access, file reads + network sends
- **Prompt Injection**: Malicious prompts in metadata files
- **Data Exfiltration**: Suspicious network operations
- **Code Obfuscation**: High-entropy variables and encoded payloads
- **Secrets in Code**: API keys, tokens, private keys in configs

### Current Limitations ⚠️
- **Indirect Execution**: Complex execution chains
- **Advanced Obfuscation**: Sophisticated encoding techniques
- **Context Awareness**: Difficulty distinguishing safe vs unsafe usage
- **Multi-file Analysis**: Limited cross-file tracking

## Understanding Results

### Threat Levels
- 🔴 **CRITICAL** (80-100%): Do not use - immediate compromise
- 🟠 **HIGH** (60-79%): Significant risk - extensive review required
- 🟡 **MEDIUM** (40-59%): Potential vulnerability - review before use
- 🟢 **LOW** (20-39%): Minor concerns - generally safe
- ✅ **MINIMAL** (0-19%): Safe to use

### Attack Vectors
- **COMMAND_INJECTION**: Code execution vulnerabilities
- **DATA_EXFILTRATION**: Unauthorized data transmission
- **CREDENTIAL_THEFT**: Attempts to steal secrets
- **OBFUSCATION**: Hidden malicious code
- **PROMPT_INJECTION**: LLM manipulation
- **NETWORK_BACKDOOR**: Remote access mechanisms

## API Usage

```python
from mighty_mcp import check_tool, scan_system

# Check a single tool
result = await check_tool(tool_definition)
if result['should_block']:
    print(f"Blocked: {result['reason']}")

# Scan entire system
report = await scan_system()
print(f"Found {report['total_threats']} threats")
```

## Configuration

### Environment Variables
```bash
CEREBRAS_API_KEY=your_key      # For LLM analysis
MCP_SECURITY_POLICY=strict     # Policy level
MCP_SECURITY_PORT=8080         # Monitoring port
```

### Policy Files
Create custom policies in `policies/`:
```yaml
name: strict_policy
rules:
  - block: command_execution
  - block: network_access
  - allow: file_read
    condition: "path.startswith('/tmp')"
```

## Contributing

We welcome contributions! Key areas needing improvement:
- Enhanced detection patterns
- Better false positive reduction
- Multi-language support
- Additional LLM integrations

See [CONTRIBUTION.md](CONTRIBUTION.md) for guidelines.

## Performance

- **Scan Speed**: ~100-200 files/second
- **Memory Usage**: <100MB typical
- **LLM Context**: 64K tokens
- **Detection Rate**: ~60% (improving with each release)

## Roadmap

### Current Focus
- ✅ Unified codebase structure
- ✅ FastAPI dashboard
- 🚧 Enhanced taint analysis
- 🚧 Improved SSRF detection

### Coming Soon
- GraphQL API
- CI/CD integrations
- Container scanning
- Cloud deployment options

## References

- [Invariant Labs - MCP Vulnerability Research](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [OWASP Security Guidelines](https://owasp.org)

## License

MIT License - See [LICENSE](LICENSE) for details

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/secure-toolings/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secure-toolings/discussions)

---

**⚠️ Important**: While this tool provides comprehensive security analysis, it should be part of a defense-in-depth strategy. Always manually review MCP tools and run them in sandboxed environments.
