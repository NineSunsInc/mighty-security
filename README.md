# MCP Security Suite 🛡️

**Unified security framework for Model Context Protocol (MCP) servers**

## What is this?

A comprehensive security analysis tool that protects against malicious MCP (Model Context Protocol) servers and tools. MCP servers give AI assistants powerful capabilities - but with that power comes serious security risks. This tool helps identify and prevent those risks.

## Why do you need this?

MCP servers are becoming critical infrastructure for AI applications, but recent research shows:
- **43% of MCP servers have command injection vulnerabilities**
- **30% allow unrestricted URL fetches (SSRF attacks)**  
- **22% leak files outside intended directories**
- The GitHub MCP vulnerability showed how prompt injection can leak private repositories

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
# Install dependencies
uv sync

# Scan your entire system for MCP vulnerabilities
python mighty_mcp.py check

# Analyze a specific tool or repository
python mighty_mcp.py check https://github.com/example/mcp-tool

# Start real-time monitoring
python mighty_mcp.py check --realtime

# Launch web dashboard
python mighty_mcp.py web
```

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/secure-toolings.git
cd secure-toolings

# Install with uv (recommended)
brew install uv  # macOS
uv sync

# Or with pip
pip install -e .

# Optional: Enable LLM analysis
echo "CEREBRAS_API_KEY=your_key" > .env
```

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
# Scan a GitHub repository
python mighty_mcp.py check https://github.com/modelcontextprotocol/servers

# Scan local directory
python mighty_mcp.py check /path/to/mcp-tool

# Quick system scan
python mighty_mcp.py check
```

### Advanced Analysis

```bash
# Deep analysis with LLM (requires API key)
python mighty_mcp.py check https://github.com/example/tool --deep

# Real-time monitoring on custom port
python mighty_mcp.py check --realtime --port 9090

# Generate detailed report
python mighty_mcp.py check --output report.json --format json
```

### Testing with Examples

```bash
# Test detection capabilities
python mighty_mcp.py check examples/super_evals/ssrf_unguarded
python mighty_mcp.py check examples/super_evals/command_injection
python mighty_mcp.py check examples/super_evals/creds_flow
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