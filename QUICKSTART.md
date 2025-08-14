# Quick Start Guide - MCP Security Suite

## 3-Minute Setup

⚠️ **Testing Note**: This project contains malicious test files in `mcp_test_cases/` and `tests/` to validate detection. Use `--profile production` when scanning this project to exclude them.

### 1. Install (One-Time Setup)
```bash
# Clone the repository
git clone https://github.com/NineSunsInc/mighty-security.git
cd secure-toolings

# Install UV package manager (if not already installed)
brew install uv  # macOS
# OR
pip install uv

# Install project dependencies
uv sync
```

### 2. Activate Environment (Every Session)
```bash
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows
```

### 3. Start Using!

#### Option A: Web Dashboard (Recommended for First-Time Users)
```bash
python3 src/dashboard/app.py
# Open http://localhost:8080 in your browser
```

#### Option B: Command Line
```bash
# Scan a GitHub repository before installing
python3 mighty_mcp.py check https://github.com/modelcontextprotocol/servers

# Scan a local file or directory
python3 mighty_mcp.py check /path/to/mcp-tool

# Find and scan all MCP configs on your system
python3 mighty_mcp.py check
```

## What You'll See

### In the Dashboard:
- **Scanner Tab**: Paste GitHub URLs or file paths to scan
- **Learning Center**: Understand MCP security threats
- **Scan History**: View past scans and detailed reports

### In the Terminal:
```
🔍 Scanning: https://github.com/example/mcp-tool
✅ Files analyzed: 42
⚠️  Threats found: 3
🛡️ Threat Score: 35/100 (MEDIUM RISK)

Threats Detected:
1. COMMAND_INJECTION in server.py:142 (Critical)
2. CREDENTIAL_THEFT in config.py:23 (High)
3. DATA_EXFILTRATION in utils.py:89 (Medium)
```

## Understanding Results

- **0-19**: ✅ SAFE - No significant issues
- **20-39**: 🟡 LOW RISK - Minor concerns
- **40-59**: ⚠️ MEDIUM RISK - Review carefully
- **60-79**: 🔴 HIGH RISK - Significant issues
- **80-100**: ⛔ CRITICAL - Do not use

## Common Commands

```bash
# Get help
python3 mighty_mcp.py --help

# Quick scan (faster, less thorough)
python3 mighty_mcp.py check <target> --quick

# Deep analysis with LLM (requires API key)
echo "CEREBRAS_API_KEY=your_key" > .env
python3 mighty_mcp.py check <target> --deep

# Force fresh scan (bypass cache)
python3 mighty_mcp.py check <target> --no-cache

# Debug mode (shows LLM responses for troubleshooting)
python3 mighty_mcp.py check <target> --deep --debug

# Scan with specific profile
python3 mighty_mcp.py check <target> --profile production  # Excludes test files
python3 mighty_mcp.py check <target> --profile development  # Includes everything

# Export scan results
python3 mighty_mcp.py check <target> --output report.json
```

## Troubleshooting

**"Module not found" error:**
```bash
# You forgot to activate the virtual environment
source .venv/bin/activate
```

**Dashboard won't start:**
```bash
# The dashboard auto-finds an available port if 8080 is in use!
python3 src/dashboard/app.py
# It will show you which port it's using
```

**Can't find mighty_mcp.py:**
```bash
# Make sure you're in the project directory
cd secure-toolings
ls mighty_mcp.py  # Should see the file
```

## Next Steps

1. **Scan Before You Install**: Always scan MCP tools before adding them
2. **Enable AI Analysis**: Add a Cerebras API key for deeper analysis
3. **Set Up Monitoring**: Use `--realtime` flag for continuous monitoring
4. **Read the Docs**: Check README.md for advanced features

## Need Help?

- Read the full [README.md](README.md)
- Check [CONTRIBUTION.md](CONTRIBUTION.md) for development setup
- Report issues on GitHub
