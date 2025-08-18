# 🚀 Quick Start Guide

⚠️ **Testing Note**: This project contains malicious test files in `tests/mcp_test_cases/` and `tests/test_suite_output/` to validate detection. Use `--profile production` when scanning this project to exclude them.

## Prerequisites

- **Python 3.13+** (required)
- **Node.js 16+** (for dashboard development)
- **uv** package manager (recommended) or pip

## 1. Installation

```bash
# Clone the repository
git clone https://github.com/NineSunsInc/mighty-security.git
cd secure-toolings

# Install Python dependencies  
uv sync  # or: python3 -m venv .venv && source .venv/bin/activate && pip install -e .

# Activate virtual environment
source .venv/bin/activate
```

## 2. Run Security Scans

```bash
# Scan a GitHub repository
python3 mighty_mcp.py check https://github.com/user/repo

# Scan local files/directory
python3 mighty_mcp.py check /path/to/mcp/server

# Quick scan mode (faster)
python3 mighty_mcp.py check . --quick

# With AI analysis (requires CEREBRAS_API_KEY)
python3 mighty_mcp.py check . --llm
```

## 3. Web Dashboard

### Option A: Secure Production (Recommended)
```bash
source .venv/bin/activate
python3 src/dashboard/secure_app.py
# → Open http://localhost:8080
# ✅ Includes security protections
```

### Option B: Development Mode
```bash
# Terminal 1: Start SECURE API server
source .venv/bin/activate  
python3 src/dashboard/secure_app.py

# Terminal 2: Start React dev server
cd src/dashboard
npm install
npm run dev
# → Open http://localhost:3000 (auto-proxies to API)
```

### Option C: Build Production
```bash
cd src/dashboard
./build.sh  # Builds and copies React app
python3 app.py  # Serves production build
```

## 4. Dashboard Features

- **🔍 Scanner Tab**: Run interactive security scans
- **📊 Reports Tab**: View detailed threat analysis  
- **📜 History Tab**: Audit trail of all actions
- **⚡ Tasks Tab**: Monitor running scans
- **📚 About Tab**: Learn about threats and protection

## 5. Example Workflow

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Start SECURE dashboard
python3 src/dashboard/secure_app.py &

# 3. Run CLI scan
python3 mighty_mcp.py check https://github.com/example/mcp-tool

# 4. View results in dashboard at http://localhost:8080
```

## 🔧 Troubleshooting

**"Module not found"**
```bash
source .venv/bin/activate  # Always activate first!
```

**"Port already in use"**
```bash
python3 src/dashboard/app.py --port 8081
```

**"React build fails"**
```bash
cd src/dashboard
rm -rf node_modules dist
npm install
npm run build
```

**"Permission denied on build.sh"**
```bash
chmod +x src/dashboard/build.sh
```

## 🎯 Next Steps

1. Check out the **About** tab in the dashboard to learn about MCP threats
2. Try scanning some example repositories
3. Explore the **Reports** tab to understand threat analysis
4. Review the **History** tab for audit logging

For more details, see the main [README.md](README.md) and [documentation](docs/).