# MCP Security Suite - Architecture Overview

## 🎯 Purpose
A defensive security framework for analyzing and detecting vulnerabilities in Model Context Protocol (MCP) implementations. **This is security tooling for defense only** - analyzing threats, not creating them.

## 🏗️ Module Organization

### 1. **Static Analysis** (`src/analyzers/`)
The core security scanning engine that performs comprehensive code analysis.

#### Components:
- **comprehensive_mcp_analyzer.py**: Main orchestrator
  - Coordinates all analysis methods
  - Handles GitHub repos and local files/directories
  - Produces threat scores (0-100) and detailed reports

- **comprehensive/** subdirectory:
  - `patterns.py`: 50+ threat pattern definitions
  - `behavior.py`: Suspicious behavior detection
  - `data_flow.py`: Track data through code
  - `ml.py`: Optional ML-based scoring

- **taint/** subdirectory:
  - Inter-procedural data flow analysis
  - Tracks potentially malicious data through code paths

- **security/** subdirectory:
  - Specialized detectors for credentials, PII, URLs
  - Secret scanning with entropy analysis

- **llm/** subdirectory:
  - Cerebras GPT integration for semantic analysis
  - Multi-pass analysis for deep inspection

### 2. **Web Dashboard** (`src/dashboard/`)
FastAPI-based web interface for security scanning.

#### Current Structure:
- `app.py`: Main FastAPI application
- `static/dashboard.html`: Extracted HTML interface
- `CLAUDE.md`: Dashboard-specific instructions

#### Issue to Fix:
- **Duplication**: `app.py` contains embedded HTML (lines 600-1398) that duplicates `static/dashboard.html`
- **Solution**: Remove embedded HTML, use FileResponse to serve static file

### 3. **Runtime Monitoring** (`src/runtime/`)
Framework for real-time MCP traffic monitoring (not yet active).

#### Components:
- `proxy_server.py`: FastAPI server for intercepting MCP traffic
- `gateway.py`: Wraps MCP servers with monitoring
- `analyzer_integration.py`: Bridges static analysis with runtime
- `session.py`: Session management
- `activity_logger.py`: Activity tracking

#### Status:
- Infrastructure exists but not actively monitoring
- Would require actual MCP server integration to function

### 4. **Core Unification** (`src/core/`)
- `unified_analyzer.py`: Single interface for all analysis methods
- Lazy loads components based on availability
- Provides consistent API across different analyzers

### 5. **Supporting Modules**
- **policies/**: Security policy templates and enforcement
- **signatures/**: Tool signature verification (detect tampering)
- **configs/**: MCP configuration discovery
- **semantics/**: ML ensemble for threat scoring
- **cli/**: Command-line interfaces

## 🔄 Data Flow

```
Input (GitHub URL / Local Path)
         ↓
    Web Dashboard
    (or CLI: mighty_mcp.py)
         ↓
ComprehensiveMCPAnalyzer
         ↓
    ┌────────────────────────┐
    │  Parallel Analysis:    │
    │  - Pattern Matching    │
    │  - AST Analysis        │
    │  - Taint Tracking      │
    │  - Behavior Detection  │
    │  - Optional: ML/LLM    │
    └────────────────────────┘
         ↓
    Threat Report
    (Score, Findings, CWE IDs)
         ↓
    SQLite Database
    (History, Statistics)
```

## 🛠️ Recommended Fixes

### 1. Dashboard Consolidation
```python
# In src/dashboard/app.py, replace get_dashboard_html() with:
@app.get("/")
async def index():
    """Serve the static dashboard HTML"""
    html_file = Path(__file__).parent / "static" / "dashboard.html"
    return FileResponse(html_file)
```

### 2. Remove Duplication
- Delete lines 600-1398 from `app.py` (the embedded HTML)
- Keep only the FastAPI routes and logic
- Ensure `static/dashboard.html` is the single source of truth

### 3. Entry Point Clarity
- `mighty_mcp.py` - Main CLI entry point
- `src/dashboard/app.py` - Web dashboard
- `src/cli/dashboard.py` - Just a launcher for the web dashboard

### 4. Runtime Monitoring Clarification
- Document that runtime monitoring is a framework, not active
- Would need:
  - MCP server wrapper implementation
  - WebSocket connections for real-time updates
  - Integration with actual MCP clients

## 📊 Current Capabilities

### ✅ Working Features
- Static code analysis (AST-based)
- 50+ threat pattern detection
- GitHub repository scanning
- Local file/directory scanning
- Secret/credential detection
- Command injection detection
- Threat scoring (0-100)
- Web dashboard with history
- SQLite storage

### 🚧 Framework Only (Not Active)
- Runtime proxy monitoring
- Real-time MCP traffic interception
- Session tracking
- Activity logging

### 🔧 Optional Features (Require Setup)
- LLM analysis (needs CEREBRAS_API_KEY)
- ML ensemble scoring (needs ML dependencies)

## 🎯 Detection Focus
- Command injection (exec, eval, subprocess)
- Credential theft and leakage
- Path traversal vulnerabilities
- SSRF (Server-Side Request Forgery)
- Prompt injection in MCP metadata
- Data exfiltration patterns
- Code obfuscation
- Secrets in configuration files

## 📈 Performance Metrics
- Scan rate: ~100-200 files/second
- Detection rate: ~40% for sophisticated attacks
- False positive rate: ~20-30%
- Threat scoring accuracy: Moderate (context-unaware)

## 🔒 Security Note
This is **defensive security tooling only**. It's designed to:
- Analyze and detect vulnerabilities
- Protect against malicious MCP tools
- Provide security assessments
- Help developers write secure code

It should **never** be used to:
- Create exploits
- Attack systems
- Bypass security measures
- Develop malicious tools