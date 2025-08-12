# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Security Suite - A unified security framework for Model Context Protocol (MCP) servers. This is a defensive security tooling project for analyzing and detecting vulnerabilities in MCP implementations.

**Main entry point**: `mighty_mcp.py` - ALL functionality goes through this single CLI.

## Essential Commands

### Setup & Installation
```bash
# Python 3.11+ required
# Using uv (recommended)
uv sync -p 3.11

# Alternative: pip with venv
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Optional ML features (for semantic analysis)
pip install transformers torch sentence-transformers scikit-learn networkx gitpython

# Optional LLM features (Cerebras GPT-OSS-120B)
pip install cerebras-cloud-sdk
echo "CEREBRAS_API_KEY=your_api_key" > .env
```

### Core Analysis Commands
```bash
# Main entry point - comprehensive analysis
python3 mighty_mcp.py check [target]

# Alternative direct analyzer
python3 src/analyzers/comprehensive_mcp_analyzer.py [target]

# Analyze GitHub repository
python3 src/analyzers/comprehensive_mcp_analyzer.py https://github.com/example/mcp-tool

# Analyze with LLM enhancement
python3 src/analyzers/comprehensive_mcp_analyzer.py [target] --llm

# Start web dashboard
python3 mighty_mcp.py web
```

### Testing
```bash
# Run comprehensive test suite
python3 tests/comprehensive_test_suite.py

# Create test cases
python3 tests/create_test_cases.py

# Test ML integration (requires ML deps)
python3 tests/demo_ml_integration.py

# Test real MCP servers
python3 tests/test_real_mcp_servers.py --test-all
```

### Important Notes
- Always use `python3` explicitly (not just `python`)
- Always verify files/directories exist before creating new ones
- Virtual environment activation is critical before running commands

## Architecture Overview

### Module Organization

The codebase follows a modular architecture with clear separation of concerns:

1. **Entry Points**
   - `mighty_mcp.py` - Unified CLI and simplified API (MightySecurity class)
   - `src/core/unified_analyzer.py` - Consolidates all analysis methods

2. **Analysis Modules** (`src/analyzers/`)
   - `comprehensive_mcp_analyzer.py` - Main orchestrator for static analysis
   - `comprehensive/` - Pattern matching, behavior analysis, ML scoring
   - `llm/` - Cerebras LLM integration for enhanced detection
   - `taint/` - Inter-procedural data flow analysis
   - `security/` - Specialized rules (SSRF, credentials, PII)

3. **Runtime Components** (`src/runtime/`)
   - Proxy server for real-time monitoring
   - Session management and activity logging
   - Gateway for MCP request interception

4. **Policy System** (`src/policies/`)
   - Policy parsing and enforcement
   - Template-based security rules
   - Custom policy management

5. **Supporting Infrastructure**
   - `src/configs/` - MCP configuration discovery
   - `src/signatures/` - Signature verification
   - `src/semantics/` - ML ensemble for threat scoring
   - `src/dashboard/` - Web interface

### Key Design Patterns

1. **Lazy Loading**: Components are loaded only when needed to reduce startup time
2. **Graceful Degradation**: Missing optional dependencies (ML, LLM) don't break core functionality
3. **Modular Analysis**: Each analyzer can run independently or as part of the unified pipeline
4. **Evidence-Based Reporting**: All findings include CWE IDs, snippets, and flow traces when available

### Analysis Pipeline Flow

```
Input (file/repo/config)
    ↓
Discovery & Loading
    ↓
Static Analysis (patterns, AST)
    ↓
Taint Analysis (data flow)
    ↓
Behavior Analysis (suspicious patterns)
    ↓
Optional: ML Scoring
    ↓
Optional: LLM Deep Analysis
    ↓
Policy Evaluation
    ↓
Report Generation (threat score, findings, recommendations)
```

### Detection Capabilities

Current detection focus areas:
- Command injection (exec, eval, subprocess)
- Credential theft and leakage
- Path traversal vulnerabilities
- SSRF (Server-Side Request Forgery)
- Prompt injection in MCP metadata
- Data exfiltration patterns
- Code obfuscation
- Secrets in configuration files

### Important Implementation Details

1. **Threat Scoring**: Weighted average of multiple signals (patterns, flows, behaviors, ML)
2. **False Positive Reduction**: Uses context-aware analysis and ML consensus
3. **Performance**: ~100-200 files/second scan rate
4. **Context Limits**: LLM analysis uses smart file prioritization for large repos

### Development Workflow Notes

When making changes:
1. Check existing patterns in `src/analyzers/shared_constants.py`
2. Reuse detection logic from `src/analyzers/comprehensive/patterns.py`
3. Add tests to `tests/` for new detection capabilities
4. Update detection gaps in documentation if closing vulnerabilities
5. Run the comprehensive test suite before committing

### Known Limitations

- Detection rate: ~40% for sophisticated attacks
- Static analysis only (no runtime behavior monitoring)
- Limited cross-file analysis capabilities
- High false positive rate on some safe operations (~20-30%)
- Context-unaware (can't distinguish hardcoded vs user input)

## Common Development Tasks

### Adding New Detection Patterns
1. Update patterns in `src/analyzers/shared_constants.py`
2. Add test cases in `examples/super_evals/`
3. Run analyzer against test cases to verify

### Debugging Analysis Issues
```bash
# Run with verbose output
python3 src/analyzers/comprehensive_mcp_analyzer.py [target] --verbose

# Check specific detection category
python3 -c "from src.analyzers.comprehensive.patterns import get_threat_patterns; print(get_threat_patterns()['COMMAND_INJECTION'])"
```

### Working with LLM Integration
Requires `CEREBRAS_API_KEY` in environment or `.env` file. The LLM provides enhanced semantic analysis beyond pattern matching.

## Repository Structure Summary

- `src/` - Core implementation code
- `examples/` - Test cases (malicious, safe, suspicious)
- `tests/` - Test suites and validation scripts  
- `reports/` - Generated analysis reports
- `docs/` - Architecture and usage documentation
- `hooks/` - Runtime security hooks for MCP
- `internal/` - Development notes and guides