# 📖 MCP Security Analyzer - Usage Guide

## 🚀 Quick Start

### Analyze a GitHub Repository
```bash
python3 comprehensive_mcp_analyzer.py https://github.com/modelcontextprotocol/servers
```

### Analyze a Local Directory
```bash
python3 comprehensive_mcp_analyzer.py /path/to/local/mcp-server
```

### Test the ML Models
```bash
python3 test_ml_security.py
```

### Analyze Individual MCP Servers
```bash
python3 analyze_mcp_servers.py
```

## 🧹 Automatic Cleanup

**No manual cleanup needed!** The analyzer automatically:

1. **Uses temporary directories** - All cloned repositories are stored in system temp folders
2. **Auto-deletes after analysis** - Files are removed immediately after scanning
3. **No residual files** - Nothing is left on your system

### How it works:
```python
with tempfile.TemporaryDirectory() as temp_dir:
    # Repository is cloned here
    repo_path = Path(temp_dir) / "repo"
    # Analysis happens
    # ... 
# Directory is automatically deleted when done
```

## 📁 Output Files

The only files created are:
- `comprehensive_report_*.json` - Detailed analysis reports (kept for your records)
- `mcp_servers_analysis.json` - Summary of analyzed servers (if using analyze_mcp_servers.py)
- `mcp_test_results.json` - Test results (if running tests)

### Manual Cleanup (if needed)
```bash
# Remove analysis reports
rm comprehensive_report_*.json
rm mcp_servers_analysis.json
rm mcp_test_results.json
```

## 🔍 What Gets Analyzed

When you analyze a GitHub URL:
1. Repository is **cloned with depth=1** (shallow clone, minimal data)
2. All code files are scanned
3. ML models analyze patterns
4. Report is generated
5. **Cloned repo is automatically deleted**

## 💾 Storage Requirements

- **Temporary space needed**: ~50MB per repository analyzed
- **Permanent space**: Only the JSON reports (typically < 1MB each)
- **No accumulation**: Each analysis cleans up after itself

## 🛡️ Security Features

### 3-Layer Analysis System
1. **Pattern Detection** - Fast regex-based threats
2. **AST Analysis** - Code structure examination  
3. **ML Models** - Deep semantic analysis

### Detected Threats
- Command injection
- Data exfiltration
- Prompt injection
- Path traversal
- Credential theft
- Obfuscated code
- Supply chain attacks

## 📊 Understanding Results

### Threat Scores
- **0-20%**: Safe to use ✅
- **20-50%**: Review recommended ⚠️
- **50%+**: High risk, careful review required 🚨

### Threat Levels
- **MINIMAL**: No significant threats
- **LOW**: Minor issues found
- **MEDIUM**: Some concerns, review needed
- **HIGH**: Significant threats detected
- **CRITICAL**: Do not use without remediation

## 🔧 Advanced Usage

### Analyze Specific Server Types
```python
from analyze_mcp_servers import MCPServerAnalyzer

analyzer = MCPServerAnalyzer()
# Analyzes filesystem, git, memory, etc. individually
analyzer.analyze_all_servers()
```

### Use ML Models Directly
```python
from src.ml.comprehensive_analyzer import ComprehensiveSecurityAnalyzer

analyzer = ComprehensiveSecurityAnalyzer()
result = await analyzer.analyze(tool_config)

if result.is_malicious:
    print(f"Threat detected: {result.threat_indicators}")
```

## 🐛 Troubleshooting

### "Git not found" Error
Install git:
```bash
# macOS
brew install git

# Ubuntu/Debian
sudo apt-get install git

# Windows
# Download from https://git-scm.com/download/win
```

### Missing Python Modules
The analyzer works without external dependencies, but for ML features:
```bash
pip install transformers torch sentence-transformers
```

### Permission Errors
Run with appropriate permissions:
```bash
# If analyzing system directories
sudo python3 comprehensive_mcp_analyzer.py /path/to/directory
```

## 📈 Performance

- **Basic analysis**: < 5 seconds per repository
- **With ML models**: < 30 seconds per repository
- **Memory usage**: < 500MB
- **CPU usage**: Moderate (single core)

## 🔐 Privacy

- **No data sent externally** - All analysis is local
- **No tracking** - No telemetry or usage data collected
- **Temporary files only** - Nothing persists except reports
- **Your code stays private** - Analyzed locally and deleted

## 📝 Report Format

Reports include:
```json
{
  "threat_score": 15.5,
  "threat_level": "LOW",
  "threats_found": [...],
  "capabilities": ["file_access", "network_access"],
  "recommendations": [...],
  "fingerprints": {...}
}
```

## 🆘 Getting Help

1. Check this guide first
2. Review the README.md
3. Look at example outputs in test files
4. Open an issue on GitHub for bugs

## ✨ Best Practices

1. **Always review HIGH/CRITICAL threats** before using an MCP server
2. **Check capabilities** - Ensure the server only has necessary permissions
3. **Verify sources** - Prefer official or well-known repositories
4. **Keep analyzer updated** - Pull latest version regularly
5. **Save reports** - Keep analysis reports for audit trail

---

**Remember**: This tool helps identify risks but doesn't guarantee complete security. Always use caution with third-party code.