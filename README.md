# MCP Security Analyzer 🛡️

A security analyzer for Model Context Protocol (MCP) tools that detects malicious patterns and potential security threats through static code analysis.

## 🚨 The Problem

MCP tools are becoming critical infrastructure for AI applications, but they present serious security risks:

- **43% of MCP servers have command injection vulnerabilities**
- **30% allow unrestricted URL fetches (SSRF attacks)**
- **22% leak files outside intended directories**
- Recent exploits like the GitHub MCP vulnerability show how prompt injection can leak private data

## ✅ What This Tool Actually Detects

### Current Detection Capabilities (Honest Assessment)

#### 1. **Command Execution Threats** (~40% coverage)
✅ **Detects Well:**
- `exec()` and `eval()` function calls
- `compile()` usage
- Some AST-based code execution patterns

❌ **Currently Misses:**
- `os.system()` without specific characters
- `subprocess` calls with `shell=True`
- Indirect execution through variables
- `__import__()` dynamic imports

#### 2. **Credential Theft Patterns** (~15% coverage)
✅ **Detects Well:**
- Generic "file read + network send" patterns
- Some environment variable access

❌ **Currently Misses:**
- AWS credentials access via `expanduser()`
- SSH key theft patterns
- Docker/Kubernetes config access
- Browser credential theft
- Keychain/keyring access

#### 3. **Prompt Injection** (~80% coverage)
✅ **Detects Well:**
- Prompt injection in MCP metadata files
- Common injection patterns in strings
- System tag injections

❌ **Currently Misses:**
- Sophisticated multi-step injections
- Context-aware injections

#### 4. **Data Exfiltration** (~30% coverage)
✅ **Detects Well:**
- Basic HTTP POST with data
- Some file-to-network flows

❌ **Currently Misses:**
- DNS tunneling
- Steganography
- Encrypted channels
- Indirect exfiltration

#### 5. **Code Obfuscation** (~30% coverage)
✅ **Detects Well:**
- High entropy variable names
- Some suspicious naming patterns

❌ **Currently Misses:**
- Base64 decode + exec patterns
- Compression-based obfuscation
- Unicode escapes
- Most real-world obfuscation

### Overall Detection Rate: ~40%
- Good at detecting obvious, direct threats
- Poor at detecting sophisticated or indirect attacks
- Many false positives on safe code

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-security-analyzer.git
cd mcp-security-analyzer

# Python 3.11+

# Option A: uv (recommended)
brew install uv  # macOS
uv sync -p 3.11

# Option B: pip + venv
python3 -m venv .venv
source .venv/bin/activate  # IMPORTANT: Always activate the virtual environment!
pip install -U pip
pip install -e .

# Optional: enable ML features used by src/ml/*
pip install transformers torch sentence-transformers scikit-learn networkx gitpython

# Optional: enable LLM-powered analysis (Cerebras GPT-OSS-120B)
pip install cerebras-cloud-sdk
# Set your API key in .env file:
echo "CEREBRAS_API_KEY=your_api_key_here" > .env
```

### Basic Usage

⚠️ **IMPORTANT**: Always activate the virtual environment before running the analyzer:

```bash
# Activate virtual environment first!
source .venv/bin/activate
```

#### Standard Analysis (Pattern-based + ML)

```bash
# Analyze a GitHub repository
python analyzers/comprehensive_mcp_analyzer.py https://github.com/example/mcp-tool

# Analyze a local directory
python analyzers/comprehensive_mcp_analyzer.py /path/to/mcp/tool

# Analyze current directory
python analyzers/comprehensive_mcp_analyzer.py .
```

#### Enhanced Analysis with LLM (Cerebras GPT-OSS-120B)

The `--llm` flag enables AI-powered deep analysis using Cerebras' 120B parameter model for more sophisticated threat detection:

```bash
# With LLM for enhanced detection (requires CEREBRAS_API_KEY)
python analyzers/comprehensive_mcp_analyzer.py https://github.com/example/mcp-tool --llm

# Analyze local directory with LLM
python analyzers/comprehensive_mcp_analyzer.py /path/to/mcp/tool --llm

# Example: Analyze the malicious examples with LLM
python analyzers/comprehensive_mcp_analyzer.py examples/malicious_credential_theft --llm
```

**What the --llm flag adds:**
- 🤖 AI-powered code analysis with 64K context window
- 🎯 Better detection of sophisticated attack patterns
- 📊 Contextual understanding of code intent
- 🔍 Reduced false positives through semantic analysis
- ⚡ Smart file prioritization for efficient analysis

### Example Output

```
======================================================================
🔒 MCP SECURITY ANALYZER
======================================================================
Target: https://github.com/example/mcp-tool
Mode: Deep Scan
======================================================================

📊 Starting scan of 15 files...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Scanning files
   [████████████████████████████░░]  90.0% │ 14/15 files │ ETA: 1s

📊 OVERALL ASSESSMENT
   Threat Level: HIGH
   Threat Score: 66.00%
   
⚠️ THREATS DETECTED: 8

   COMMAND_INJECTION (2 threats)
      • Direct exec() usage
        File: tool.py, Line: 45
      • Direct eval() usage  
        File: tool.py, Line: 89

💡 RECOMMENDATIONS:
   ⚠️ HIGH RISK - Thorough review required
   • Detected command injection risks
   • Manual review strongly recommended
```

## ⚠️ Important Limitations

### What This Tool CANNOT Do:

1. **Runtime Analysis** - Only static code analysis, no dynamic behavior monitoring
2. **Context Awareness** - Cannot distinguish between safe hardcoded values and dangerous user input
3. **Data Flow Tracking** - Limited ability to follow variables through code
4. **Sophisticated Attacks** - Misses most advanced attack patterns
5. **Multi-file Analysis** - Limited cross-file threat detection

### Known False Positives:
- Flags standard library imports as "dangerous"
- Marks common variable names as "suspicious"
- Over-reports on safe operations

### Known False Negatives:
- Misses indirect command execution
- Fails to detect most credential theft
- Cannot detect time bombs or logic bombs
- Misses obfuscated payloads

## 🔍 How It Works

1. **Static Pattern Matching**: Uses regex patterns to find dangerous code
2. **AST Analysis**: Basic Python AST parsing for some patterns
3. **Entropy Analysis**: Detects high-entropy (obfuscated) code
4. **File Fingerprinting**: SHA-512/SHA3-512 hashes for integrity
5. **Basic Scoring**: Weighted threat scoring (needs improvement)
6. **Optional Semantic Ensemble**: If ML dependencies are installed, runs `src/semantics.SecurityModelEnsemble` to compute an ML maliciousness score used in the final assessment (the CLI prints "ML Score"). Falls back to a lightweight local heuristic otherwise.
7. **LLM Integration (--llm flag)**: When enabled with Cerebras API key, uses GPT-OSS-120B for deep semantic analysis, providing contextual threat detection beyond pattern matching

## 🎯 Real-World Performance

| Attack Type | Detection Rate | Notes |
|-------------|---------------|-------|
| **Direct exec/eval** | ✅ 90% | Good detection |
| **os.system** | ❌ 10% | Poor - pattern too specific |
| **Credential Theft** | ❌ 15% | Very limited |
| **Prompt Injection** | ✅ 80% | Works well for metadata |
| **Obfuscation** | ⚠️ 30% | Basic detection only |
| **Network Backdoors** | ⚠️ 20% | Limited patterns |
| **RADE Attacks** | ❌ 5% | Almost no detection |
| **Tool Poisoning** | ❌ 10% | Minimal coverage |

## 🛠️ Technical Details

### File Structure
```
analyzers/
├── comprehensive_mcp_analyzer.py  # Main analyzer (use this)
├── report_formatter.py            # Comprehensive report generation
├── shared_constants.py            # Reusable patterns and constants
├── llm/                           # LLM integration (--llm flag)
│   ├── cerebras_analyzer.py      # Cerebras GPT-OSS-120B integration
│   ├── context_optimizer.py      # Smart file ranking for LLM
│   ├── llm_integration.py        # Coordinates LLM analysis
│   └── prompts.py                # Security-focused prompts
└── archive/                       # Old/experimental analyzers

examples/
├── malicious_command_injection/    # Test cases
├── malicious_credential_theft/
├── malicious_obfuscated/
└── malicious_prompt_injection/
```

### Threat Categories Checked
- **COMMAND_INJECTION**: exec, eval, compile
- **CREDENTIAL_THEFT**: File access patterns
- **DATA_EXFILTRATION**: Network operations
- **PROMPT_INJECTION**: LLM manipulation
- **OBFUSCATION**: Hidden/encoded threats
- **PERSISTENCE**: Backdoor mechanisms
- **NETWORK_BACKDOOR**: Remote access

## 🔮 Roadmap

### Immediate Fixes Needed
- Fix overly specific regex patterns
- Add proper data flow analysis
- Implement context-aware detection
- Reduce false positive rate

### Future Improvements
- Add machine learning models (currently claimed but not implemented)
- Implement runtime monitoring
- Add multi-language support beyond Python
- Create CI/CD integration

## ⚡ Performance

- **Scan Speed**: ~100-200 files/second
- **Memory Usage**: <100MB for most repos
- **Accuracy**: ~40% detection rate (needs improvement)
- **False Positive Rate**: ~20-30% (too high)

## 🤝 Contributing

This tool needs significant improvements. Key areas:

1. **Fix Pattern Detection**: Current patterns miss obvious threats
2. **Add Data Flow Analysis**: Track variables from source to sink
3. **Reduce False Positives**: Better discrimination needed
4. **Add Test Coverage**: More comprehensive test cases
5. **Improve Documentation**: Better threat descriptions

See [DETECTION_GAP_ANALYSIS.md](DETECTION_GAP_ANALYSIS.md) for detailed analysis of current gaps. For contribution workflow, see `CONTRIBUTION.md`.

## 📚 References

- [Invariant Labs - GitHub MCP Vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [Docker - MCP Security Issues](https://www.docker.com/blog/mcp-security-issues-threatening-ai-infrastructure/)
- [PromptHub - MCP Security in 2025](https://www.prompthub.us/blog/mcp-security-in-2025)

## ⚖️ License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

**This tool provides basic security scanning but should NOT be your only security measure.** 

Current limitations:
- Only ~40% detection rate for real threats
- High false positive rate
- Misses many sophisticated attacks
- No runtime protection

Always:
- Manually review MCP tools before use
- Use multiple security layers
- Run tools in sandboxed environments
- Monitor runtime behavior

## 📞 Support

For questions or security concerns:
- Open an issue on GitHub
- See DETECTION_GAP_ANALYSIS.md for known issues

---

**Remember**: This tool is a work in progress with significant detection gaps. Do not rely on it as your sole security measure. Always perform manual security reviews and use defense-in-depth strategies.