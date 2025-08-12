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

## ✨ What’s new (architecture + early improvements)

We’ve started a major hardening effort to align with standard static-analysis practices (OWASP/ASVS, CodeQL/Semgrep-style rule packs) and to reduce false positives by backing findings with evidence.

- Orchestrator stays thin; rules and engines live in dedicated modules:
  - `analyzers/security/` for specialized rules (e.g., SSRF, credentials)
  - `analyzers/taint/` for inter-procedural data-flow (source→sink) with `FlowTrace`
  - `src/semantics/` for semantic ensemble and LLM coordination
- Immediate, user-visible improvements:
  - Generic secret detection in code and JSON configs (including `mcp.json`): detects private keys, JWTs, common API token formats, and high-entropy strings
  - CWE tagging in findings (e.g., `CWE-918` for SSRF, `CWE-77` for command injection)
- Experimental scaffolding (present, but not fully active yet):
  - SSRF rule hooks on `requests.*` callsites
  - Inter-procedural taint analysis wiring in the deep phase

These experimental modules are stubbed today and won’t change your results until the rule logic is completed in upcoming commits. Secret detection is active now and will show up when secrets are present.

## 🚀 Quick Start

The NextJS Leaderboard and scanning codebase is located [here](https://github.com/olivercarmont/mighty-security-web-app)

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

# Optional: enable ML features used by src/semantics/*
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
python analyzers/comprehensive_mcp_analyzer.py https://github.com/github/github-mcp-server --llm

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

### Super Evals (stress tests)

Use these curated examples to validate detection:

```bash
# 1) SSRF unguarded (should flag SSRF risks – upcoming rule release)
python analyzers/comprehensive_mcp_analyzer.py examples/super_evals/ssrf_unguarded

# 2) SSRF guarded (should be low/no findings for SSRF)
python analyzers/comprehensive_mcp_analyzer.py examples/super_evals/ssrf_guarded

# 3) Credential exfiltration flow (should flag secret read + network send)
python analyzers/comprehensive_mcp_analyzer.py examples/super_evals/creds_flow

# 4) Indirect command execution (taint will catch in upcoming release)
python analyzers/comprehensive_mcp_analyzer.py examples/super_evals/command_injection

# 5) Secrets in mcp.json (active now: token/private key/JWT detection)
python analyzers/comprehensive_mcp_analyzer.py examples/super_evals/mcp_secrets
```

## ❓ Why your report may look unchanged

If you ran something like:

```bash
python analyzers/comprehensive_mcp_analyzer.py ./examples/suspicious_mixed
```

and didn’t see changes, that’s expected in this snapshot:

- The new SSRF hooks and taint engine are scaffolds and don’t emit new findings yet (rule logic ships next).
- The `suspicious_mixed` example doesn’t contain secrets, so the new secret detector won’t trigger.

You can validate a visible improvement now by scanning examples that include secrets or credential access:

```bash
# Contains environment/credential access patterns
python analyzers/comprehensive_mcp_analyzer.py ./examples/malicious_credential_theft

# Or any repo with tokens in mcp.json/package.json to see credential findings
```

In the next release, SSRF and taint rules will start emitting findings with evidence-backed flow traces and missing-guard diagnostics.

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

## 📊 Scoring System Documentation

### Understanding the Threat Score

The **Threat Score** (0-100%) represents the combined maliciousness rating of the analyzed code. It's calculated using multiple factors:

#### Threat Score Calculation
```
threat_score = weighted_average(
    pattern_threats * 0.35,    # Direct threat patterns found
    data_flows * 0.25,         # Dangerous data flow patterns
    behaviors * 0.20,          # Suspicious behavioral indicators
    ml_score * 0.20            # Machine learning analysis (if enabled)
)
```

#### Risk Levels Based on Threat Score
- **CRITICAL** (≥80%): 🔴 Immediate compromise - Do not use
- **HIGH** (≥60%): 🟠 Significant risk - Extensive review required
- **MEDIUM** (≥40%): 🟡 Potential vulnerability - Review before use
- **LOW** (≥20%): 🟢 Minor concern - Generally safe with improvements
- **MINIMAL** (<20%): ✅ Safe for use - Standard precautions apply

### Severity Levels Explained

Each individual threat is assigned a severity level:

- **CRITICAL**: 🔴 Immediate security compromise (e.g., direct command execution, credential theft)
- **HIGH**: 🟠 Significant security risk (e.g., unvalidated user input, SSRF vulnerabilities)
- **MEDIUM**: 🟡 Potential vulnerability (e.g., obfuscation, suspicious patterns)
- **LOW**: 🟢 Minor security concern (e.g., outdated dependencies, code quality issues)
- **INFO**: ℹ️ Informational finding (e.g., best practice recommendations)

### Confidence Level

The **Confidence Level** (0-100%) indicates the analysis coverage and certainty:
- **90-100%**: Complete analysis with high certainty
- **70-89%**: Good coverage with reliable results
- **50-69%**: Moderate coverage, some uncertainty
- **<50%**: Limited analysis, results may be incomplete

### Attack Vector Categories

Threats are categorized by attack vector:
- **COMMAND_INJECTION**: Code execution vulnerabilities
- **DATA_EXFILTRATION**: Unauthorized data transmission
- **CREDENTIAL_THEFT**: Attempts to steal secrets/credentials
- **OBFUSCATION**: Hidden or encoded malicious code
- **PROMPT_INJECTION**: LLM manipulation attempts
- **NETWORK_BACKDOOR**: Remote access mechanisms
- **PERSISTENCE**: Backdoor installation attempts

## 🔍 How It Works

1. **Static Pattern Matching**: Uses regex patterns to find dangerous code
2. **AST Analysis**: Basic Python AST parsing for some patterns
3. **Entropy Analysis**: Detects high-entropy (obfuscated) code
4. **File Fingerprinting**: SHA-512/SHA3-512 hashes for integrity
5. **Weighted Threat Scoring**: Combines multiple signals into a unified score
6. **Optional Semantic Ensemble**: If ML dependencies are installed, runs `src/semantics.ModelEnsemble` to compute an ML maliciousness score used in the final assessment (the CLI prints "ML Score"). Falls back to a lightweight local heuristic otherwise.
7. **LLM Integration (--llm flag)**: When enabled with Cerebras API key, uses GPT-OSS-120B for deep semantic analysis, providing contextual threat detection beyond pattern matching

### What’s different now under the hood
- The orchestrator wires in:
  - Secret detection (active)
  - SSRF rule hook (scaffolded)
  - Taint engine (scaffolded) → converts `FlowTrace` to `DataFlow` + `ThreatIndicator`
- Findings can include `cwe_ids` and structured evidence (e.g., missing SSRF guards, snippet previews, flow paths).

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

### File Structure & Purpose

```
analyzers/
├── comprehensive_mcp_analyzer.py  # Main analyzer (use this)
│   # Entry point for all security scans. Orchestrates pattern matching,
│   # ML analysis, and report generation. Handles both local and GitHub repos.
│
├── report_formatter.py            # Comprehensive report generation
│   # Formats analysis results into readable reports with risk matrices,
│   # threat breakdowns, and actionable recommendations.
│
├── shared_constants.py            # Reusable patterns and constants
│   # Contains all threat detection patterns, regex rules, and
│   # severity mappings used across the analyzer.
│
├── security/                      # Specialized security modules
│   ├── ssrf_detector.py          # SSRF vulnerability detection
│   └── credential_scanner.py     # Secret/credential detection
│
├── taint/                         # Data flow analysis
│   └── taint_analyzer.py         # Tracks data from source to sink
│
├── llm/                           # LLM integration (--llm flag)
│   ├── cerebras_analyzer.py      # Cerebras GPT-OSS-120B integration
│   │   # Interfaces with Cerebras API for deep semantic analysis
│   │
│   ├── context_optimizer.py      # Smart file ranking for LLM
│   │   # Prioritizes files for analysis within LLM context limits
│   │
│   ├── llm_integration.py        # Coordinates LLM analysis
│   │   # Manages batch processing and result aggregation
│   │
│   └── prompts.py                # Security-focused prompts
│       # Contains specialized prompts for threat detection
│
└── archive/                       # Old/experimental analyzers
    # Legacy code and experimental features not in production

src/
├── semantics/                     # ML-based analysis
│   ├── model_ensemble.py         # Ensemble ML models for threat detection
│   ├── semantic_analyzer.py      # Code semantic understanding
│   └── pattern_learner.py        # Pattern learning from examples
│
└── utils/                         # Utility functions
    ├── file_processor.py          # File handling and parsing
    ├── git_handler.py             # GitHub repository cloning
    └── report_generator.py        # Report formatting utilities

examples/
├── malicious_command_injection/    # Test cases for command injection
├── malicious_credential_theft/     # Credential theft examples
├── malicious_obfuscated/          # Obfuscated code samples
├── malicious_prompt_injection/     # Prompt injection tests
├── suspicious_mixed/               # Mixed threat examples
└── super_evals/                   # Comprehensive test suite
    ├── ssrf_unguarded/            # SSRF without protection
    ├── ssrf_guarded/              # SSRF with proper guards
    ├── creds_flow/                # Credential flow tracking
    ├── command_injection/         # Various injection patterns
    └── mcp_secrets/               # Secrets in config files

reports/                           # Generated security reports
    # JSON and text reports from analysis runs

docs/                              # Documentation
    # Additional documentation and guides
```

### Key Files Explained

#### Core Analysis Engine
- **comprehensive_mcp_analyzer.py**: The main orchestrator that coordinates all analysis modules, manages the scanning pipeline, and generates final threat scores.

#### Detection Modules
- **shared_constants.py**: Central repository of threat patterns, including regex for command injection, data exfiltration patterns, and suspicious API calls.
- **ssrf_detector.py**: Identifies Server-Side Request Forgery vulnerabilities by analyzing HTTP request patterns and URL validation.
- **credential_scanner.py**: Detects hardcoded credentials, API keys, and sensitive data patterns in code and configuration files.

#### Analysis Enhancement
- **taint_analyzer.py**: Performs inter-procedural data flow analysis to track how user input flows to dangerous sinks.
- **model_ensemble.py**: Combines multiple ML models to provide a consensus threat score with reduced false positives.

#### Reporting
- **report_formatter.py**: Transforms raw analysis data into comprehensive, actionable security reports with severity ratings and remediation guidance.

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

### Near-term milestones (actively in progress)
- Implement SSRF guard checks (host/IP validation, redirect policy, `file://` ban) → emit `CWE-918`
- Implement credential rules for common secret stores and sensitive paths → pair with network sinks for CRITICAL
- Inter-procedural taint flows for user_input→exec and sensitive_read→network, producing path evidence

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

---

**Remember**: This tool is a work in progress with significant detection gaps. Do not rely on it as your sole security measure. Always perform manual security reviews and use defense-in-depth strategies.