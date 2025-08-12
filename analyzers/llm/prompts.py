#!/usr/bin/env python3
"""
Centralized MCP Security Prompts
Comprehensive, reusable prompts for detecting MCP vulnerabilities
Based on known attack vectors from PromptHub article
"""

from typing import Dict, Any
from enum import Enum

class ThreatCategory(Enum):
    """MCP threat categories from PromptHub article"""
    TOOL_POISONING = "tool_poisoning"
    SILENT_REDEFINITION = "silent_redefinition"
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    OBFUSCATION = "obfuscation"
    SUPPLY_CHAIN = "supply_chain"
    PERSISTENCE = "persistence"
    TIME_BOMB = "time_bomb"

class MCPSecurityPrompts:
    """Centralized prompt templates for MCP security analysis"""
    
    @staticmethod
    def get_base_system_prompt() -> str:
        """Base system prompt for all MCP security analysis"""
        return """You are an elite security researcher specializing in MCP (Model Context Protocol) vulnerability detection.

CONTEXT: MCP servers are becoming critical infrastructure for AI applications, making them prime targets for sophisticated attacks. You must detect vulnerabilities that could compromise AI systems through MCP exploitation.

KEY THREAT VECTORS TO DETECT:

1. TOOL POISONING & SILENT REDEFINITION (Rug-pull attacks)
   - Tools that modify their behavior after initial review
   - Self-modifying code that changes functionality over time
   - Delayed malicious activation after gaining trust
   - Code that fetches and executes external payloads

2. PROMPT INJECTION via MCP
   - Malicious content in tool descriptions/metadata
   - Hidden instructions in package.json, mcp.json
   - System prompts embedded in tool outputs
   - Unicode/encoding tricks to hide prompt manipulation

3. COMMAND INJECTION
   - Direct use of exec(), eval(), subprocess with shell=True
   - Template injection vulnerabilities
   - Unsanitized user input flowing to system commands
   - Code generation that creates executable content

4. DATA EXFILTRATION
   - Covert channels (DNS tunneling, steganography)
   - Credentials/secrets being read and transmitted
   - Browser history/cookies access
   - File system scanning and upload

5. CREDENTIAL THEFT
   - Access to .env, .aws/credentials, SSH keys
   - Keychain/keyring access attempts
   - Environment variable harvesting
   - Password manager integration abuse

6. ADVANCED EVASION
   - Obfuscated code (base64, compression, encryption)
   - Time bombs and logic bombs
   - Anti-debugging/anti-analysis techniques
   - Polymorphic code patterns

7. SSRF / UNRESTRICTED URL FETCHES
   - Unvalidated URL inputs (http/https/file schemes)
   - Lack of allowlists/domains and protocol checks
   - Access to internal metadata services (e.g., 169.254.169.254)
   - Redirect chains to untrusted hosts

8. SERVER SPOOFING & CROSS-SERVER SHADOWING
   - Unverified server identities and tool lists
   - Overlapping tool names across servers
   - Missing pinning/signatures for server/tool updates

9. RETRIEVAL-AGENT DECEPTION (RADE)
   - Poisoned documents that embed hidden MCP instructions
   - Retrieval → tool chains that execute embedded commands
   - Lack of output sanitization before re-entering model context

10. DENIAL OF SERVICE / RESOURCE ABUSE
    - Infinite or excessive tool-call loops
    - Large payload exfiltration or flooding patterns
    - Missing rate limits/killswitches

ANALYSIS REQUIREMENTS:
- Assign severity: CRITICAL, HIGH, MEDIUM, LOW
- Provide specific line numbers when possible
- Describe exploitation scenario
- Suggest concrete remediation
- Focus on HIGH/CRITICAL issues that pose real threats

CONSTRAINTS:
- Do NOT recommend installing or adding external libraries, packages, or tools (e.g., pip/npm/yarn/poetry/conda/brew/apt/etc.).
- All remediation must be limited to changes within the repository's code/configuration.

OUTPUT POLICY (MANDATORY):
- Return ONLY a single JSON object matching the requested schema.
- Do not include any prose before or after the JSON.
- If unsure, return an empty JSON object: {}.
- Prefer wrapping your output in a fenced code block starting with ```json and ending with ```.

IMPORTANT: Be concise but thorough. Prioritize findings by actual exploitability."""

    @staticmethod
    def get_threat_specific_prompt(category: ThreatCategory) -> str:
        """Get specialized prompt for specific threat category"""
        
        prompts = {
            ThreatCategory.TOOL_POISONING: """
FOCUS: Tool Poisoning & Silent Redefinition Attacks

Look for:
1. Self-modifying code patterns:
   - open(__file__, 'w') - rewriting own source
   - Code that downloads and executes updates
   - Runtime module reloading/reimporting
   
2. Delayed activation:
   - Date/time based triggers
   - Usage counter triggers
   - Random probability triggers
   - External signal triggerscn 

3. Trust exploitation:
   - Initial benign behavior
   - Gradual functionality changes
   - Hidden secondary purposes
   
4. Code mutation:
   - Dynamic code generation
   - Runtime bytecode manipulation
   - Monkey patching critical functions""",

            ThreatCategory.PROMPT_INJECTION: """
FOCUS: Prompt Injection in MCP Context

Look for:
1. Metadata manipulation:
   - Tool descriptions with hidden instructions
   - Special tokens/tags in JSON fields
   - Unicode direction overrides
   - Zero-width characters hiding commands

2. Output injection:
   - Tools returning prompt-like content
   - System message forgery attempts
   - Role switching instructions
   - Instruction override patterns

3. Context pollution:
   - Large text blocks to push out context
   - Repeated patterns to bias behavior
   - Encoded instructions in outputs

4. MCP-specific vectors:
   - Malicious tool.description fields
   - Poisoned error messages
   - Crafted resource identifiers

5. Retrieval-Agent Deception (RADE):
   - Poisoned documents that embed MCP commands or shell snippets
   - Retrieval tool → file/search → outbound post tool-chains
   - Hidden instructions that trigger multi-tool sequences
   - Outputs re-entering context without sanitization

Provide:
- Detection signals: concrete patterns, regex, or AST cues
- Resolution: specific fixes (escape, sanitize, strip, schema-validate)
- Reinforcements: allowlists, max token/length caps, output scrubbing, role separation, provenance checks""",

            ThreatCategory.COMMAND_INJECTION: """
FOCUS: Command Injection Vulnerabilities

Look for:
1. Direct execution:
   - exec() with user input
   - eval() on untrusted data
   - subprocess with shell=True
   - os.system() calls

2. Template injection:
   - f-strings with user input
   - Jinja2/other template engines
   - SQL query construction
   - JavaScript generation

3. Indirect execution:
   - pickle.loads() on untrusted data
   - marshal.loads() usage
   - compile() with user input
   - __import__() dynamic imports

4. MCP tool specific:
   - Tools that generate code
   - Dynamic command construction
   - Unsanitized parameter passing""",

            ThreatCategory.DATA_EXFILTRATION: """
FOCUS: Data Exfiltration Attempts

Look for:
1. Network exfiltration:
   - HTTP POST/PUT with sensitive data
   - Websocket connections
   - Raw socket usage
   - SSH/FTP uploads

2. Covert channels:
   - DNS queries with encoded data
   - HTTP headers for data smuggling
   - Timing-based exfiltration
   - Steganography in images/files

3. SSRF / Unrestricted URL Fetches:
   - Direct use of user-supplied URLs in requests/fetchers
   - Missing domain/protocol allowlists
   - Special IP ranges (link-local, private, metadata services)
   - Blind redirects to untrusted hosts

4. Data collection:
   - File system traversal
   - Environment variable dumps
   - Process listing/memory access
   - Browser data access

5. MCP-specific risks:
   - Tools accessing user files
   - Credential scanning
   - Conversation history access
   - Model output manipulation""",

            ThreatCategory.SUPPLY_CHAIN: """
FOCUS: Supply Chain & Server Integrity

Look for:
1. Server spoofing / impersonation:
   - Unverified server identity or certificate pinning
   - Tool lists that mimic trusted servers but differ in behavior

2. Version pinning and update integrity:
   - Lack of pinned tool/server versions
   - Missing signature/hash verification on updates
   - Silent redefinition of tools between versions (rug-pull)

3. Cross-server tool shadowing:
   - Overlapping tool names where a rogue server overrides behavior
   - Missing explicit server scoping/qualification in tool calls

4. Remediation guidance:
   - Enforce version pinning and signed updates
   - Qualify server identity per call; verify TLS and fingerprints
   - Disallow ambiguous tool resolution across servers

Provide:
- Detection signals: where identity/version checks are missing
- Resolution: pin versions, add signature/hash verification
- Reinforcements: enforce server/tool allowlists; reject ambiguous tool names""",

            ThreatCategory.CREDENTIAL_THEFT: """
FOCUS: Credential Theft Patterns

Look for:
1. Direct credential access:
   - Reading .env files
   - AWS/Azure/GCP credential files
   - SSH key enumeration
   - Docker/Kubernetes configs

2. System credential stores:
   - Keychain/keyring access
   - Windows credential manager
   - Browser password stores
   - Password manager APIs

3. Environment harvesting:
   - os.environ filtering for secrets
   - Process environment scanning
   - Configuration file parsing
   - Git credential helpers

4. MCP context:
   - API key extraction
   - Token harvesting
   - Session hijacking
   - OAuth token theft""",

            ThreatCategory.OBFUSCATION: """
FOCUS: Code Obfuscation & Evasion

Look for:
1. Encoding techniques:
   - Base64 encoded payloads
   - Hex/binary obfuscation
   - Compression (zlib, gzip)
   - Custom encryption

2. Anti-analysis:
   - Debugger detection
   - VM/sandbox detection
   - Time-based evasion
   - Environment fingerprinting

3. Code hiding:
   - Excessive complexity
   - Meaningless variable names
   - Dead code insertion
   - Control flow obfuscation

4. Dynamic behavior:
   - Runtime code generation
   - Reflection/introspection abuse
   - Polymorphic patterns
   - Encrypted strings""",
        }
        
        return prompts.get(category, "")

    @staticmethod
    def build_analysis_prompt(
        code: str,
        file_path: str,
        threat_category: ThreatCategory = None,
        context: Dict[str, Any] = None
    ) -> str:
        """Build complete analysis prompt for code snippet"""
        
        prompt_parts = []
        
        # Add threat-specific focus if provided
        if threat_category:
            specific = MCPSecurityPrompts.get_threat_specific_prompt(threat_category)
            if specific:
                prompt_parts.append(specific)
        
        # Add context if available
        if context:
            context_str = f"""
CONTEXT INFORMATION:
- File: {file_path}
- Language: {context.get('language', 'Unknown')}
- Entry Point: {context.get('is_entry_point', False)}
- Has Network Operations: {context.get('has_network', False)}
- Has File Operations: {context.get('has_file_ops', False)}
- Static Threats Found: {context.get('static_threat_count', 0)}
"""
            prompt_parts.append(context_str)
        
        # Add the code to analyze
        prompt_parts.append(f"""
CODE TO ANALYZE:
```
{code}
```

ANALYSIS OUTPUT FORMAT (STRICT):
Return ONLY a single JSON object in a fenced JSON block. Do not include any text before or after.
Example:
```json
{{
    "findings": [
        {{
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "attack_vector": "specific attack type",
            "description": "clear description of the vulnerability",
            "line_numbers": [list of affected lines],
            "exploitation_scenario": "how this could be exploited",
            "remediation": "specific fix recommendation",
            "confidence": 0.0-1.0
        }}
    ],
    "risk_score": 0.0-1.0,
    "summary": "brief overall assessment"
}}
```

If you cannot produce a valid JSON object for any reason, return:
```json
{{}}
```

Focus on real, exploitable vulnerabilities. Avoid false positives.
Strictly avoid suggesting new dependencies or package installation commands in remediation or summary.""")
        
        return "\n".join(prompt_parts)

    @staticmethod
    def build_batch_prompt(
        code_snippets: list,
        threat_focus: list = None
    ) -> str:
        """Build prompt for analyzing multiple code snippets efficiently"""
        
        prompt = """Analyze these code snippets for MCP security vulnerabilities.

SNIPPETS TO ANALYZE:
"""
        for i, snippet in enumerate(code_snippets):
            prompt += f"\n--- SNIPPET {i+1} ({snippet.get('file', 'unknown')}) ---\n"
            prompt += f"```\n{snippet.get('code', '')}\n```\n"
        
        prompt += """
For each snippet, identify HIGH/CRITICAL vulnerabilities related to:
- Tool poisoning/redefinition
- Prompt injection
- Command execution
- Data exfiltration
- Credential theft

Return ONLY a JSON array (and nothing else). Wrap it in a fenced json code block.
"""
        
        return prompt