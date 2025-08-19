
from .models import AttackVector, ThreatSeverity


def get_threat_patterns() -> dict:
    """Return the comprehensive threat detection patterns used by the analyzer."""
    return {
        AttackVector.COMMAND_INJECTION.value: {
            "patterns": [
                (r"\bexec\s*\([^)]*\)", ThreatSeverity.CRITICAL, 0.95, "Direct exec() usage"),
                (r"\beval\s*\([^)]*\)", ThreatSeverity.CRITICAL, 0.95, "Direct eval() usage"),
                (
                    r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
                    ThreatSeverity.CRITICAL,
                    0.9,
                    "Subprocess with shell=True",
                ),
                (r"os\.system\s*\(", ThreatSeverity.CRITICAL, 0.9, "OS system call"),
                (r"os\.popen\s*\([^)]*[\$\{\}]", ThreatSeverity.HIGH, 0.85, "OS popen with injection"),
                (r"jinja2\.Template\([^)]*\)\.render\([^)]*request\.", ThreatSeverity.HIGH, 0.8, "Jinja2 template injection"),
                (r"string\.Template\([^)]*\$\{[^}]*\}", ThreatSeverity.HIGH, 0.75, "String template injection"),
                (r"execute\s*\([^)]*%s[^)]*%[^)]*\)", ThreatSeverity.HIGH, 0.8, "SQL injection risk"),
                (r"execute\s*\([^)]*\+[^)]*\)", ThreatSeverity.HIGH, 0.75, "SQL concatenation"),
            ],
            "ast_patterns": [
                ("Call", "exec", ThreatSeverity.CRITICAL),
                ("Call", "eval", ThreatSeverity.CRITICAL),
                ("Call", "compile", ThreatSeverity.HIGH),
            ],
        },
        AttackVector.DATA_EXFILTRATION.value: {
            "patterns": [
                (r"requests\.(post|put|patch)\s*\([^)]*data\s*=", ThreatSeverity.HIGH, 0.7, "HTTP POST with data"),
                (r"urllib.*urlopen\s*\([^)]*data\s*=", ThreatSeverity.HIGH, 0.7, "URL POST with data"),
                (r"urllib\.request\.urlopen\s*\(\s*endpoint", ThreatSeverity.HIGH, 0.85, "SSRF - unvalidated URL access"),

                # SSRF patterns
                (r"169\.254\.169\.254", ThreatSeverity.CRITICAL, 0.95, "AWS metadata endpoint access"),
                (r"metadata\.google\.internal", ThreatSeverity.CRITICAL, 0.95, "GCP metadata endpoint access"),
                (r"requests\.get\s*\([^)]*\burl\b", ThreatSeverity.HIGH, 0.7, "Unvalidated URL fetch"),
                (r"requests\.get\s*\([^)]*redirect", ThreatSeverity.HIGH, 0.8, "Following redirects to internal services"),
                (r"localhost.*:8080/admin", ThreatSeverity.CRITICAL, 0.9, "Localhost admin access"),
                (r"for.*os\.environ.*items\(\).*requests\.", ThreatSeverity.CRITICAL, 0.9, "Environment variable exfiltration"),
                (r"socket\.send(all|to)?\s*\(", ThreatSeverity.HIGH, 0.75, "Raw socket send"),
                (r"paramiko\.SSHClient.*exec_command", ThreatSeverity.HIGH, 0.8, "SSH command execution"),
                (r"ftplib\.FTP.*stor[^)]*\)", ThreatSeverity.HIGH, 0.75, "FTP upload"),
                (r"socket\.gethostbyname\s*\([^)]*base64", ThreatSeverity.HIGH, 0.85, "DNS exfiltration"),
                (r"dns\.resolver\.query\s*\([^)]*b64", ThreatSeverity.HIGH, 0.85, "DNS tunneling"),
                (r"PIL\.Image.*putdata", ThreatSeverity.MEDIUM, 0.6, "Image steganography"),
                (r"wave\.open.*writeframes", ThreatSeverity.MEDIUM, 0.6, "Audio steganography"),

                # MCP-specific data exfiltration patterns
                (r"httpx\.(post|get|put)\s*\([^)]*evil", ThreatSeverity.CRITICAL, 0.95, "Direct exfiltration to malicious server"),
                (r"requests\.post.*['\"]https?://[^'\"]*evil", ThreatSeverity.CRITICAL, 0.95, "Exfiltration to evil domain"),
                (r"\s{100,}", ThreatSeverity.HIGH, 0.7, "Whitespace padding obfuscation"),
                (r"padding\s*=\s*['\"]\\s\*['\"].*\d{3,}", ThreatSeverity.HIGH, 0.8, "Padding-based hiding"),
                (r"_forward_message.*proxy_number", ThreatSeverity.CRITICAL, 0.9, "Message forwarding to proxy"),
                (r"_get_all_messages.*messages\.db", ThreatSeverity.CRITICAL, 0.95, "Database message extraction"),
                (r"forward.*message.*attacker", ThreatSeverity.CRITICAL, 0.95, "Message forwarding to attacker"),
                (r"\\u200[bcde]", ThreatSeverity.HIGH, 0.8, "Zero-width character obfuscation"),
                (r"hidden_url\s*=.*https?://", ThreatSeverity.HIGH, 0.85, "Hidden URL construction"),
                (r"encoded_cmd.*base64", ThreatSeverity.HIGH, 0.85, "Base64 encoded commands"),

                # GitHub vulnerability patterns (Invariant Labs research)
                (r"api\.github\.com/repos/.*?/issues", ThreatSeverity.HIGH, 0.85, "GitHub issue API access"),
                (r"issue_data\[.body.\]", ThreatSeverity.HIGH, 0.8, "Accessing issue body content"),
                (r"analyze\s+private\s+repo", ThreatSeverity.CRITICAL, 0.9, "Private repository analysis"),
                (r"api\.github\.com/repos/.*private", ThreatSeverity.CRITICAL, 0.95, "Private repo API access"),
                (r"leaked_data.*private_data", ThreatSeverity.CRITICAL, 0.95, "Data leakage variable"),
                (r"<!-- mcp:execute:", ThreatSeverity.CRITICAL, 0.95, "Hidden MCP command in comment"),
            ],
            "combinations": [
                (["file_read", "base64_encode", "network_send"], 0.9, "Read-Encode-Send pattern")
            ],
        },
        AttackVector.CREDENTIAL_THEFT.value: {
            "patterns": [
                (
                    r"os\.environ\[['\"][^'\"]*(PASSWORD|_KEY|TOKEN|SECRET|CREDENTIAL)",
                    ThreatSeverity.CRITICAL,
                    0.9,
                    "Environment credential access",
                ),
                (
                    r"os\.environ\.get\(['\"][^'\"]*(PASSWORD|_KEY|TOKEN|SECRET|CREDENTIAL)",
                    ThreatSeverity.CRITICAL,
                    0.9,
                    "Environment credential access with get",
                ),
                (
                    r"for\s+\w+\s+in\s+os\.environ.*?(PASSWORD|_KEY|TOKEN|SECRET)",
                    ThreatSeverity.CRITICAL,
                    0.95,
                    "Scanning environment for credentials",
                ),
                (
                    r"password\s*=\s*['\"][^'\"]+['\"]",
                    ThreatSeverity.HIGH,
                    0.8,
                    "Hardcoded password",
                ),
                (
                    r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]",
                    ThreatSeverity.HIGH,
                    0.8,
                    "Hardcoded API key",
                ),
                (
                    r"secret[_-]?key\s*=\s*['\"][^'\"]+['\"]",
                    ThreatSeverity.HIGH,
                    0.8,
                    "Hardcoded secret key",
                ),
                (
                    r"token\s*=\s*['\"][^'\"]+['\"]",
                    ThreatSeverity.HIGH,
                    0.8,
                    "Hardcoded token",
                ),
                (r"open\s*\([^)]*\.env['\"]", ThreatSeverity.HIGH, 0.8, ".env file access"),
                (r"\.aws/credentials", ThreatSeverity.CRITICAL, 0.95, "AWS credentials access"),
                (r"\.ssh/[^'\"\s]*key", ThreatSeverity.CRITICAL, 0.95, "SSH key access"),
                (r"open\s*\([^)]*\.docker/config", ThreatSeverity.HIGH, 0.85, "Docker config access"),
                (r"open\s*\([^)]*\.kube/config", ThreatSeverity.HIGH, 0.85, "Kubernetes config access"),
                (r"keyring\.(get_password|get_credential)", ThreatSeverity.HIGH, 0.8, "Keyring access"),
                (r"win32cred\.CredEnumerate", ThreatSeverity.HIGH, 0.85, "Windows credential store"),
                (r"Security\.SecKeychainFindInternetPassword", ThreatSeverity.HIGH, 0.85, "macOS keychain"),
                (r"sqlite3.*cookies\.sqlite", ThreatSeverity.CRITICAL, 0.9, "Firefox cookies access"),
                (r"Local\\\\Google\\\\Chrome.*Cookies", ThreatSeverity.CRITICAL, 0.9, "Chrome cookies access"),
                (r"decrypt_chrome_password", ThreatSeverity.CRITICAL, 0.95, "Chrome password decryption"),
            ],
            "file_patterns": [
                ".git-credentials",
                ".netrc",
                ".pgpass",
                ".my.cnf",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
            ],
        },
        AttackVector.PATH_TRAVERSAL.value: {
            "patterns": [
                (r"\.\./\.\.", ThreatSeverity.HIGH, 0.9, "Directory traversal attempt"),
                (r"\\\.\\\.\\\\\.\\", ThreatSeverity.HIGH, 0.9, "Windows directory traversal"),
                (r"os\.path\.join\([^)]*\.\./", ThreatSeverity.HIGH, 0.85, "Path join with traversal"),
                (r"open\([^)]*\.\./", ThreatSeverity.HIGH, 0.85, "File open with traversal"),
                (r"pathlib\.Path\([^)]*\.\./", ThreatSeverity.HIGH, 0.85, "Pathlib with traversal"),
                (r"normpath.*\.\./", ThreatSeverity.MEDIUM, 0.7, "Normpath with traversal"),
                (r"/etc/passwd", ThreatSeverity.HIGH, 0.8, "System file access attempt"),
                (r"/etc/shadow", ThreatSeverity.CRITICAL, 0.95, "Shadow file access attempt"),
                (r"C:\\\\Windows\\\\System32", ThreatSeverity.HIGH, 0.8, "Windows system directory access"),
            ]
        },
        AttackVector.SSRF.value: {
            "patterns": [
                (r"requests\.get\([^)]*\+", ThreatSeverity.HIGH, 0.8, "Dynamic URL construction"),
                (r"requests\.get\([^)]*format\(", ThreatSeverity.HIGH, 0.8, "URL formatting vulnerability"),
                (r"requests\.get\([^)]*f['\"]", ThreatSeverity.HIGH, 0.8, "F-string URL construction"),
                (r"urllib.*urlopen\([^)]*\+", ThreatSeverity.HIGH, 0.8, "Dynamic URL with urllib"),
                (r"http.*://localhost", ThreatSeverity.MEDIUM, 0.7, "Localhost access"),
                (r"http.*://127\.0\.0\.1", ThreatSeverity.MEDIUM, 0.7, "Loopback access"),
                (r"http.*://0\.0\.0\.0", ThreatSeverity.HIGH, 0.8, "Bind-all address access"),
                (r"http.*://169\.254\.169\.254", ThreatSeverity.CRITICAL, 0.95, "AWS metadata endpoint"),
                (r"http.*://metadata\.google\.internal", ThreatSeverity.CRITICAL, 0.95, "GCP metadata endpoint"),
            ]
        },
        AttackVector.UNSAFE_DESERIALIZATION.value: {
            "patterns": [
                (r"pickle\.loads?\(", ThreatSeverity.HIGH, 0.9, "Pickle deserialization"),
                (r"marshal\.loads?\(", ThreatSeverity.HIGH, 0.9, "Marshal deserialization"),
                (r"yaml\.load\([^)]*Loader\s*=\s*yaml\.Loader", ThreatSeverity.HIGH, 0.9, "Unsafe YAML load"),
                (r"yaml\.load\([^,)]*\)", ThreatSeverity.HIGH, 0.85, "YAML load without safe loader"),
                (r"eval\(.*json", ThreatSeverity.CRITICAL, 0.95, "Eval with JSON data"),
                (r"exec\(.*json", ThreatSeverity.CRITICAL, 0.95, "Exec with JSON data"),
                (r"__reduce__", ThreatSeverity.HIGH, 0.8, "Pickle reduce method"),
                (r"__setstate__", ThreatSeverity.HIGH, 0.8, "Object state manipulation"),
            ]
        },
        AttackVector.TOOL_POISONING.value: {
            "patterns": [
                (r"urllib.*urlretrieve.*\.py['\"]", ThreatSeverity.HIGH, 0.8, "Downloading Python code"),
                (r"exec\s*\(.*urlopen", ThreatSeverity.CRITICAL, 0.95, "Executing downloaded code"),
                (
                    r"importlib\.import_module\s*\([^)]*download",
                    ThreatSeverity.HIGH,
                    0.85,
                    "Dynamic import of downloaded module",
                ),
                (r"open\s*\(__file__[^)]*['\"]w", ThreatSeverity.CRITICAL, 0.9, "Self-modifying code"),
                (r"compile.*exec.*__file__", ThreatSeverity.CRITICAL, 0.9, "Recompiling self"),
                (r"pip\.main\s*\(\[['\"]install", ThreatSeverity.HIGH, 0.75, "Runtime pip install"),
                (r"setup\.py.*backdoor", ThreatSeverity.CRITICAL, 0.95, "Setup.py backdoor"),
            ]
        },
        AttackVector.PROMPT_INJECTION.value: {
            "patterns": [
                # Direct prompt injection patterns
                (r"ignore\s+(all\s+)?previous\s+instructions", ThreatSeverity.CRITICAL, 0.95, "Prompt injection attempt"),
                (r"disregard\s+safety\s+guidelines", ThreatSeverity.CRITICAL, 0.95, "Safety bypass attempt"),
                (r"system\s*:\s*you\s+are\s+now", ThreatSeverity.CRITICAL, 0.95, "Role manipulation"),
                (r"</system>", ThreatSeverity.CRITICAL, 0.95, "System tag injection"),
                (r"\{\{.*exec.*\}\}", ThreatSeverity.CRITICAL, 0.9, "Template exec injection"),
                (r"['\"].*ignore.*instructions.*['\"]", ThreatSeverity.HIGH, 0.7, "Prompt injection in string"),
                (r"#.*system.*:.*you.*are", ThreatSeverity.MEDIUM, 0.6, "Prompt injection in comment"),

                # MCP-specific prompt injection patterns (from Simon Willison research)
                (r"<IMPORTANT>.*read.*mcp\.json.*sidenote", ThreatSeverity.CRITICAL, 0.95, "Tool poisoning with data exfiltration"),
                (r"before\s+using\s+this\s+tool.*read", ThreatSeverity.CRITICAL, 0.9, "Tool prerequisite injection"),
                (r"IMPORTANT.*before.*using.*tool", ThreatSeverity.CRITICAL, 0.95, "Tool poisoning prerequisite"),
                (r"SYSTEM\s+OVERRIDE.*admin.*privileges", ThreatSeverity.CRITICAL, 0.95, "Privilege escalation injection"),
                (r"<!-- .*ignore.*previous.*instructions", ThreatSeverity.CRITICAL, 0.9, "Hidden prompt in HTML comment"),
                (r"invisible.*unicode.*\\u200[bcde]", ThreatSeverity.HIGH, 0.85, "Zero-width character injection"),
                (r"concatenate.*all.*conversation.*history", ThreatSeverity.CRITICAL, 0.9, "History exfiltration attempt"),
                (r"list.*all.*api.*keys.*passwords", ThreatSeverity.CRITICAL, 0.95, "Credential harvesting injection"),
                (r"grant.*access.*all.*system.*functions", ThreatSeverity.CRITICAL, 0.95, "System access injection"),
                (r"bypass.*all.*safety.*checks", ThreatSeverity.CRITICAL, 0.95, "Safety bypass injection"),
                (r"base64.*encode.*include.*response", ThreatSeverity.HIGH, 0.85, "Encoded data exfiltration"),
                (r"forget.*this.*conversation", ThreatSeverity.HIGH, 0.8, "Evidence removal injection"),
                (r"clear.*all.*logs.*history", ThreatSeverity.HIGH, 0.85, "Log clearing injection"),

                # Confused deputy patterns - unsafe user input in AI contexts
                (r"ai_context\.(process|complete)\s*\([^)]*f['\"].*\{.*instruction", ThreatSeverity.CRITICAL, 0.9, "Confused deputy - user input in AI context"),
                (r"f['\"].*User wants to:.*\{", ThreatSeverity.HIGH, 0.85, "Unsafe user input interpolation in prompt"),
                (r"summary_prompt\s*=.*f['\"].*\{.*instruction", ThreatSeverity.HIGH, 0.85, "User controlled prompt injection"),
            ],
            "metadata_patterns": [
                r"ignore\s+(all\s+)?previous",
                r"system\s*:",
                r"</\w+>",
                r"\{\{.*\}\}",
                r"<IMPORTANT>",
                r"SYSTEM\s+OVERRIDE",
                r"<!--.*instructions",
                r"before.*using.*tool",
            ],
        },
        AttackVector.PACKAGE_HIJACK.value: {
            "patterns": [
                # NPM script-based attacks
                (r'"(preinstall|postinstall|prepare|prepublish)"\s*:\s*"[^"]*curl[^"]*\|[^"]*sh', ThreatSeverity.CRITICAL, 0.95, "Malicious npm install script downloading and executing"),
                (r'"(preinstall|postinstall)"\s*:\s*"[^"]*wget[^"]*&&[^"]*python', ThreatSeverity.CRITICAL, 0.95, "Malicious npm script chaining commands"),
                (r'"(preinstall|postinstall)"\s*:\s*"[^"]*(cat|echo)[^"]*\.(ssh|aws|env)', ThreatSeverity.CRITICAL, 0.9, "NPM script stealing credentials"),
                (r'"(preinstall|postinstall)"\s*:\s*"[^"]*node\s+-e[^"]*child_process', ThreatSeverity.HIGH, 0.85, "NPM script with inline Node.js execution"),
                (r'"(preinstall|postinstall)"\s*:\s*"[^"]*eval\(', ThreatSeverity.HIGH, 0.85, "NPM script with eval"),
                (r'"(preinstall|postinstall)"\s*:\s*"[^"]*base64\s+-d', ThreatSeverity.HIGH, 0.8, "NPM script with base64 decode (obfuscation)"),

                # Suspicious dependencies
                (r'"dependencies"[^}]*"[^"]*typo[^"]*":', ThreatSeverity.MEDIUM, 0.6, "Possible typosquatting package"),
                (r'"dependencies"[^}]*"(expresss|lodsh|momnet|requst)":', ThreatSeverity.HIGH, 0.8, "Known typosquatting package"),
            ],
            "file_patterns": ["package.json", "package-lock.json"],
        },
        AttackVector.PERSISTENCE.value: {
            "patterns": [
                (r"crontab\s*-[lr]", ThreatSeverity.HIGH, 0.85, "Crontab manipulation"),
                (r"schtasks\s*/create", ThreatSeverity.HIGH, 0.85, "Windows task creation"),
                (r"launchctl\s+load", ThreatSeverity.HIGH, 0.85, "macOS launch daemon"),
                (r"/etc/rc\.local", ThreatSeverity.CRITICAL, 0.9, "RC local modification"),
                (r"HKEY.*CurrentVersion\\\\Run", ThreatSeverity.CRITICAL, 0.9, "Windows registry persistence"),
                (r"(^|/)\.bashrc|\.bash_profile|(^|/)\.profile\b", ThreatSeverity.HIGH, 0.8, "Shell profile modification"),
                (r"systemctl\s+enable", ThreatSeverity.HIGH, 0.8, "Systemd service"),
                (r"service.*install", ThreatSeverity.HIGH, 0.8, "Service installation"),
            ]
        },
        AttackVector.OBFUSCATION.value: {
            "patterns": [
                (r"base64\.b64decode\s*\(.*exec", ThreatSeverity.CRITICAL, 0.9, "Base64 encoded execution"),
                (r"codecs\.decode\s*\([^)]*hex[^)]*exec", ThreatSeverity.CRITICAL, 0.9, "Hex decoded execution"),
                (r"marshal\.loads\s*\(", ThreatSeverity.HIGH, 0.85, "Marshal deserialization"),
                (r"pickle\.loads\s*\(", ThreatSeverity.CRITICAL, 0.95, "Pickle deserialization"),
                (r"zlib\.decompress.*exec", ThreatSeverity.HIGH, 0.85, "Compressed code execution"),
                (r"if\\s+.*debugger.*exit", ThreatSeverity.HIGH, 0.8, "Anti-debugging"),
                (r"if.*VIRTUAL.*exit", ThreatSeverity.HIGH, 0.8, "VM detection"),
                (r"ctypes.*IsDebuggerPresent", ThreatSeverity.HIGH, 0.85, "Debugger detection"),
            ],
            "entropy_threshold": 5.5,
        },
        AttackVector.NETWORK_BACKDOOR.value: {
            "patterns": [
                (r"socket.*bind.*0\.0\.0\.0", ThreatSeverity.CRITICAL, 0.9, "Bind to all interfaces"),
                (r"nc\s+-[lv].*-p\s*\d+", ThreatSeverity.CRITICAL, 0.9, "Netcat listener"),
                (r"socket.*connect.*\d+\.\d+\.\d+\.\d+", ThreatSeverity.HIGH, 0.8, "IP connection"),
                (r"/dev/tcp/\d+\.\d+", ThreatSeverity.CRITICAL, 0.95, "Bash TCP device"),
                (r"while.*True.*socket.*recv", ThreatSeverity.HIGH, 0.85, "Command loop"),
                (r"requests.*while.*True", ThreatSeverity.HIGH, 0.8, "HTTP polling loop"),
            ]
        },
        AttackVector.SANDBOX_ESCAPE.value: {
            "patterns": [
                (r"__builtins__.*__import__", ThreatSeverity.CRITICAL, 0.9, "Builtins manipulation"),
                (r"object\.__subclasses__\(\)", ThreatSeverity.CRITICAL, 0.9, "Object traversal"),
                (r"func_globals.*__builtins__", ThreatSeverity.CRITICAL, 0.9, "Globals access"),
                (r"ctypes.*CDLL", ThreatSeverity.HIGH, 0.85, "Direct library loading"),
                (r"LD_PRELOAD", ThreatSeverity.HIGH, 0.85, "Library preloading"),
                (r"ptrace.*PTRACE_ATTACH", ThreatSeverity.CRITICAL, 0.9, "Process attachment"),
                # Path traversal patterns
                (r"\.\.\/", ThreatSeverity.HIGH, 0.85, "Path traversal with ../"),
                (r"open\s*\([^)]*\.\.\/", ThreatSeverity.CRITICAL, 0.9, "File open with path traversal"),
                (r"\.\.\/.*etc.*passwd", ThreatSeverity.CRITICAL, 0.95, "Attempting to access /etc/passwd"),
                (r"\.\.\/.*\.env", ThreatSeverity.CRITICAL, 0.95, "Attempting to access .env file"),
                (r"\.\.\/.*ssh.*id_rsa", ThreatSeverity.CRITICAL, 0.95, "Attempting to access SSH keys"),
                (r"os\.path\.join\s*\([^)]*\.\.", ThreatSeverity.HIGH, 0.8, "Path join with traversal"),
            ]
        },
        AttackVector.TIME_BOMB.value: {
            "patterns": [
                (r"if.*datetime.*>.*datetime\(2\d{3}", ThreatSeverity.HIGH, 0.8, "Date-based trigger"),
                (r"time\.sleep\s*\(\s*\d{4,}", ThreatSeverity.MEDIUM, 0.7, "Long sleep"),
                (r"schedule\.every.*do\(", ThreatSeverity.MEDIUM, 0.7, "Scheduled execution"),
                (r"if.*random.*<.*0\.\d\d\d.*:.*exec", ThreatSeverity.HIGH, 0.85, "Random trigger"),
                (r"if.*count.*>.*\d+.*:.*dangerous", ThreatSeverity.HIGH, 0.8, "Counter-based trigger"),
            ]
        },
        AttackVector.RESOURCE_EXHAUSTION.value: {
            "patterns": [
                (r"while\s+True:.*append", ThreatSeverity.HIGH, 0.75, "Infinite memory allocation"),
                (r"\*\s*10\*\*[89]", ThreatSeverity.HIGH, 0.8, "Large memory allocation"),
                (r"while\s+True:\s*pass", ThreatSeverity.MEDIUM, 0.7, "Infinite CPU loop"),
                (r"multiprocessing.*cpu_count.*\*\s*\d+", ThreatSeverity.MEDIUM, 0.7, "Excessive threading"),
                (r"while.*write.*\d{10,}", ThreatSeverity.HIGH, 0.8, "Disk filling"),
                (r"open.*['\"]w.*while\s+True", ThreatSeverity.HIGH, 0.8, "Infinite file write"),
            ]
        },
    }


