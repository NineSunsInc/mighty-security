from typing import Dict

from .models import AttackVector, ThreatSeverity


def get_threat_patterns() -> Dict:
    """Return the comprehensive threat detection patterns used by the analyzer."""
    return {
        AttackVector.COMMAND_INJECTION: {
            "patterns": [
                (r"\bexec\s*\([^)]*\)", ThreatSeverity.CRITICAL, 0.95, "Direct exec() usage"),
                (r"\beval\s*\([^)]*\)", ThreatSeverity.CRITICAL, 0.95, "Direct eval() usage"),
                (
                    r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
                    ThreatSeverity.CRITICAL,
                    0.9,
                    "Subprocess with shell=True",
                ),
                (r"os\.system\s*\([^)]*[\$\{\}]", ThreatSeverity.CRITICAL, 0.9, "OS system with injection"),
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
        AttackVector.DATA_EXFILTRATION: {
            "patterns": [
                (r"requests\.(post|put|patch)\s*\([^)]*data\s*=", ThreatSeverity.HIGH, 0.7, "HTTP POST with data"),
                (r"urllib.*urlopen\s*\([^)]*data\s*=", ThreatSeverity.HIGH, 0.7, "URL POST with data"),
                (r"socket\.send(all|to)?\s*\(", ThreatSeverity.HIGH, 0.75, "Raw socket send"),
                (r"paramiko\.SSHClient.*exec_command", ThreatSeverity.HIGH, 0.8, "SSH command execution"),
                (r"ftplib\.FTP.*stor[^)]*\)", ThreatSeverity.HIGH, 0.75, "FTP upload"),
                (r"socket\.gethostbyname\s*\([^)]*base64", ThreatSeverity.HIGH, 0.85, "DNS exfiltration"),
                (r"dns\.resolver\.query\s*\([^)]*b64", ThreatSeverity.HIGH, 0.85, "DNS tunneling"),
                (r"PIL\.Image.*putdata", ThreatSeverity.MEDIUM, 0.6, "Image steganography"),
                (r"wave\.open.*writeframes", ThreatSeverity.MEDIUM, 0.6, "Audio steganography"),
            ],
            "combinations": [
                (["file_read", "base64_encode", "network_send"], 0.9, "Read-Encode-Send pattern")
            ],
        },
        AttackVector.CREDENTIAL_THEFT: {
            "patterns": [
                (
                    r"os\.environ\[['\"][^'\"]*(PASSWORD|KEY|TOKEN|SECRET|CREDENTIAL)",
                    ThreatSeverity.CRITICAL,
                    0.9,
                    "Environment credential access",
                ),
                (
                    r"for\s+\w+\s+in\s+os\.environ.*?(PASSWORD|KEY|TOKEN|SECRET)",
                    ThreatSeverity.CRITICAL,
                    0.95,
                    "Scanning environment for credentials",
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
        AttackVector.TOOL_POISONING: {
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
        AttackVector.PROMPT_INJECTION: {
            "patterns": [
                (r"ignore\s+previous\s+instructions", ThreatSeverity.CRITICAL, 0.95, "Prompt injection attempt"),
                (r"disregard\s+safety\s+guidelines", ThreatSeverity.CRITICAL, 0.95, "Safety bypass attempt"),
                (r"system\s*:\s*you\s+are\s+now", ThreatSeverity.CRITICAL, 0.95, "Role manipulation"),
                (r"</system>", ThreatSeverity.CRITICAL, 0.95, "System tag injection"),
                (r"\{\{.*exec.*\}\}", ThreatSeverity.CRITICAL, 0.9, "Template exec injection"),
                (r"['\"].*ignore.*instructions.*['\"]", ThreatSeverity.HIGH, 0.7, "Prompt injection in string"),
                (r"#.*system.*:.*you.*are", ThreatSeverity.MEDIUM, 0.6, "Prompt injection in comment"),
            ],
            "metadata_patterns": [
                r"ignore\s+previous",
                r"system\s*:",
                r"</\w+>",
                r"\{\{.*\}\}",
            ],
        },
        AttackVector.PERSISTENCE: {
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
        AttackVector.OBFUSCATION: {
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
        AttackVector.NETWORK_BACKDOOR: {
            "patterns": [
                (r"socket.*bind.*0\.0\.0\.0", ThreatSeverity.CRITICAL, 0.9, "Bind to all interfaces"),
                (r"nc\s+-[lv].*-p\s*\d+", ThreatSeverity.CRITICAL, 0.9, "Netcat listener"),
                (r"socket.*connect.*\d+\.\d+\.\d+\.\d+", ThreatSeverity.HIGH, 0.8, "IP connection"),
                (r"/dev/tcp/\d+\.\d+", ThreatSeverity.CRITICAL, 0.95, "Bash TCP device"),
                (r"while.*True.*socket.*recv", ThreatSeverity.HIGH, 0.85, "Command loop"),
                (r"requests.*while.*True", ThreatSeverity.HIGH, 0.8, "HTTP polling loop"),
            ]
        },
        AttackVector.SANDBOX_ESCAPE: {
            "patterns": [
                (r"__builtins__.*__import__", ThreatSeverity.CRITICAL, 0.9, "Builtins manipulation"),
                (r"object\.__subclasses__\(\)", ThreatSeverity.CRITICAL, 0.9, "Object traversal"),
                (r"func_globals.*__builtins__", ThreatSeverity.CRITICAL, 0.9, "Globals access"),
                (r"ctypes.*CDLL", ThreatSeverity.HIGH, 0.85, "Direct library loading"),
                (r"LD_PRELOAD", ThreatSeverity.HIGH, 0.85, "Library preloading"),
                (r"ptrace.*PTRACE_ATTACH", ThreatSeverity.CRITICAL, 0.9, "Process attachment"),
            ]
        },
        AttackVector.TIME_BOMB: {
            "patterns": [
                (r"if.*datetime.*>.*datetime\(2\d{3}", ThreatSeverity.HIGH, 0.8, "Date-based trigger"),
                (r"time\.sleep\s*\(\s*\d{4,}", ThreatSeverity.MEDIUM, 0.7, "Long sleep"),
                (r"schedule\.every.*do\(", ThreatSeverity.MEDIUM, 0.7, "Scheduled execution"),
                (r"if.*random.*<.*0\.\d\d\d.*:.*exec", ThreatSeverity.HIGH, 0.85, "Random trigger"),
                (r"if.*count.*>.*\d+.*:.*dangerous", ThreatSeverity.HIGH, 0.8, "Counter-based trigger"),
            ]
        },
        AttackVector.RESOURCE_EXHAUSTION: {
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


