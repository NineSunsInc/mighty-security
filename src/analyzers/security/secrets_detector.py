"""
Simple secrets detection for policy evaluation.
"""

import re
from typing import List, Dict

# Common secret patterns
SECRET_PATTERNS = [
    # API Keys
    (r'[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', 'api_key'),
    (r'[sS][eE][cC][rR][eE][tT]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', 'secret'),
    
    # AWS
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'[aA][wW][sS].*[sS][eE][cC][rR][eE][tT].*[kK][eE][yY]\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'aws_secret'),
    
    # GitHub
    (r'ghp_[a-zA-Z0-9]{36}', 'github_personal_token'),
    (r'gho_[a-zA-Z0-9]{36}', 'github_oauth_token'),
    
    # Generic tokens
    (r'[tT][oO][kK][eE][nN]\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', 'token'),
    (r'[bB][eE][aA][rR][eE][rR]\s+([a-zA-Z0-9\-_.]{20,})', 'bearer_token'),
    
    # Private keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'private_key'),
    
    # Database URLs with passwords
    (r'(?:mongodb|postgres|mysql|redis)://[^:]+:([^@]+)@', 'db_password'),
]


def detect_secrets(content: str) -> List[Dict]:
    """
    Detect potential secrets in content.
    
    Args:
        content: Text to analyze
        
    Returns:
        List of detected secrets with type and location
    """
    secrets = []
    
    for pattern, secret_type in SECRET_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            secrets.append({
                'type': secret_type,
                'match': match.group(0)[:50],  # Truncate for safety
                'position': match.start()
            })
    
    return secrets