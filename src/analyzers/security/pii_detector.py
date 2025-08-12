"""
Simple PII detection for policy evaluation.
"""

import re
from typing import List, Dict

# PII patterns
PII_PATTERNS = [
    # Email addresses
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
    
    # Phone numbers (US format)
    (r'\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b', 'phone_us'),
    
    # Social Security Numbers
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
    
    # Credit card numbers (basic)
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit_card'),
    
    # IP addresses
    (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'ip_address'),
    
    # Names (very basic - looks for patterns like "Mr. John Doe")
    (r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b', 'name'),
    
    # Dates of birth (various formats)
    (r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', 'date'),
    
    # Passport numbers (basic pattern)
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'passport'),
]


def detect_pii(content: str) -> List[Dict]:
    """
    Detect potential PII in content.
    
    Args:
        content: Text to analyze
        
    Returns:
        List of detected PII with type and location
    """
    pii_items = []
    
    for pattern, pii_type in PII_PATTERNS:
        matches = re.finditer(pattern, content)
        for match in matches:
            # Redact the actual value for safety
            redacted = match.group(0)
            if len(redacted) > 4:
                redacted = redacted[:2] + '*' * (len(redacted) - 4) + redacted[-2:]
            
            pii_items.append({
                'type': pii_type,
                'redacted': redacted,
                'position': match.start()
            })
    
    return pii_items