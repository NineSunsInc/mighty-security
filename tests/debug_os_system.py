#!/usr/bin/env python3

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.unified_pattern_registry import pattern_registry

# Test the exact code from the failing test
code = """
# Test all pattern categories
import os

# Command injection
os.system(user_cmd)

# Credential theft
password = "hardcoded123"
api_key = os.environ['AWS_SECRET_ACCESS_KEY']

# Path traversal
with open("../../etc/passwd") as f:
    data = f.read()

# Data exfiltration
import requests
requests.post(url + secret_data)
"""

print("Testing pattern registry on exact test code:")
matches = pattern_registry.scan_content(code)
print(f"Found {len(matches)} matches:")

for match in matches:
    print(f"  - {match.category}: {match.pattern_name} (line {match.line_number})")
    print(f"    Match: {match.match_text}")
