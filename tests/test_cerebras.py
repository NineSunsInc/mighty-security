#!/usr/bin/env python3
"""Test Cerebras API connection"""

import os
from cerebras.cloud.sdk import Cerebras

"""Test Cerebras connectivity, but gracefully skip when no key is present."""

# Load API key from environment or .env file
api_key = os.environ.get('CEREBRAS_API_KEY')
env_file = '.env'
if api_key is None and os.path.exists(env_file):
    with open(env_file, 'r') as f:
        for line in f:
            if line.startswith('CEREBRAS_API_KEY='):
                api_key = line.split('=', 1)[1].strip()
                break

if not api_key:
    print("CEREBRAS_API_KEY not set; skipping live API test (not a failure)")
    exit(0)

print(f"API Key found: {api_key[:10]}...")

try:
    # Initialize client
    client = Cerebras(api_key=api_key)
    
    # Test with a simple request
    print("Testing Cerebras API...")
    completion = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a security analyzer."},
            {"role": "user", "content": "Is the code 'exec(input())' dangerous? Answer in one sentence."}
        ],
        model="gpt-oss-120b",
        temperature=0.1,
        max_tokens=100
    )
    
    print("Response:", completion.choices[0].message.content)
    print("Success! Cerebras API is working.")
    
except Exception as e:
    error_msg = str(e)
    if "429" in error_msg or "rate" in error_msg.lower() or "quota" in error_msg.lower():
        print(f"Warning: API rate limit or quota exceeded - {e}")
        print("Test skipped due to rate limits (not a failure)")
        exit(0)  # Exit successfully - rate limit is not a test failure
    else:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)