#!/usr/bin/env python3
"""Test Cerebras API connection"""

import os
from cerebras.cloud.sdk import Cerebras

# Load API key from .env file
api_key = None
env_file = '.env'
if os.path.exists(env_file):
    with open(env_file, 'r') as f:
        for line in f:
            if line.startswith('CEREBRAS_API_KEY='):
                api_key = line.split('=', 1)[1].strip()
                break

if not api_key:
    print("Error: CEREBRAS_API_KEY not found in .env file")
    exit(1)

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
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()