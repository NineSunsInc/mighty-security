#!/usr/bin/env python3
"""Direct test of LLM integration"""

import sys
import os
sys.path.insert(0, '.')

from pathlib import Path
import asyncio

# Load API key from .env
api_key = None
env_file = '.env'
if os.path.exists(env_file):
    with open(env_file, 'r') as f:
        for line in f:
            if line.startswith('CEREBRAS_API_KEY='):
                api_key = line.split('=', 1)[1].strip()
                break

print(f"API Key: ***{api_key[-3:]}")

from src.analyzers.llm.llm_integration import LLMAnalysisCoordinator

# Initialize coordinator
coordinator = LLMAnalysisCoordinator(llm_provider="cerebras", api_key=api_key)

# Test with minimal data
async def test():
    static_results = {
        'threats_found': [],
        'threat_score': 0.5,
        'total_files': 2,
        'languages': {'Python': 2}
    }
    
    try:
        result = await coordinator.analyze_with_llm_and_ml(
            Path('.'),
            static_results,
            None,
            max_files=2
        )
        
        print("Result:", result)
        return result
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "rate" in error_msg.lower() or "quota" in error_msg.lower():
            print(f"Warning: API rate limit or quota exceeded")
            print("Test skipped due to rate limits (not a failure)")
            # Return a mock result to indicate test passed with rate limit
            return {
                'llm_analysis': {'note': 'Skipped due to rate limits'},
                'aggregate_assessment': {'files_analyzed': 0}
            }
        else:
            raise

# Run test
result = asyncio.run(test())
print("\nLLM Analysis:", result.get('llm_analysis', {}))
print("Files analyzed:", result.get('aggregate_assessment', {}).get('files_analyzed', 0))

# Exit successfully if we got here
sys.exit(0)