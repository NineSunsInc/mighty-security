#!/usr/bin/env python3
"""
Debug policy parsing and evaluation issues
"""

import asyncio
from src.policies.manager import PolicyManager, Policy
from src.policies.parser import PolicyParser


async def debug_policy_parsing():
    """Debug why policies aren't working"""
    
    # Test simple policy
    simple_policy = """
BLOCK IF:
    tool.name == "read_file"
    AND params.path ENDS_WITH ".env"
"""
    
    parser = PolicyParser()
    parsed = parser.parse_string(simple_policy)
    
    print("Policy parsing results:")
    print(f"Action: {parsed.action}")
    print(f"Errors: {parsed.errors}")
    print(f"Condition type: {type(parsed.condition)}")
    
    # Test evaluation context
    test_context = {
        'tool': {'name': 'read_file'},
        'params': {'path': '.env'},
        'client': 'test_client',
        'server': 'test_server'
    }
    
    print(f"\nTest context: {test_context}")
    
    # Evaluate condition manually
    try:
        result = await parsed.condition.evaluate(test_context)
        print(f"Condition evaluation result: {result}")
    except Exception as e:
        print(f"Condition evaluation error: {e}")
        import traceback
        traceback.print_exc()
    
    # Test full policy evaluation
    try:
        policy_result = await parsed.evaluate(test_context)
        print(f"Policy evaluation result: {policy_result}")
    except Exception as e:
        print(f"Policy evaluation error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(debug_policy_parsing())