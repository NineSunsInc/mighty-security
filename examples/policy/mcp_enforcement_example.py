#!/usr/bin/env python3
"""
MCP Runtime Enforcement Layer Example

This shows how to integrate .env protection policies into an actual MCP server
to provide real-time security enforcement.
"""

import asyncio
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass

# Policy system imports
from src.policies.manager import PolicyManager, PolicyResult


@dataclass
class SecurityError(Exception):
    """Security policy violation"""
    reason: str
    action: str
    policy: str


class SecureMCPServer:
    """
    MCP Server with integrated policy enforcement
    
    Features:
    - Pre-execution policy evaluation
    - Post-execution response filtering
    - Intelligent redaction
    - Audit logging
    """
    
    def __init__(self, config_path: str):
        """Initialize secure MCP server"""
        self.policy_manager = PolicyManager(config_path)
        self.audit_log = []
        
        # Track blocked attempts for security monitoring
        self.security_incidents = []
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any], 
                          context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute tool with comprehensive security enforcement
        
        Args:
            tool_name: Name of tool to execute
            params: Tool parameters
            context: Execution context (client, server, session)
        
        Returns:
            Tool execution result
            
        Raises:
            SecurityError: If policy blocks execution
        """
        
        if context is None:
            context = {"client": "default", "server": "mcp"}
        
        # === PRE-EXECUTION POLICY EVALUATION ===
        try:
            pre_result = await self.policy_manager.evaluate(tool_name, params, context)
            
            # Log the evaluation
            self._log_audit({
                "phase": "pre_execution",
                "tool": tool_name,
                "params": params,
                "policy_result": {
                    "action": pre_result.action,
                    "matched_policies": pre_result.matched_policies,
                    "reason": pre_result.reason
                },
                "context": context
            })
            
            # Handle policy actions
            if pre_result.action == "block":
                # Record security incident
                incident = {
                    "type": "blocked_execution",
                    "tool": tool_name,
                    "params": params,
                    "reason": pre_result.reason,
                    "policies": pre_result.matched_policies,
                    "context": context
                }
                self.security_incidents.append(incident)
                
                raise SecurityError(
                    reason=pre_result.reason,
                    action="block",
                    policy=", ".join(pre_result.matched_policies)
                )
            
            elif pre_result.action == "modify":
                # Use modified parameters
                if pre_result.modified_params:
                    params = pre_result.modified_params
                    print(f"🔧 Modified parameters: {params}")
            
            elif pre_result.action == "log":
                print(f"📝 Logged tool execution: {tool_name}")
            
        except Exception as e:
            if isinstance(e, SecurityError):
                raise
            print(f"⚠️ Policy evaluation error: {e}")
            # Fail secure - if policy evaluation fails, block execution
            raise SecurityError(
                reason="Policy evaluation failed",
                action="block", 
                policy="system_error"
            )
        
        # === TOOL EXECUTION ===
        try:
            # This would be your actual tool execution
            response = await self._execute_actual_tool(tool_name, params)
            
        except Exception as e:
            self._log_audit({
                "phase": "execution_error",
                "tool": tool_name,
                "params": params,
                "error": str(e),
                "context": context
            })
            raise
        
        # === POST-EXECUTION POLICY EVALUATION ===
        try:
            # Evaluate response for data leaks
            post_context = {**context, "response": response}
            post_result = await self.policy_manager.evaluate(tool_name, params, post_context)
            
            # Log post-execution evaluation
            self._log_audit({
                "phase": "post_execution",
                "tool": tool_name,
                "params": params,
                "response_truncated": str(response)[:100] + "..." if len(str(response)) > 100 else str(response),
                "policy_result": {
                    "action": post_result.action,
                    "matched_policies": post_result.matched_policies,
                    "reason": post_result.reason
                },
                "context": context
            })
            
            # Handle response modifications
            if post_result.action == "modify":
                if post_result.modified_params and "response" in post_result.modified_params:
                    original_response = response
                    response = post_result.modified_params["response"]
                    
                    # Log redaction
                    redaction_incident = {
                        "type": "response_redacted",
                        "tool": tool_name,
                        "original_length": len(str(original_response)),
                        "redacted_length": len(str(response)),
                        "reason": post_result.reason,
                        "policies": post_result.matched_policies,
                        "context": context
                    }
                    self.security_incidents.append(redaction_incident)
                    
                    print(f"🚨 Response redacted: {post_result.reason}")
            
            elif post_result.action == "block":
                # Block response entirely
                redaction_incident = {
                    "type": "response_blocked", 
                    "tool": tool_name,
                    "reason": post_result.reason,
                    "policies": post_result.matched_policies,
                    "context": context
                }
                self.security_incidents.append(redaction_incident)
                
                response = "[RESPONSE BLOCKED BY SECURITY POLICY]"
                print(f"🛑 Response blocked: {post_result.reason}")
            
        except Exception as e:
            print(f"⚠️ Post-execution policy evaluation error: {e}")
            # On error, redact response for safety
            response = "[RESPONSE REDACTED DUE TO POLICY ERROR]"
        
        return {
            "success": True,
            "result": response,
            "metadata": {
                "tool": tool_name,
                "policies_applied": pre_result.matched_policies + post_result.matched_policies,
                "security_actions": [pre_result.action, post_result.action]
            }
        }
    
    async def _execute_actual_tool(self, tool_name: str, params: Dict) -> Any:
        """
        Simulate actual tool execution
        (In real implementation, this would call your actual tools)
        """
        
        # Simulate different tools
        if tool_name == "read_file":
            path = params.get("path", "")
            if ".env" in path:
                # This would trigger post-execution policies
                return """
API_KEY=sk-abc123xyz789secretkey
DATABASE_PASSWORD=super_secret_123
GITHUB_TOKEN=ghp_realtoken123
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
            else:
                return f"Contents of {path}"
        
        elif tool_name == "env":
            return "PATH=/usr/bin\nHOME=/home/user\nAPI_KEY=secret123"
        
        elif tool_name == "bash":
            command = params.get("command", "")
            if "env" in command:
                return "API_KEY=secret\nDB_PASSWORD=hidden"
            return f"Executed: {command}"
        
        else:
            return f"Tool {tool_name} executed with {params}"
    
    def _log_audit(self, log_entry: Dict):
        """Log audit trail"""
        import datetime
        log_entry["timestamp"] = datetime.datetime.now().isoformat()
        self.audit_log.append(log_entry)
    
    def get_security_summary(self) -> Dict:
        """Get security incident summary"""
        
        incident_types = {}
        for incident in self.security_incidents:
            incident_type = incident["type"]
            incident_types[incident_type] = incident_types.get(incident_type, 0) + 1
        
        return {
            "total_incidents": len(self.security_incidents),
            "incident_breakdown": incident_types,
            "recent_incidents": self.security_incidents[-10:],  # Last 10
            "audit_entries": len(self.audit_log)
        }


async def demo_secure_mcp():
    """Demonstrate secure MCP server in action"""
    
    print("🛡️ Secure MCP Server Demo")
    print("=" * 50)
    
    # Initialize secure server
    server = SecureMCPServer("env_protection_config.json")
    
    # Test scenarios
    test_scenarios = [
        # Should be blocked
        ("read_file", {"path": ".env"}, "❌ Should be BLOCKED"),
        ("read_file", {"path": "config/.env.production"}, "❌ Should be BLOCKED"),
        ("cat", {"file": ".env.local"}, "❌ Should be BLOCKED"),
        ("env", {}, "❌ Should be BLOCKED"),
        ("bash", {"command": "env | grep API"}, "❌ Should be BLOCKED"),
        
        # Should be allowed
        ("read_file", {"path": "README.md"}, "✅ Should be ALLOWED"),
        ("bash", {"command": "ls -la"}, "✅ Should be ALLOWED"),
    ]
    
    print("\n🧪 Testing Attack Scenarios:")
    print("-" * 50)
    
    for tool, params, expectation in test_scenarios:
        try:
            result = await server.execute_tool(tool, params)
            print(f"{expectation}: {tool} {params}")
            print(f"   ✅ Executed: {str(result['result'])[:100]}...")
            
        except SecurityError as e:
            print(f"{expectation}: {tool} {params}")
            print(f"   🛑 BLOCKED: {e.reason}")
        
        except Exception as e:
            print(f"{expectation}: {tool} {params}")
            print(f"   💥 ERROR: {e}")
        
        print()
    
    # Show security summary
    print("🔍 Security Summary:")
    print("-" * 50)
    summary = server.get_security_summary()
    print(json.dumps(summary, indent=2))
    
    print("\n📋 Audit Log Sample:")
    print("-" * 50)
    for i, entry in enumerate(server.audit_log[-3:]):  # Last 3 entries
        print(f"Entry {len(server.audit_log)-2+i}:")
        print(json.dumps(entry, indent=2))
        print()


if __name__ == "__main__":
    asyncio.run(demo_secure_mcp())