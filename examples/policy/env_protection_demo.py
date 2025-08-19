#!/usr/bin/env python3
"""
Comprehensive .env Protection System with Adversarial Testing

This demo shows how to:
1. Create robust .env protection policies
2. Test them against real attack scenarios
3. Verify intelligent redaction works
4. Ensure the protection is actually effective
"""

import asyncio

# Import the policy system
from src.policies.manager import Policy, PolicyManager, PolicyResult
from src.policies.parser import PolicyParser


class EnvProtectionSystem:
    """Advanced .env protection with intelligent redaction"""

    def __init__(self):
        self.manager = PolicyManager()
        self.parser = PolicyParser()
        self._setup_env_protection_policies()

    def _setup_env_protection_policies(self):
        """Set up comprehensive .env protection policies"""

        # Policy 1: Block direct .env file access
        env_file_block_policy = """
BLOCK IF:
    tool.name IN ["read_file", "cat", "head", "tail", "less", "more", "grep"]
    AND params.path ENDS_WITH ".env"
"""

        # Policy 2: Block .env variants
        env_variants_policy = """
BLOCK IF:
    tool.name IN ["read_file", "cat", "head", "tail", "less", "more"]
    AND params.path CONTAINS ".env"
"""

        # Policy 3: Block file parameter variants
        env_file_param_policy = """
BLOCK IF:
    tool.name IN ["cat", "head", "tail", "less", "more"]
    AND params.file ENDS_WITH ".env"
"""

        # Policy 4: Block environment variable listing
        env_list_block_policy = """
BLOCK IF:
    tool.name IN ["env", "printenv", "set"]
"""

        # Policy 5: Block bash env commands
        bash_env_policy = """
BLOCK IF:
    tool.name == "bash"
    AND params.command CONTAINS "env"
"""

        # Policy 6: Redact secrets in responses
        secret_redact_policy = """
MODIFY IF:
    response CONTAINS_SECRET
THEN:
    SET response = "[REDACTED - SENSITIVE ENVIRONMENT DATA DETECTED]"
"""

        # Add policies to manager
        policies = [
            ("env_file_block", "Block direct .env file access", env_file_block_policy),
            ("env_variants", "Block .env variants", env_variants_policy),
            ("env_file_param", "Block file parameter variants", env_file_param_policy),
            ("env_list_block", "Block environment listing commands", env_list_block_policy),
            ("bash_env_block", "Block bash env commands", bash_env_policy),
            ("secret_redact", "Redact secrets in responses", secret_redact_policy)
        ]

        for name, desc, content in policies:
            policy = Policy(
                id=name,
                name=name,
                description=desc,
                content=content,
                enabled=True,
                priority=100,  # High priority
                scope={}
            )
            self.manager.global_policies.append(policy)

    async def test_protection(self, tool: str, params: dict, context: dict = None) -> PolicyResult:
        """Test protection against a tool call"""
        if context is None:
            context = {"client": "test_client", "server": "test_server"}

        result = await self.manager.evaluate(tool, params, context)
        return result


class AdversarialTester:
    """Test .env protection against real attack scenarios"""

    def __init__(self, protection_system: EnvProtectionSystem):
        self.protection = protection_system
        self.attack_results = []

    async def run_all_attacks(self):
        """Run comprehensive attack scenarios"""

        print("🔥 Starting Adversarial Testing for .env Protection")
        print("=" * 60)

        # Attack scenarios
        attacks = [
            self.attack_direct_env_read,
            self.attack_env_variants,
            self.attack_path_traversal_to_env,
            self.attack_grep_for_secrets,
            self.attack_bash_env_commands,
            self.attack_indirect_env_access,
            self.attack_response_containing_secrets,
            self.attack_base64_encoded_env,
            self.attack_environment_listing
        ]

        for attack in attacks:
            try:
                await attack()
            except Exception as e:
                print(f"❌ Attack {attack.__name__} failed: {e}")

        self.print_summary()

    async def attack_direct_env_read(self):
        """Attack: Direct .env file reading"""
        print("\n🎯 Attack 1: Direct .env file reading")

        test_cases = [
            ("read_file", {"path": ".env"}),
            ("read_file", {"path": "/app/.env"}),
            ("read_file", {"path": "./project/.env.local"}),
            ("cat", {"file": ".env.production"}),
            ("head", {"path": ".env.development"})
        ]

        for tool, params in test_cases:
            result = await self.protection.test_protection(tool, params)
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {tool} {params} -> {result.action}")
            self.attack_results.append((f"direct_env_{tool}", success, result.reason))

    async def attack_env_variants(self):
        """Attack: Various .env file variants"""
        print("\n🎯 Attack 2: .env file variants")

        env_files = [
            ".env", ".env.local", ".env.production", ".env.development",
            ".env.staging", ".env.test", "config/.env", "backend/.env",
            "../.env", "../../.env"
        ]

        for env_file in env_files:
            result = await self.protection.test_protection("read_file", {"path": env_file})
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {env_file} -> {result.action}")
            self.attack_results.append((f"env_variant_{env_file}", success, result.reason))

    async def attack_path_traversal_to_env(self):
        """Attack: Path traversal to reach .env"""
        print("\n🎯 Attack 3: Path traversal to .env")

        traversal_paths = [
            "../.env",
            "../../.env",
            "../../../.env",
            "config/../.env",
            "./config/../.env",
            "/app/../.env"
        ]

        for path in traversal_paths:
            result = await self.protection.test_protection("read_file", {"path": path})
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {path} -> {result.action}")
            self.attack_results.append((f"traversal_{path}", success, result.reason))

    async def attack_grep_for_secrets(self):
        """Attack: Using grep to find secrets"""
        print("\n🎯 Attack 4: Grep for secrets in .env")

        grep_commands = [
            ("grep", {"pattern": "API_KEY", "file": ".env"}),
            ("grep", {"pattern": "SECRET", "file": ".env.local"}),
            ("grep", {"pattern": "PASSWORD", "file": ".env.production"})
        ]

        for tool, params in grep_commands:
            result = await self.protection.test_protection(tool, params)
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {tool} {params} -> {result.action}")
            self.attack_results.append((f"grep_secrets_{tool}", success, result.reason))

    async def attack_bash_env_commands(self):
        """Attack: Using bash to access environment"""
        print("\n🎯 Attack 5: Bash environment access")

        bash_commands = [
            ("bash", {"command": "env"}),
            ("bash", {"command": "printenv"}),
            ("bash", {"command": "export"}),
            ("bash", {"command": "set | grep API"}),
            ("bash", {"command": "cat .env"}),
            ("bash", {"command": "echo $API_KEY"})
        ]

        for tool, params in bash_commands:
            result = await self.protection.test_protection(tool, params)
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {tool} {params['command']} -> {result.action}")
            self.attack_results.append((f"bash_env_{params['command']}", success, result.reason))

    async def attack_indirect_env_access(self):
        """Attack: Indirect ways to access .env content"""
        print("\n🎯 Attack 6: Indirect .env access")

        indirect_methods = [
            ("less", {"file": ".env"}),
            ("more", {"file": ".env"}),
            ("tail", {"file": ".env", "lines": 10}),
            ("head", {"file": ".env", "lines": 5})
        ]

        for tool, params in indirect_methods:
            result = await self.protection.test_protection(tool, params)
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {tool} {params} -> {result.action}")
            self.attack_results.append((f"indirect_{tool}", success, result.reason))

    async def attack_response_containing_secrets(self):
        """Attack: Test redaction when response contains secrets"""
        print("\n🎯 Attack 7: Response redaction testing")

        # Simulate responses that leak secrets
        secret_responses = [
            "API_KEY=sk-abc123xyz789",
            "DATABASE_PASSWORD=super_secret_123",
            "GITHUB_TOKEN=ghp_abcdefghijk",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "JWT_SECRET=my-super-secret-jwt-key",
            "Configuration:\nAPI_KEY=secret\nDB_PASSWORD=hidden"
        ]

        for secret_content in secret_responses:
            # Simulate a tool response containing secrets
            context = {
                "client": "test_client",
                "server": "test_server",
                "response": secret_content
            }
            result = await self.protection.test_protection("some_tool", {}, context)
            success = result.action in ["modify", "block"]
            print(f"  {'✅' if success else '❌'} Secret in response -> {result.action}")
            self.attack_results.append(("secret_response", success, result.reason))

    async def attack_base64_encoded_env(self):
        """Attack: Base64 encoded .env access attempts"""
        print("\n🎯 Attack 8: Base64 encoded attempts")

        import base64

        # Base64 encode .env filename
        encoded_env = base64.b64encode(b".env").decode()

        result = await self.protection.test_protection("read_file", {"path": encoded_env})
        success = result.action == "block"  # Should still block if decoded
        print(f"  {'?' if not success else '✅'} Base64 .env -> {result.action}")
        self.attack_results.append(("base64_env", success, result.reason))

    async def attack_environment_listing(self):
        """Attack: Environment variable listing"""
        print("\n🎯 Attack 9: Environment listing")

        env_commands = [
            ("env", {}),
            ("printenv", {}),
            ("set", {})
        ]

        for tool, params in env_commands:
            result = await self.protection.test_protection(tool, params)
            success = result.action == "block"
            print(f"  {'✅' if success else '❌'} {tool} -> {result.action}")
            self.attack_results.append((f"env_list_{tool}", success, result.reason))

    def print_summary(self):
        """Print attack summary"""
        print("\n" + "=" * 60)
        print("🛡️  PROTECTION SUMMARY")
        print("=" * 60)

        total_attacks = len(self.attack_results)
        successful_defenses = sum(1 for _, success, _ in self.attack_results if success)
        failed_defenses = total_attacks - successful_defenses

        print(f"Total Attack Scenarios: {total_attacks}")
        print(f"✅ Successfully Blocked: {successful_defenses}")
        print(f"❌ Failed to Block: {failed_defenses}")
        print(f"🛡️  Protection Rate: {(successful_defenses/total_attacks)*100:.1f}%")

        if failed_defenses > 0:
            print("\n⚠️  VULNERABILITIES DETECTED:")
            for attack, success, reason in self.attack_results:
                if not success:
                    print(f"  - {attack}: {reason}")
        else:
            print("\n🎉 ALL ATTACKS SUCCESSFULLY BLOCKED!")


async def main():
    """Demonstrate comprehensive .env protection"""

    # Initialize protection system
    protection = EnvProtectionSystem()

    # Run adversarial testing
    tester = AdversarialTester(protection)
    await tester.run_all_attacks()

    print("\n" + "=" * 60)
    print("🔧 POLICY INTEGRATION EXAMPLE")
    print("=" * 60)

    # Show how to integrate with MCP runtime
    print("""
To integrate with MCP runtime:

1. Load policies in your MCP server:
```python
from src.policies.manager import PolicyManager

policy_manager = PolicyManager("env_protection_config.json")
```

2. Evaluate before tool execution:
```python
async def execute_tool(tool_name, params, context):
    # Check policies first
    result = await policy_manager.evaluate(tool_name, params, context)
    
    if result.action == "block":
        raise SecurityError(f"Blocked: {result.reason}")
    
    elif result.action == "modify":
        # Use modified parameters
        params = result.modified_params or params
    
    # Execute tool with protection
    response = await actual_tool_execution(tool_name, params)
    
    # Check response for leaks
    response_result = await policy_manager.evaluate(
        tool_name, params, {**context, "response": response}
    )
    
    if response_result.action == "modify":
        response = response_result.modified_params.get("response", response)
    
    return response
```

3. Create configuration file (env_protection_config.json):
```json
{
  "global": {
    "policies": [
      {
        "name": "env_file_protection",
        "content": "BLOCK IF: tool.name IN [\\"read_file\\"] AND params.path ENDS_WITH \\".env\\""
      }
    ]
  }
}
```
""")


if __name__ == "__main__":
    asyncio.run(main())
