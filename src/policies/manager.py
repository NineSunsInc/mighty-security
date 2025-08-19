"""
Mighty MCP Security - Policy Manager.

Advanced policy management for runtime security:
- Hierarchical policy system (global → client → server → tool)
- Dynamic policy loading and updates
- Intelligent conflict resolution
- Deep analyzer integration
"""

import json

# Optional yaml support
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .parser import ParsedPolicy, PolicyAction, PolicyParser
from .templates import GuardrailTemplate


@dataclass
class Policy:
    """Security policy definition"""
    id: str
    name: str
    description: str
    content: str
    enabled: bool = True
    priority: int = 0
    scope: dict = None
    created_at: str = None
    updated_at: str = None

    def __post_init__(self):
        if self.scope is None:
            self.scope = {}
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.updated_at is None:
            self.updated_at = datetime.now().isoformat()


@dataclass
class PolicyResult:
    """Policy evaluation result"""
    action: str  # allow, block, modify, log
    matched_policies: list[str]
    reason: str | None = None
    modifications: dict | None = None
    modified_params: dict | None = None


class PolicyManager:
    """
    Manages security policies with hierarchical evaluation.
    
    Features:
    - Global, client, server, and tool-level policies
    - Template-based policy generation
    - Conflict resolution
    - Dynamic policy updates
    """

    def __init__(self, config_path: str | None = None):
        """
        Initialize policy manager.
        
        Args:
            config_path: Path to policy configuration file
        """
        self.parser = PolicyParser()
        self.templates = GuardrailTemplate()

        # Policy storage (hierarchical)
        self.global_policies: list[Policy] = []
        self.client_policies: dict[str, list[Policy]] = {}
        self.server_policies: dict[str, list[Policy]] = {}
        self.tool_policies: dict[str, list[Policy]] = {}

        # Parsed policy cache
        self._parsed_cache: dict[str, ParsedPolicy] = {}

        # Load configuration
        if config_path:
            self.load_config(config_path)
        else:
            self._load_default_policies()

    def load_config(self, config_path: str):
        """Load policies from configuration file"""

        path = Path(config_path)

        if (path.suffix == '.yaml' or path.suffix == '.yml') and HAS_YAML:
            with open(path) as f:
                config = yaml.safe_load(f)
        else:
            with open(path) as f:
                config = json.load(f)

        # Load global policies
        if 'global' in config:
            for policy_config in config['global'].get('policies', []):
                policy = self._create_policy_from_config(policy_config)
                self.global_policies.append(policy)

        # Load client-specific policies
        if 'clients' in config:
            for client_name, client_config in config['clients'].items():
                self.client_policies[client_name] = []

                # Client-level policies
                for policy_config in client_config.get('policies', []):
                    policy = self._create_policy_from_config(policy_config)
                    self.client_policies[client_name].append(policy)

                # Server-specific policies
                for server_name, server_config in client_config.get('servers', {}).items():
                    server_key = f"{client_name}:{server_name}"
                    self.server_policies[server_key] = []

                    for policy_config in server_config.get('policies', []):
                        policy = self._create_policy_from_config(policy_config)
                        self.server_policies[server_key].append(policy)

                    # Tool-specific policies
                    for tool_name, tool_config in server_config.get('tools', {}).items():
                        tool_key = f"{server_key}:{tool_name}"
                        self.tool_policies[tool_key] = []

                        for policy_config in tool_config.get('policies', []):
                            policy = self._create_policy_from_config(policy_config)
                            self.tool_policies[tool_key].append(policy)

    def _load_default_policies(self):
        """Load default security policies"""

        # Default global policies
        default_policies = [
            {
                'name': 'block_secrets',
                'template': 'secrets',
                'variables': {'WHITELIST': []}
            },
            {
                'name': 'log_pii',
                'template': 'pii',
                'variables': {'ACTION': 'LOG', 'TRUSTED_SERVERS': []}
            },
            {
                'name': 'block_injection',
                'template': 'command_injection',
                'variables': {}
            },
            {
                'name': 'block_traversal',
                'template': 'path_traversal',
                'variables': {}
            }
        ]

        for policy_config in default_policies:
            policy = self._create_policy_from_config(policy_config)
            self.global_policies.append(policy)

    def _create_policy_from_config(self, config: dict) -> Policy:
        """Create policy from configuration"""

        # Check if it's a template-based policy
        if 'template' in config:
            content = self.templates.render(
                config['template'],
                config.get('variables', {})
            )

            return Policy(
                id=config.get('id', config['name']),
                name=config['name'],
                description=config.get('description', f"Policy from template {config['template']}"),
                content=content,
                enabled=config.get('enabled', True),
                priority=config.get('priority', 0),
                scope=config.get('scope', {})
            )

        # Direct policy content
        return Policy(
            id=config.get('id', config['name']),
            name=config['name'],
            description=config.get('description', ''),
            content=config['content'],
            enabled=config.get('enabled', True),
            priority=config.get('priority', 0),
            scope=config.get('scope', {})
        )

    async def evaluate(self, tool: str, params: dict, context: dict) -> PolicyResult:
        """
        Evaluate all applicable policies.
        
        Args:
            tool: Tool name
            params: Tool parameters
            context: Evaluation context (client, server, session, etc.)
        
        Returns:
            PolicyResult with action to take
        """

        # Build evaluation context
        eval_context = {
            'tool': {'name': tool},
            'params': params,
            **context
        }

        # Collect applicable policies (in priority order)
        policies = self._get_applicable_policies(tool, context)

        # Sort by priority (higher priority first)
        policies.sort(key=lambda p: p.priority, reverse=True)

        # Evaluate policies
        matched_policies = []
        final_action = PolicyAction.ALLOW
        final_modifications = {}
        reasons = []

        for policy in policies:
            if not policy.enabled:
                continue

            # Get or parse policy
            parsed = await self._get_parsed_policy(policy)

            if not parsed:
                continue

            # Evaluate
            result = await parsed.evaluate(eval_context)

            if result.matched:
                matched_policies.append(policy.name)
                reasons.append(f"{policy.name}: {result.reason}")

                # Determine action precedence
                if result.action == PolicyAction.BLOCK:
                    # BLOCK takes highest precedence
                    final_action = PolicyAction.BLOCK
                    break  # No need to evaluate further

                elif result.action == PolicyAction.MODIFY:
                    # MODIFY applies unless blocked
                    if final_action != PolicyAction.BLOCK:
                        final_action = PolicyAction.MODIFY
                        final_modifications.update(result.modifications or {})

                elif result.action == PolicyAction.LOG:
                    # LOG only if not blocked or modified
                    if final_action == PolicyAction.ALLOW:
                        final_action = PolicyAction.LOG

        # Apply modifications to params if needed
        modified_params = None
        if final_action == PolicyAction.MODIFY and final_modifications:
            modified_params = self._apply_modifications(params, final_modifications)

        return PolicyResult(
            action=final_action.value,
            matched_policies=matched_policies,
            reason='; '.join(reasons) if reasons else None,
            modifications=final_modifications if final_modifications else None,
            modified_params=modified_params
        )

    def _get_applicable_policies(self, tool: str, context: dict) -> list[Policy]:
        """Get all policies applicable to current context"""

        policies = []

        # Add global policies
        policies.extend(self.global_policies)

        # Add client-specific policies
        client = context.get('client')
        if client and client in self.client_policies:
            policies.extend(self.client_policies[client])

        # Add server-specific policies
        server = context.get('server')
        if client and server:
            server_key = f"{client}:{server}"
            if server_key in self.server_policies:
                policies.extend(self.server_policies[server_key])

        # Add tool-specific policies
        if client and server and tool:
            tool_key = f"{client}:{server}:{tool}"
            if tool_key in self.tool_policies:
                policies.extend(self.tool_policies[tool_key])

        return policies

    async def _get_parsed_policy(self, policy: Policy) -> ParsedPolicy | None:
        """Get parsed policy (with caching)"""

        if policy.id not in self._parsed_cache:
            try:
                parsed = self.parser.parse_string(policy.content)
                self._parsed_cache[policy.id] = parsed
            except Exception as e:
                print(f"Failed to parse policy {policy.name}: {e}")
                return None

        return self._parsed_cache[policy.id]

    def _apply_modifications(self, params: dict, modifications: dict) -> dict:
        """Apply modifications to parameters"""

        modified = params.copy()

        for field_path, new_value in modifications.items():
            # Handle nested fields
            parts = field_path.split('.')
            target = modified

            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]

            target[parts[-1]] = new_value

        return modified

    async def create_policy(self, policy_data: dict) -> Policy:
        """Create new policy"""

        policy = Policy(
            id=policy_data.get('id', policy_data['name']),
            name=policy_data['name'],
            description=policy_data.get('description', ''),
            content=policy_data['content'],
            enabled=policy_data.get('enabled', True),
            priority=policy_data.get('priority', 0),
            scope=policy_data.get('scope', {})
        )

        # Add to appropriate level
        scope = policy.scope
        if 'tool' in scope:
            key = f"{scope['client']}:{scope['server']}:{scope['tool']}"
            if key not in self.tool_policies:
                self.tool_policies[key] = []
            self.tool_policies[key].append(policy)

        elif 'server' in scope:
            key = f"{scope['client']}:{scope['server']}"
            if key not in self.server_policies:
                self.server_policies[key] = []
            self.server_policies[key].append(policy)

        elif 'client' in scope:
            if scope['client'] not in self.client_policies:
                self.client_policies[scope['client']] = []
            self.client_policies[scope['client']].append(policy)

        else:
            self.global_policies.append(policy)

        return policy

    async def delete_policy(self, policy_id: str) -> bool:
        """Delete policy by ID"""

        # Search and remove from all levels
        for policies in [self.global_policies]:
            for i, policy in enumerate(policies):
                if policy.id == policy_id:
                    del policies[i]
                    if policy_id in self._parsed_cache:
                        del self._parsed_cache[policy_id]
                    return True

        for policies_list in self.client_policies.values():
            for i, policy in enumerate(policies_list):
                if policy.id == policy_id:
                    del policies_list[i]
                    if policy_id in self._parsed_cache:
                        del self._parsed_cache[policy_id]
                    return True

        return False

    async def get_all_policies(self) -> dict:
        """Get all policies organized by level"""

        return {
            'global': [asdict(p) for p in self.global_policies],
            'clients': {
                client: [asdict(p) for p in policies]
                for client, policies in self.client_policies.items()
            },
            'servers': {
                server: [asdict(p) for p in policies]
                for server, policies in self.server_policies.items()
            },
            'tools': {
                tool: [asdict(p) for p in policies]
                for tool, policies in self.tool_policies.items()
            }
        }

    def export_config(self, filepath: str):
        """Export current configuration to file"""

        config = {
            'global': {
                'policies': [asdict(p) for p in self.global_policies]
            },
            'clients': {}
        }

        # Organize by client/server hierarchy
        for client, policies in self.client_policies.items():
            config['clients'][client] = {
                'policies': [asdict(p) for p in policies],
                'servers': {}
            }

        path = Path(filepath)

        if (path.suffix == '.yaml' or path.suffix == '.yml') and HAS_YAML:
            with open(path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        else:
            with open(path, 'w') as f:
                json.dump(config, f, indent=2)
