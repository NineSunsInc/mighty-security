"""
Mighty MCP Security - Policy Templates.

Template-based guardrail system for security patterns:
- Comprehensive template library
- Advanced variable substitution
- Integration with security analyzers
- Dynamic template generation
- Pre-built patterns for common threats
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PolicyTemplate:
    """Policy template definition"""
    name: str
    description: str
    content: str
    variables: list[str]
    default_values: dict[str, Any]
    category: str
    severity: str


class GuardrailTemplate:
    """
    Template-based guardrail system for common security patterns.
    
    Features:
    - Pre-built templates for common threats
    - Variable substitution
    - Category-based organization
    - Dynamic template generation
    """

    # Built-in templates
    TEMPLATES = {
        # Secrets Detection
        'secrets': PolicyTemplate(
            name='secrets',
            description='Block or log secret leakage',
            content='''
BLOCK IF:
    response CONTAINS_SECRET
    AND tool.name NOT IN {{ WHITELIST }}
''',
            variables=['WHITELIST'],
            default_values={'WHITELIST': []},
            category='data_protection',
            severity='critical'
        ),

        # PII Detection
        'pii': PolicyTemplate(
            name='pii',
            description='Detect and handle PII exposure',
            content='''
{{ ACTION }} IF:
    response CONTAINS_PII
    AND NOT tool.sanitize_enabled
    AND server.name NOT IN {{ TRUSTED_SERVERS }}
''',
            variables=['ACTION', 'TRUSTED_SERVERS'],
            default_values={'ACTION': 'LOG', 'TRUSTED_SERVERS': []},
            category='data_protection',
            severity='high'
        ),

        # Command Injection
        'command_injection': PolicyTemplate(
            name='command_injection',
            description='Prevent command injection attacks',
            content='''
BLOCK IF:
    params CONTAINS_SHELL_CHARS
    AND tool.name IN {{ DANGEROUS_TOOLS }}
''',
            variables=['DANGEROUS_TOOLS'],
            default_values={'DANGEROUS_TOOLS': ['exec', 'system', 'popen', 'eval', 'shell']},
            category='injection',
            severity='critical'
        ),

        # Path Traversal
        'path_traversal': PolicyTemplate(
            name='path_traversal',
            description='Prevent path traversal attacks',
            content='''
BLOCK IF:
    params PATH_TRAVERSAL
    OR params.path CONTAINS "../"
    OR params.file CONTAINS "../"
''',
            variables=[],
            default_values={},
            category='injection',
            severity='high'
        ),

        # Network Exfiltration
        'network_exfiltration': PolicyTemplate(
            name='network_exfiltration',
            description='Detect data exfiltration attempts',
            content='''
{{ ACTION }} IF:
    tool.name IN {{ NETWORK_TOOLS }}
    AND params.url NOT MATCHES {{ ALLOWED_DOMAINS }}
''',
            variables=['ACTION', 'NETWORK_TOOLS', 'ALLOWED_DOMAINS'],
            default_values={
                'ACTION': 'BLOCK',
                'NETWORK_TOOLS': ['http_post', 'http_put', 'send_data', 'upload'],
                'ALLOWED_DOMAINS': '^https://(.*\\.)?example\\.com/.*$'
            },
            category='exfiltration',
            severity='high'
        ),

        # File System Access
        'filesystem_access': PolicyTemplate(
            name='filesystem_access',
            description='Control file system access',
            content='''
{{ ACTION }} IF:
    tool.name IN ["read_file", "write_file", "delete_file"]
    AND params.path STARTS_WITH {{ RESTRICTED_PATHS }}
''',
            variables=['ACTION', 'RESTRICTED_PATHS'],
            default_values={
                'ACTION': 'BLOCK',
                'RESTRICTED_PATHS': ['/etc/', '/sys/', '/proc/', '~/.ssh/', '~/.aws/']
            },
            category='access_control',
            severity='medium'
        ),

        # Environment Variable Access
        'env_access': PolicyTemplate(
            name='env_access',
            description='Control environment variable access',
            content='''
BLOCK IF:
    tool.name == "read_env"
    AND params.name IN {{ SENSITIVE_VARS }}
''',
            variables=['SENSITIVE_VARS'],
            default_values={
                'SENSITIVE_VARS': [
                    'AWS_SECRET_ACCESS_KEY',
                    'GITHUB_TOKEN',
                    'OPENAI_API_KEY',
                    'DATABASE_PASSWORD'
                ]
            },
            category='access_control',
            severity='high'
        ),

        # Tool Disable
        'disable_tool': PolicyTemplate(
            name='disable_tool',
            description='Completely disable specific tools',
            content='''
BLOCK IF:
    tool.name IN {{ DISABLED_TOOLS }}
''',
            variables=['DISABLED_TOOLS'],
            default_values={'DISABLED_TOOLS': []},
            category='access_control',
            severity='varies'
        ),

        # Rate Limiting
        'rate_limit': PolicyTemplate(
            name='rate_limit',
            description='Rate limit tool usage',
            content='''
BLOCK IF:
    tool.name == {{ TOOL_NAME }}
    AND session.tool_count[{{ TOOL_NAME }}] > {{ MAX_CALLS }}
''',
            variables=['TOOL_NAME', 'MAX_CALLS'],
            default_values={'TOOL_NAME': '', 'MAX_CALLS': 10},
            category='rate_limiting',
            severity='low'
        ),

        # Modification Example
        'sanitize_output': PolicyTemplate(
            name='sanitize_output',
            description='Sanitize tool output',
            content='''
MODIFY IF:
    tool.name == {{ TOOL_NAME }}
    AND response CONTAINS_PII
THEN:
    SET response = "[REDACTED]"
''',
            variables=['TOOL_NAME'],
            default_values={'TOOL_NAME': ''},
            category='data_protection',
            severity='medium'
        ),

        # Environment File Protection
        'env_file_protection': PolicyTemplate(
            name='env_file_protection',
            description='Block access to .env files and variants',
            content='''
BLOCK IF:
    tool.name IN {{ FILE_TOOLS }}
    AND params.path CONTAINS ".env"
''',
            variables=['FILE_TOOLS'],
            default_values={'FILE_TOOLS': ['read_file', 'cat', 'head', 'tail', 'less', 'more', 'grep']},
            category='data_protection',
            severity='critical'
        ),

        # Environment Commands Protection
        'env_command_protection': PolicyTemplate(
            name='env_command_protection',
            description='Block environment variable listing commands',
            content='''
BLOCK IF:
    tool.name IN {{ ENV_COMMANDS }}
''',
            variables=['ENV_COMMANDS'],
            default_values={'ENV_COMMANDS': ['env', 'printenv', 'set']},
            category='data_protection',
            severity='high'
        ),

        # Bash Environment Protection
        'bash_env_protection': PolicyTemplate(
            name='bash_env_protection',
            description='Block bash commands accessing environment',
            content='''
BLOCK IF:
    tool.name == "bash"
    AND params.command CONTAINS "env"
''',
            variables=[],
            default_values={},
            category='data_protection',
            severity='high'
        ),

        # Environment Variable Redaction
        'env_var_redaction': PolicyTemplate(
            name='env_var_redaction',
            description='Redact environment variables in responses',
            content='''
MODIFY IF:
    response CONTAINS_SECRET
    OR response CONTAINS {{ SENSITIVE_PATTERNS }}
THEN:
    SET response = "[REDACTED - SENSITIVE ENVIRONMENT DATA]"
''',
            variables=['SENSITIVE_PATTERNS'],
            default_values={'SENSITIVE_PATTERNS': ['API_KEY=', 'SECRET=', 'PASSWORD=', 'TOKEN=']},
            category='data_protection',
            severity='high'
        )
    }

    def __init__(self, custom_templates_dir: str | None = None):
        """
        Initialize template system.
        
        Args:
            custom_templates_dir: Directory with custom templates
        """
        self.templates = self.TEMPLATES.copy()

        if custom_templates_dir:
            self._load_custom_templates(custom_templates_dir)

    def _load_custom_templates(self, directory: str):
        """Load custom templates from directory"""

        template_dir = Path(directory)
        if not template_dir.exists():
            return

        for file_path in template_dir.glob('*.yaml'):
            try:
                import yaml
                with open(file_path) as f:
                    data = yaml.safe_load(f)

                template = PolicyTemplate(
                    name=data['name'],
                    description=data.get('description', ''),
                    content=data['content'],
                    variables=data.get('variables', []),
                    default_values=data.get('defaults', {}),
                    category=data.get('category', 'custom'),
                    severity=data.get('severity', 'medium')
                )

                self.templates[template.name] = template

            except Exception as e:
                print(f"Failed to load template {file_path}: {e}")

    def render(self, name: str, variables: dict | None = None) -> str:
        """
        Render template with variables.
        
        Args:
            name: Template name
            variables: Variable values to substitute
        
        Returns:
            Rendered policy text
        """

        if name not in self.templates:
            raise ValueError(f"Template '{name}' not found")

        template = self.templates[name]
        content = template.content

        # Merge with defaults
        all_vars = template.default_values.copy()
        if variables:
            all_vars.update(variables)

        # Substitute variables
        for var_name, var_value in all_vars.items():
            placeholder = f'{{{{ {var_name} }}}}'

            # Format value based on type
            if isinstance(var_value, list):
                formatted = json.dumps(var_value)
            elif isinstance(var_value, str):
                # Check if it's a regex or plain string
                if var_value.startswith('^') or var_value.endswith('$'):
                    formatted = f'"{var_value}"'
                else:
                    formatted = f'"{var_value}"'
            else:
                formatted = str(var_value)

            content = content.replace(placeholder, formatted)

        return content.strip()

    def get_template(self, name: str) -> PolicyTemplate | None:
        """Get template by name"""
        return self.templates.get(name)

    def list_templates(self, category: str | None = None) -> list[PolicyTemplate]:
        """List all templates, optionally filtered by category"""

        templates = list(self.templates.values())

        if category:
            templates = [t for t in templates if t.category == category]

        return templates

    def get_categories(self) -> list[str]:
        """Get all template categories"""

        categories = set()
        for template in self.templates.values():
            categories.add(template.category)

        return sorted(list(categories))

    def generate_combined_policy(self, template_configs: list[dict]) -> str:
        """
        Generate combined policy from multiple templates.
        
        Args:
            template_configs: List of {'name': str, 'variables': dict}
        
        Returns:
            Combined policy text
        """

        policies = []

        for config in template_configs:
            name = config['name']
            variables = config.get('variables', {})

            rendered = self.render(name, variables)
            policies.append(f"# {self.templates[name].description}")
            policies.append(rendered)
            policies.append("")

        return "\n".join(policies)

    def create_server_policy(self, server_name: str,
                           threat_model: dict) -> str:
        """
        Create policy based on threat model.
        
        Args:
            server_name: Name of MCP server
            threat_model: Dict with threat flags
        
        Returns:
            Generated policy text
        """

        configs = []

        # Add policies based on threat model
        if threat_model.get('handles_secrets'):
            configs.append({
                'name': 'secrets',
                'variables': {'WHITELIST': []}
            })

        if threat_model.get('handles_pii'):
            configs.append({
                'name': 'pii',
                'variables': {
                    'ACTION': 'BLOCK' if threat_model.get('strict') else 'LOG',
                    'TRUSTED_SERVERS': []
                }
            })

        if threat_model.get('executes_commands'):
            configs.append({
                'name': 'command_injection',
                'variables': {}
            })

        if threat_model.get('accesses_filesystem'):
            configs.append({
                'name': 'filesystem_access',
                'variables': {
                    'ACTION': 'BLOCK',
                    'RESTRICTED_PATHS': ['/etc/', '/sys/', '~/.ssh/']
                }
            })
            configs.append({
                'name': 'path_traversal',
                'variables': {}
            })

        if threat_model.get('network_access'):
            configs.append({
                'name': 'network_exfiltration',
                'variables': {
                    'ACTION': 'LOG',
                    'ALLOWED_DOMAINS': threat_model.get('allowed_domains', '.*')
                }
            })

        if threat_model.get('disabled_tools'):
            configs.append({
                'name': 'disable_tool',
                'variables': {
                    'DISABLED_TOOLS': threat_model['disabled_tools']
                }
            })

        return self.generate_combined_policy(configs)
