"""
Mighty MCP Security - Policy Parser.

Advanced policy language for declarative security rules:
- Expressive domain-specific language (DSL)
- Comprehensive error handling
- Support for complex conditional logic
- Deep integration with static analyzers
"""

import re
import ast
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from enum import Enum


class PolicyAction(Enum):
    """Policy actions"""
    BLOCK = "block"
    LOG = "log"
    MODIFY = "modify"
    ALLOW = "allow"


class ConditionOperator(Enum):
    """Condition operators"""
    EQUALS = "=="
    NOT_EQUALS = "!="
    IN = "IN"
    NOT_IN = "NOT IN"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT CONTAINS"
    MATCHES = "MATCHES"
    NOT_MATCHES = "NOT MATCHES"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    GREATER_THAN = ">"
    LESS_THAN = "<"
    AND = "AND"
    OR = "OR"


@dataclass
class Condition:
    """Base condition class"""
    pass


@dataclass
class SimpleCondition(Condition):
    """Simple field comparison condition"""
    field: str
    operator: ConditionOperator
    value: Any
    
    async def evaluate(self, context: Dict) -> bool:
        """Evaluate condition against context"""
        
        # Get field value from context
        field_value = self._get_field_value(context, self.field)
        
        # Evaluate based on operator
        if self.operator == ConditionOperator.EQUALS:
            return field_value == self.value
        
        elif self.operator == ConditionOperator.NOT_EQUALS:
            return field_value != self.value
        
        elif self.operator == ConditionOperator.IN:
            return field_value in self.value
        
        elif self.operator == ConditionOperator.NOT_IN:
            return field_value not in self.value
        
        elif self.operator == ConditionOperator.CONTAINS:
            return self.value in str(field_value)
        
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return self.value not in str(field_value)
        
        elif self.operator == ConditionOperator.MATCHES:
            return bool(re.match(self.value, str(field_value)))
        
        elif self.operator == ConditionOperator.NOT_MATCHES:
            return not bool(re.match(self.value, str(field_value)))
        
        elif self.operator == ConditionOperator.STARTS_WITH:
            return str(field_value).startswith(self.value)
        
        elif self.operator == ConditionOperator.ENDS_WITH:
            return str(field_value).endswith(self.value)
        
        elif self.operator == ConditionOperator.GREATER_THAN:
            return field_value > self.value
        
        elif self.operator == ConditionOperator.LESS_THAN:
            return field_value < self.value
        
        return False
    
    def _get_field_value(self, context: Dict, field: str) -> Any:
        """Get nested field value from context"""
        
        parts = field.split('.')
        value = context
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value


@dataclass
class CompositeCondition(Condition):
    """Composite condition with AND/OR logic"""
    operator: ConditionOperator
    conditions: List[Condition]
    
    async def evaluate(self, context: Dict) -> bool:
        """Evaluate composite condition"""
        
        if self.operator == ConditionOperator.AND:
            for condition in self.conditions:
                if not await condition.evaluate(context):
                    return False
            return True
        
        elif self.operator == ConditionOperator.OR:
            for condition in self.conditions:
                if await condition.evaluate(context):
                    return True
            return False
        
        return False


@dataclass
class SecurityCheck(Condition):
    """Special security check condition"""
    check_type: str
    params: Dict
    
    async def evaluate(self, context: Dict) -> bool:
        """Evaluate security check"""
        
        if self.check_type == "CONTAINS_SECRET":
            # Check for secrets in response
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from src.analyzers.security.secrets_detector import detect_secrets
            content = str(context.get('response', ''))
            return len(detect_secrets(content)) > 0
        
        elif self.check_type == "CONTAINS_PII":
            # Check for PII
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from src.analyzers.security.pii_detector import detect_pii
            content = str(context.get('response', ''))
            return len(detect_pii(content)) > 0
        
        elif self.check_type == "CONTAINS_SHELL_CHARS":
            # Check for shell injection characters
            params = context.get('params', {})
            dangerous_chars = [';', '&&', '||', '`', '$', '|']
            params_str = str(params)
            return any(char in params_str for char in dangerous_chars)
        
        elif self.check_type == "PATH_TRAVERSAL":
            # Check for path traversal
            params = context.get('params', {})
            params_str = str(params)
            return '../' in params_str or '..\\' in params_str
        
        return False


class PolicyLanguage:
    """
    Enhanced DSL for security policies.
    
    Example syntax:
    ```
    BLOCK IF:
        tool.name IN ["exec", "eval"]
        OR params CONTAINS_SHELL_CHARS
        OR response CONTAINS_SECRET
    
    MODIFY IF:
        tool.name == "read_file"
        AND file.path STARTS_WITH "/etc/"
    THEN:
        SET file.path = "/tmp/safe"
    
    LOG IF:
        response CONTAINS_PII
        AND NOT tool.sanitize_enabled
    ```
    """
    
    def __init__(self):
        self.line_number = 0
        self.errors = []
    
    def parse(self, policy_text: str) -> 'ParsedPolicy':
        """Parse policy DSL into executable policy"""
        
        lines = policy_text.strip().split('\n')
        self.line_number = 0
        self.errors = []
        
        # Parse action
        action_line = self._next_non_empty_line(lines)
        action = self._parse_action(action_line)
        
        # Parse conditions
        conditions = []
        modifications = {}
        
        parsing_then = False
        
        for line in lines[self.line_number:]:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line == "THEN:":
                parsing_then = True
                continue
            
            if parsing_then:
                # Parse modifications
                mod = self._parse_modification(line)
                if mod:
                    modifications.update(mod)
            else:
                # Parse conditions
                cond = self._parse_condition_line(line)
                if cond:
                    conditions.append(cond)
        
        # Build composite condition
        if len(conditions) == 1:
            root_condition = conditions[0]
        else:
            root_condition = self._build_composite_conditions(conditions)
        
        return ParsedPolicy(
            action=action,
            condition=root_condition,
            modifications=modifications,
            errors=self.errors
        )
    
    def _next_non_empty_line(self, lines: List[str]) -> str:
        """Get next non-empty line"""
        
        while self.line_number < len(lines):
            line = lines[self.line_number].strip()
            self.line_number += 1
            
            if line and not line.startswith('#'):
                return line
        
        return ""
    
    def _parse_action(self, line: str) -> PolicyAction:
        """Parse action from line"""
        
        parts = line.split()
        if not parts:
            self.errors.append(f"Line {self.line_number}: Empty action")
            return PolicyAction.LOG
        
        action_str = parts[0].upper()
        
        try:
            return PolicyAction[action_str]
        except KeyError:
            self.errors.append(f"Line {self.line_number}: Unknown action '{action_str}'")
            return PolicyAction.LOG
    
    def _parse_condition_line(self, line: str) -> Optional[Condition]:
        """Parse single condition line"""
        
        # Remove logical operators at start
        if line.startswith('AND '):
            line = line[4:]
        elif line.startswith('OR '):
            line = line[3:]
        
        # Parse security checks
        if 'CONTAINS_SECRET' in line:
            return SecurityCheck('CONTAINS_SECRET', {})
        elif 'CONTAINS_PII' in line:
            return SecurityCheck('CONTAINS_PII', {})
        elif 'CONTAINS_SHELL_CHARS' in line:
            return SecurityCheck('CONTAINS_SHELL_CHARS', {})
        elif 'PATH_TRAVERSAL' in line:
            return SecurityCheck('PATH_TRAVERSAL', {})
        
        # Parse operators
        for op_text, op_enum in [
            (' NOT IN ', ConditionOperator.NOT_IN),
            (' IN ', ConditionOperator.IN),
            (' NOT CONTAINS ', ConditionOperator.NOT_CONTAINS),
            (' CONTAINS ', ConditionOperator.CONTAINS),
            (' NOT MATCHES ', ConditionOperator.NOT_MATCHES),
            (' MATCHES ', ConditionOperator.MATCHES),
            (' STARTS_WITH ', ConditionOperator.STARTS_WITH),
            (' ENDS_WITH ', ConditionOperator.ENDS_WITH),
            (' != ', ConditionOperator.NOT_EQUALS),
            (' == ', ConditionOperator.EQUALS),
            (' > ', ConditionOperator.GREATER_THAN),
            (' < ', ConditionOperator.LESS_THAN),
        ]:
            if op_text in line:
                parts = line.split(op_text, 1)
                if len(parts) == 2:
                    field = parts[0].strip()
                    value = self._parse_value(parts[1].strip())
                    return SimpleCondition(field, op_enum, value)
        
        self.errors.append(f"Line {self.line_number}: Could not parse condition '{line}'")
        return None
    
    def _parse_value(self, value_str: str) -> Any:
        """Parse value from string"""
        
        value_str = value_str.strip()
        
        # Remove quotes
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]
        
        # Parse list
        if value_str.startswith('[') and value_str.endswith(']'):
            try:
                return ast.literal_eval(value_str)
            except:
                return value_str
        
        # Parse boolean
        if value_str.lower() == 'true':
            return True
        elif value_str.lower() == 'false':
            return False
        
        # Parse number
        try:
            if '.' in value_str:
                return float(value_str)
            else:
                return int(value_str)
        except:
            pass
        
        return value_str
    
    def _parse_modification(self, line: str) -> Optional[Dict]:
        """Parse modification instruction"""
        
        if line.startswith('SET '):
            line = line[4:]
            
            if ' = ' in line:
                field, value = line.split(' = ', 1)
                return {field.strip(): self._parse_value(value)}
        
        return None
    
    def _build_composite_conditions(self, conditions: List[Condition]) -> Condition:
        """Build composite condition tree from flat list"""
        
        # For now, treat consecutive conditions as AND
        # TODO: Properly parse AND/OR precedence
        return CompositeCondition(ConditionOperator.AND, conditions)


@dataclass
class ParsedPolicy:
    """Parsed policy ready for evaluation"""
    action: PolicyAction
    condition: Condition
    modifications: Dict[str, Any]
    errors: List[str]
    
    async def evaluate(self, context: Dict) -> 'PolicyEvaluation':
        """Evaluate policy against context"""
        
        if self.errors:
            return PolicyEvaluation(
                action=PolicyAction.LOG,
                matched=False,
                reason="Policy has parsing errors",
                errors=self.errors
            )
        
        matched = await self.condition.evaluate(context)
        
        if matched:
            return PolicyEvaluation(
                action=self.action,
                matched=True,
                reason=f"Policy condition matched",
                modifications=self.modifications if self.action == PolicyAction.MODIFY else None
            )
        
        return PolicyEvaluation(
            action=PolicyAction.ALLOW,
            matched=False,
            reason="Policy condition not matched"
        )


@dataclass
class PolicyEvaluation:
    """Policy evaluation result"""
    action: PolicyAction
    matched: bool
    reason: str
    modifications: Optional[Dict] = None
    errors: Optional[List[str]] = None


class PolicyParser:
    """Main policy parser interface"""
    
    def __init__(self):
        self.language = PolicyLanguage()
    
    def parse_file(self, filepath: str) -> ParsedPolicy:
        """Parse policy from file"""
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        return self.language.parse(content)
    
    def parse_string(self, policy_text: str) -> ParsedPolicy:
        """Parse policy from string"""
        return self.language.parse(policy_text)
    
    def validate(self, policy_text: str) -> List[str]:
        """Validate policy and return errors"""
        
        parsed = self.language.parse(policy_text)
        return parsed.errors