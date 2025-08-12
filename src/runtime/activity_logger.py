"""
Mighty MCP Security - Activity Logger.

Rich activity logging and monitoring:
- Multiple output formats (oneline, compact, full, JSON)
- Async logging for performance
- Structured logging with security levels
- Integration with monitoring systems
- Beautiful console output with Rich
"""

import json
import asyncio
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule


class OutputFormat(Enum):
    """Output format options"""
    ONELINE = "oneline"
    COMPACT = "compact"
    FULL = "full"
    JSON = "json"
    NONE = "none"


class ActivityLogger:
    """
    Rich activity logging for MCP operations.
    
    Improvements:
    - Async operations
    - Multiple output formats
    - Structured logging
    - Better formatting
    """
    
    def __init__(self, 
                 format: OutputFormat = OutputFormat.COMPACT,
                 log_file: Optional[str] = None,
                 enable_console: bool = True):
        
        self.format = format
        self.console = Console() if enable_console else None
        self.events: List[Dict] = []
        self.logged_items: set = set()  # Prevent duplicate logging
        
        # Setup file logging if requested
        if log_file:
            self.log_file = Path(log_file)
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._setup_file_logging()
        else:
            self.log_file = None
    
    def _setup_file_logging(self):
        """Setup structured file logging"""
        logging.basicConfig(
            filename=str(self.log_file),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    async def log_tool_call(self, session_id: str, client: str, 
                           server: str, tool: str, params: Dict):
        """Log tool call with formatting"""
        
        event = {
            'type': 'tool_call',
            'session_id': session_id,
            'client': client,
            'server': server,
            'tool': tool,
            'params': params,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check for duplicates
        event_key = f"{session_id}-{tool}-{datetime.now().timestamp()}"
        if event_key in self.logged_items:
            return
        self.logged_items.add(event_key)
        
        self.events.append(event)
        
        # Console output
        if self.console:
            await self._console_log_tool_call(event)
        
        # File logging
        if self.log_file:
            logging.info(json.dumps(event))
    
    async def _console_log_tool_call(self, event: Dict):
        """Format and display tool call in console"""
        
        if self.format == OutputFormat.NONE:
            return
        
        client = event['client']
        server = event['server']
        tool = event['tool']
        params = event['params']
        
        if self.format == OutputFormat.ONELINE:
            self.console.print(
                f"→ [blue]{client}[/blue] → [green]{server}.{tool}[/green]"
            )
        
        elif self.format == OutputFormat.COMPACT:
            self.console.rule(f"[bold]Tool Call: {tool}[/bold]", style="blue")
            self.console.print(f"Client: [blue]{client}[/blue]")
            self.console.print(f"Server: [green]{server}[/green]")
            if params:
                self.console.print("Params:", json.dumps(params, indent=2))
        
        elif self.format == OutputFormat.FULL:
            # Create rich table
            table = Table(title=f"Tool Call: {tool}", show_header=True)
            table.add_column("Property", style="cyan", no_wrap=True)
            table.add_column("Value", style="magenta")
            
            table.add_row("Session ID", event['session_id'])
            table.add_row("Client", client)
            table.add_row("Server", server)
            table.add_row("Timestamp", event['timestamp'])
            
            self.console.print(table)
            
            if params:
                # Pretty print parameters
                syntax = Syntax(
                    json.dumps(params, indent=2),
                    "json",
                    theme="monokai",
                    line_numbers=True
                )
                self.console.print(Panel(syntax, title="Parameters"))
        
        elif self.format == OutputFormat.JSON:
            self.console.print(json.dumps(event, indent=2))
    
    async def log_tool_response(self, session_id: str, tool: str, 
                               response: Any, duration: float = None):
        """Log tool response"""
        
        event = {
            'type': 'tool_response',
            'session_id': session_id,
            'tool': tool,
            'response': str(response)[:1000],  # Truncate long responses
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        if self.console and self.format != OutputFormat.NONE:
            await self._console_log_tool_response(event)
        
        if self.log_file:
            logging.info(json.dumps(event))
    
    async def _console_log_tool_response(self, event: Dict):
        """Format and display tool response"""
        
        tool = event['tool']
        response = event['response']
        duration = event.get('duration')
        
        if self.format == OutputFormat.ONELINE:
            duration_str = f" ({duration:.2f}s)" if duration else ""
            self.console.print(
                f"← [green]{tool}[/green]: {len(response)} chars{duration_str}"
            )
        
        elif self.format == OutputFormat.COMPACT:
            self.console.print(f"[dim]Response from {tool}:[/dim]")
            # Truncate for compact view
            if len(response) > 200:
                self.console.print(response[:200] + "...")
            else:
                self.console.print(response)
        
        elif self.format == OutputFormat.FULL:
            panel_title = f"Response: {tool}"
            if duration:
                panel_title += f" ({duration:.2f}s)"
            
            # Try to parse as JSON for better formatting
            try:
                response_obj = json.loads(response)
                syntax = Syntax(
                    json.dumps(response_obj, indent=2),
                    "json",
                    theme="monokai"
                )
                self.console.print(Panel(syntax, title=panel_title))
            except:
                self.console.print(Panel(response, title=panel_title))
        
        elif self.format == OutputFormat.JSON:
            self.console.print(json.dumps(event, indent=2))
    
    async def log_security_event(self, level: str, message: str, 
                                details: Optional[Dict] = None):
        """Log security-related events with emphasis"""
        
        event = {
            'type': 'security',
            'level': level,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        # Console output with color coding
        if self.console and self.format != OutputFormat.NONE:
            await self._console_log_security_event(event)
        
        # File logging with appropriate level
        if self.log_file:
            log_level = {
                'critical': logging.CRITICAL,
                'high': logging.ERROR,
                'medium': logging.WARNING,
                'low': logging.INFO,
                'info': logging.DEBUG
            }.get(level, logging.INFO)
            
            logging.log(log_level, json.dumps(event))
    
    async def _console_log_security_event(self, event: Dict):
        """Format and display security event"""
        
        level = event['level']
        message = event['message']
        details = event.get('details', {})
        
        # Color mapping
        colors = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        
        color = colors.get(level, 'white')
        icon = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️',
            'info': '📝'
        }.get(level, '•')
        
        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps(event, indent=2))
            return
        
        # Create styled output
        self.console.rule(style=color)
        
        if self.format == OutputFormat.ONELINE:
            self.console.print(f"[{color}]{icon} {level.upper()}: {message}[/{color}]")
        
        else:  # COMPACT or FULL
            # Main message
            text = Text()
            text.append(f"{icon} ", style=color)
            text.append(f"SECURITY {level.upper()}: ", style=f"bold {color}")
            text.append(message, style=color)
            self.console.print(text)
            
            # Details if present
            if details and self.format == OutputFormat.FULL:
                detail_table = Table(show_header=False, box=None)
                detail_table.add_column("Key", style="cyan")
                detail_table.add_column("Value", style="white")
                
                for key, value in details.items():
                    detail_table.add_row(f"  {key}:", str(value))
                
                self.console.print(detail_table)
        
        self.console.rule(style=color)
        self.console.print()  # Add spacing
    
    async def log_policy_violation(self, policy_name: str, action: str,
                                  tool: str, reason: str):
        """Log policy violations"""
        
        event = {
            'type': 'policy_violation',
            'policy': policy_name,
            'action': action,
            'tool': tool,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        if self.console and self.format != OutputFormat.NONE:
            if self.format == OutputFormat.JSON:
                self.console.print(json.dumps(event, indent=2))
            else:
                self.console.print(
                    f"[red]📋 POLICY VIOLATION[/red]: {policy_name}\n"
                    f"  Tool: {tool}\n"
                    f"  Action: [bold]{action}[/bold]\n"
                    f"  Reason: {reason}"
                )
    
    async def log_request(self, method: str, path: str, 
                         duration: float, status: int):
        """Log HTTP requests (for API monitoring)"""
        
        if self.format == OutputFormat.NONE:
            return
        
        event = {
            'type': 'http_request',
            'method': method,
            'path': path,
            'duration': duration,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        # Only log to file, not console (unless verbose)
        if self.log_file:
            logging.debug(json.dumps(event))
        
        if self.console and self.format == OutputFormat.FULL:
            status_color = "green" if status < 400 else "red"
            self.console.print(
                f"[dim]{method} {path} [{status_color}]{status}[/{status_color}] "
                f"({duration:.3f}s)[/dim]"
            )
    
    async def log_error(self, error: str, request_path: Optional[str] = None):
        """Log errors"""
        
        event = {
            'type': 'error',
            'error': error,
            'request_path': request_path,
            'timestamp': datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        if self.console:
            self.console.print(f"[red]❌ ERROR: {error}[/red]")
        
        if self.log_file:
            logging.error(json.dumps(event))
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        
        summary = {
            'total_events': len(self.events),
            'tool_calls': len([e for e in self.events if e['type'] == 'tool_call']),
            'security_events': len([e for e in self.events if e['type'] == 'security']),
            'policy_violations': len([e for e in self.events if e['type'] == 'policy_violation']),
            'errors': len([e for e in self.events if e['type'] == 'error'])
        }
        
        # Count by security level
        security_events = [e for e in self.events if e['type'] == 'security']
        for level in ['critical', 'high', 'medium', 'low', 'info']:
            summary[f'security_{level}'] = len([e for e in security_events if e['level'] == level])
        
        return summary
    
    async def display_summary(self):
        """Display activity summary"""
        
        if not self.console:
            return
        
        summary = self.get_summary()
        
        self.console.rule("[bold]Activity Summary[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")
        
        table.add_row("Total Events", str(summary['total_events']))
        table.add_row("Tool Calls", str(summary['tool_calls']))
        table.add_row("Security Events", str(summary['security_events']))
        
        if summary['security_critical'] > 0:
            table.add_row("  Critical", f"[red]{summary['security_critical']}[/red]")
        if summary['security_high'] > 0:
            table.add_row("  High", f"[yellow]{summary['security_high']}[/yellow]")
        if summary['security_medium'] > 0:
            table.add_row("  Medium", str(summary['security_medium']))
        
        table.add_row("Policy Violations", str(summary['policy_violations']))
        table.add_row("Errors", str(summary['errors']))
        
        self.console.print(table)
    
    def export_events(self, filepath: str):
        """Export all events to file"""
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.events, f, indent=2)
        
        if self.console:
            self.console.print(f"[green]✅ Exported {len(self.events)} events to {filepath}[/green]")