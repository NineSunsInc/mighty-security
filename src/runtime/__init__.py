"""
Mighty MCP Security - Runtime Module.

Real-time security monitoring for MCP servers with:
- Advanced threat detection
- Policy enforcement
- Session tracking and analysis
- Gateway injection
"""

# Lazy imports to avoid dependency issues when not using monitoring
def get_proxy_server():
    from .proxy_server import MCPProxyServer
    return MCPProxyServer

def get_gateway():
    from .gateway import SecurityGateway
    return SecurityGateway

def get_injector():
    from .injector import GatewayInjector
    return GatewayInjector

from .session import SessionManager, SessionNode, Session
from .activity_logger import ActivityLogger, OutputFormat

__all__ = [
    'get_proxy_server',
    'get_gateway', 
    'get_injector',
    'SessionManager',
    'SessionNode',
    'Session',
    'ActivityLogger',
    'OutputFormat'
]