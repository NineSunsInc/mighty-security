"""
Mighty MCP Security - Real-time Proxy Server.

Advanced security monitoring for MCP servers with:
- Async architecture for high performance
- Modular policy system
- Deep integration with security analyzers
- WebSocket support for real-time monitoring
- Comprehensive error handling and recovery
"""

import json
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..configs.discovery import ConfigDiscovery
from ..policies.manager import PolicyManager
from ..signatures.manager import SignatureManager
from .activity_logger import ActivityLogger
from .analyzer_integration import AnalyzerIntegration
from .gateway import SecurityGateway
from .session import SessionManager


class MCPProxyServer:
    """
    Real-time MCP traffic proxy with security enforcement.
    
    Key features:
    - Intercepts and validates all MCP traffic
    - Applies security policies in real-time
    - Tracks sessions and activities
    - Provides WebSocket monitoring
    - Integrates with static analyzers
    """

    def __init__(self, config_path: str | None = None, port: int = 8888):
        self.port = port
        self.app = FastAPI(title="Secure-MCP Proxy", version="2.0.0")

        # Core components
        self.gateway = SecurityGateway()
        self.sessions = SessionManager()
        self.policies = PolicyManager()
        self.signatures = SignatureManager()
        self.discovery = ConfigDiscovery()
        self.logger = ActivityLogger()
        self.analyzer = AnalyzerIntegration()

        # Runtime state
        self.active_sessions: dict[str, dict] = {}
        self.websocket_clients: list[WebSocket] = []
        self.config = self._load_config(config_path)

        # Setup
        self._setup_middleware()
        self._setup_routes()
        self._setup_error_handlers()

    def _load_config(self, config_path: str | None) -> dict:
        """Load configuration from file or use defaults"""
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                return json.load(f)

        # Default configuration
        return {
            'proxy': {
                'port': self.port,
                'host': '0.0.0.0',
                'timeout': 30
            },
            'policies': {
                'default_action': 'log',  # log, block, modify
                'strict_mode': False
            },
            'logging': {
                'format': 'compact',
                'persist': True,
                'max_size_mb': 100
            },
            'monitoring': {
                'enable_websocket': True,
                'metrics': True
            }
        }

    def _setup_middleware(self):
        """Configure middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        )

        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            """Log all requests for debugging"""
            start_time = datetime.now()
            response = await call_next(request)
            duration = (datetime.now() - start_time).total_seconds()

            # Log request details
            await self.logger.log_request(
                method=request.method,
                path=request.url.path,
                duration=duration,
                status=response.status_code
            )

            return response

    def _setup_routes(self):
        """Setup API routes"""

        @self.app.post("/proxy/intercept")
        async def intercept_tool_call(request: Request):
            """Intercept and validate MCP tool calls"""
            data = await request.json()

            # Extract request details
            session_id = data.get('session_id')
            client = data.get('client', 'unknown')
            server = data.get('server', 'unknown')
            tool_name = data.get('tool')
            params = data.get('params', {})

            # Create session if needed
            if not session_id:
                session_id = await self.sessions.create_session(client, server)

            # Log the tool call
            await self.logger.log_tool_call(
                session_id=session_id,
                client=client,
                server=server,
                tool=tool_name,
                params=params
            )

            # Run comprehensive analysis using existing analyzers
            analysis_result = await self.analyzer.analyze_tool_before_execution(
                tool={'name': tool_name, 'params': params},
                context={
                    'client': client,
                    'server': server,
                    'session_id': session_id
                }
            )

            # Apply security policies
            policy_result = await self.policies.evaluate(
                tool=tool_name,
                params=params,
                context={
                    'client': client,
                    'server': server,
                    'session_id': session_id
                }
            )

            # Check signature
            sig_result = await self.signatures.verify_tool({
                'name': tool_name,
                'params': params,
                'server': server
            })

            # Determine action based on all analysis results
            should_block = (
                policy_result.action == 'block' or
                sig_result.get('threat_level') == 'critical' or
                analysis_result.get('risk_level') == 'critical' or
                analysis_result.get('threat_score', 0) >= 8
            )

            if should_block:
                # Block the request
                await self.logger.log_security_event(
                    level='critical',
                    message=f"Blocked tool call: {tool_name}",
                    details={
                        'reason': policy_result.reason or sig_result.get('reason') or f"High risk detected (score: {analysis_result.get('threat_score', 0)})",
                        'tool': tool_name,
                        'server': server,
                        'threat_score': analysis_result.get('threat_score', 0),
                        'vulnerabilities': analysis_result.get('vulnerabilities', [])[:3]  # Top 3
                    }
                )

                # Notify WebSocket clients
                await self._broadcast_to_websockets({
                    'type': 'security_alert',
                    'level': 'critical',
                    'tool': tool_name,
                    'action': 'blocked'
                })

                return JSONResponse(
                    status_code=403,
                    content={
                        'error': 'Tool call blocked by security policy',
                        'reason': policy_result.reason,
                        'tool': tool_name
                    }
                )

            elif policy_result.action == 'modify':
                # Modify parameters based on policy
                params = policy_result.modified_params or params
                data['params'] = params

                await self.logger.log_security_event(
                    level='medium',
                    message=f"Modified tool parameters: {tool_name}",
                    details={'modifications': policy_result.modifications}
                )

            # Forward the request (either original or modified)
            response = await self._forward_to_mcp(data)

            # Log the response
            await self.sessions.log_event(
                session_id=session_id,
                event={
                    'type': 'tool_response',
                    'tool': tool_name,
                    'response': response,
                    'timestamp': datetime.now().isoformat()
                }
            )

            return response

        @self.app.websocket("/ws/monitor")
        async def websocket_monitor(websocket: WebSocket):
            """WebSocket endpoint for real-time monitoring"""
            await websocket.accept()
            self.websocket_clients.append(websocket)

            try:
                # Send initial connection info
                await websocket.send_json({
                    'type': 'connected',
                    'timestamp': datetime.now().isoformat(),
                    'active_sessions': len(self.active_sessions)
                })

                # Keep connection alive
                while True:
                    data = await websocket.receive_text()

                    # Handle ping/pong
                    if data == "ping":
                        await websocket.send_text("pong")

            except Exception as e:
                print(f"WebSocket error: {e}")
            finally:
                if websocket in self.websocket_clients:
                    self.websocket_clients.remove(websocket)

        @self.app.get("/api/v1/sessions")
        async def get_sessions():
            """Get all active sessions"""
            return {
                'sessions': await self.sessions.get_all_sessions(),
                'count': len(self.active_sessions)
            }

        @self.app.get("/api/v1/sessions/{session_id}")
        async def get_session(session_id: str):
            """Get specific session details"""
            session = await self.sessions.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            return session

        @self.app.get("/api/v1/sessions/{session_id}/toxic-flows")
        async def get_toxic_flows(session_id: str):
            """Analyze session for toxic flows"""
            session = await self.sessions.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")

            # Get session events
            events = session.get('events', [])

            # Analyze for toxic flows
            toxic_flows = await self.analyzer.analyze_toxic_flow(events)

            return {
                'session_id': session_id,
                'toxic_flows': toxic_flows,
                'risk_level': 'critical' if toxic_flows else 'low'
            }

        @self.app.get("/api/v1/policies")
        async def get_policies():
            """Get all active policies"""
            return await self.policies.get_all_policies()

        @self.app.post("/api/v1/policies")
        async def create_policy(request: Request):
            """Create new policy"""
            data = await request.json()
            policy = await self.policies.create_policy(data)
            return {'id': policy.id, 'status': 'created'}

        @self.app.delete("/api/v1/policies/{policy_id}")
        async def delete_policy(policy_id: str):
            """Delete policy"""
            success = await self.policies.delete_policy(policy_id)
            if not success:
                raise HTTPException(status_code=404, detail="Policy not found")
            return {'status': 'deleted'}

        @self.app.get("/api/v1/signatures/report")
        async def get_signatures_report():
            """Get signature database report"""
            return await self.signatures.get_report()

        @self.app.post("/api/v1/signatures/whitelist")
        async def whitelist_signature(request: Request):
            """Add signature to whitelist"""
            data = await request.json()
            await self.signatures.whitelist_tool(
                signature=data['signature'],
                reason=data.get('reason', '')
            )
            return {'status': 'whitelisted'}

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'active_sessions': len(self.active_sessions),
                'websocket_clients': len(self.websocket_clients)
            }

    def _setup_error_handlers(self):
        """Setup global error handlers"""

        @self.app.exception_handler(Exception)
        async def global_exception_handler(request: Request, exc: Exception):
            """Handle all unhandled exceptions"""
            await self.logger.log_error(
                error=str(exc),
                request_path=request.url.path
            )

            return JSONResponse(
                status_code=500,
                content={
                    'error': 'Internal server error',
                    'message': str(exc) if self.config['policies']['strict_mode'] else 'An error occurred'
                }
            )

    async def _forward_to_mcp(self, data: dict) -> dict:
        """Forward request to actual MCP server"""
        # This would be implemented to forward to the actual MCP server
        # For now, return a mock response
        return {
            'success': True,
            'response': 'Forwarded to MCP server',
            'timestamp': datetime.now().isoformat()
        }

    async def _broadcast_to_websockets(self, message: dict):
        """Broadcast message to all WebSocket clients"""
        disconnected = []

        for ws in self.websocket_clients:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)

        # Remove disconnected clients
        for ws in disconnected:
            if ws in self.websocket_clients:
                self.websocket_clients.remove(ws)

    async def start(self):
        """Start the proxy server"""
        print(f"🚀 Starting Secure-MCP Proxy on port {self.port}")

        # Inject gateway into discovered configs
        configs = await self.discovery.discover_all()
        injected = 0

        for config in configs:
            try:
                if await self.gateway.inject(config['path']):
                    injected += 1
                    print(f"✅ Injected gateway into {config['client']}")
            except Exception as e:
                print(f"⚠️ Failed to inject into {config['client']}: {e}")

        print(f"📊 Injected gateway into {injected}/{len(configs)} configs")

        # Start the FastAPI server
        config = uvicorn.Config(
            app=self.app,
            host=self.config['proxy']['host'],
            port=self.port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()

    async def stop(self):
        """Stop proxy and cleanup"""
        print("🛑 Stopping Secure-MCP Proxy...")

        # Close all WebSocket connections
        for ws in self.websocket_clients:
            try:
                await ws.close()
            except Exception:
                pass

        # Cleanup gateway injections
        await self.gateway.cleanup()

        # Save session data
        await self.sessions.save()

        print("✅ Proxy stopped successfully")
