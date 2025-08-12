"""
Mighty MCP Security - Session Management.

Advanced session tracking and analysis:
- SQLite backend for persistence
- Sophisticated event correlation
- Async operations for scalability
- Rich querying capabilities
- Toxic flow detection
"""

import json
import sqlite3
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


class ThreatLevel(Enum):
    """Threat level enumeration"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SessionNode:
    """Single event in a session"""
    timestamp: datetime
    session_id: str
    server_name: str
    client_name: str
    event_type: str
    tool_name: Optional[str]
    parameters: Optional[Dict]
    result: Optional[Dict]
    threat_level: ThreatLevel = ThreatLevel.LOW
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        
        # Convert string to datetime if needed
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['threat_level'] = self.threat_level.value
        return data
    
    def __lt__(self, other: "SessionNode") -> bool:
        """Sort by timestamp"""
        return self.timestamp < other.timestamp


class Session:
    """
    Enhanced session tracking with persistence and analysis.
    """
    
    def __init__(self, session_id: str, client: str, server: str):
        self.session_id = session_id
        self.client = client
        self.server = server
        self.nodes: List[SessionNode] = []
        self.started_at = datetime.now()
        self.ended_at: Optional[datetime] = None
        self.threat_summary = {
            'max_level': ThreatLevel.SAFE,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
    
    def add_node(self, node: SessionNode):
        """Add event node to session"""
        self.nodes.append(node)
        self.nodes.sort()  # Keep chronological order
        
        # Update threat summary
        if node.threat_level == ThreatLevel.CRITICAL:
            self.threat_summary['critical_count'] += 1
            self.threat_summary['max_level'] = ThreatLevel.CRITICAL
        elif node.threat_level == ThreatLevel.HIGH:
            self.threat_summary['high_count'] += 1
            if self.threat_summary['max_level'] != ThreatLevel.CRITICAL:
                self.threat_summary['max_level'] = ThreatLevel.HIGH
        elif node.threat_level == ThreatLevel.MEDIUM:
            self.threat_summary['medium_count'] += 1
            if self.threat_summary['max_level'] not in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                self.threat_summary['max_level'] = ThreatLevel.MEDIUM
        elif node.threat_level == ThreatLevel.LOW:
            self.threat_summary['low_count'] += 1
            if self.threat_summary['max_level'] == ThreatLevel.SAFE:
                self.threat_summary['max_level'] = ThreatLevel.LOW
    
    def get_timeline(self) -> List[SessionNode]:
        """Get chronological timeline of events"""
        return sorted(self.nodes)
    
    def get_tool_usage(self) -> Dict[str, int]:
        """Get tool usage statistics"""
        usage = {}
        for node in self.nodes:
            if node.tool_name:
                usage[node.tool_name] = usage.get(node.tool_name, 0) + 1
        return usage
    
    def find_toxic_flows(self) -> List[Dict]:
        """Detect potentially dangerous tool combinations"""
        toxic_flows = []
        
        # Look for dangerous patterns
        for i in range(len(self.nodes) - 1):
            curr = self.nodes[i]
            next_node = self.nodes[i + 1]
            
            # Check for credential read -> network send
            if curr.tool_name in ['read_file', 'read_env', 'get_credentials']:
                if next_node.tool_name in ['http_post', 'send_data', 'upload']:
                    toxic_flows.append({
                        'type': 'CREDENTIAL_EXFILTRATION',
                        'source': curr.tool_name,
                        'sink': next_node.tool_name,
                        'timestamp': next_node.timestamp.isoformat(),
                        'risk': 'CRITICAL'
                    })
            
            # Check for download -> execute
            if curr.tool_name in ['download', 'fetch_url', 'http_get']:
                if next_node.tool_name in ['exec', 'eval', 'run_command']:
                    toxic_flows.append({
                        'type': 'REMOTE_CODE_EXECUTION',
                        'source': curr.tool_name,
                        'sink': next_node.tool_name,
                        'timestamp': next_node.timestamp.isoformat(),
                        'risk': 'CRITICAL'
                    })
        
        return toxic_flows
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'client': self.client,
            'server': self.server,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'event_count': len(self.nodes),
            'threat_summary': {
                **self.threat_summary,
                'max_level': self.threat_summary['max_level'].value
            },
            'tool_usage': self.get_tool_usage(),
            'toxic_flows': self.find_toxic_flows()
        }


class SessionManager:
    """
    Manages sessions with SQLite persistence.
    
    Improvements:
    - Persistent storage
    - Rich querying
    - Async operations
    - Better analytics
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path.home() / '.secure-mcp' / 'sessions.db'
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.active_sessions: Dict[str, Session] = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                client TEXT NOT NULL,
                server TEXT NOT NULL,
                started_at TIMESTAMP NOT NULL,
                ended_at TIMESTAMP,
                max_threat_level TEXT,
                event_count INTEGER DEFAULT 0
            )
        ''')
        
        # Create events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                parameters TEXT,
                result TEXT,
                threat_level TEXT,
                metadata TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat_level)')
        
        conn.commit()
        conn.close()
    
    async def create_session(self, client: str, server: str) -> str:
        """Create new session"""
        session_id = f"{client}-{server}-{datetime.now().isoformat()}"
        session = Session(session_id, client, server)
        
        self.active_sessions[session_id] = session
        
        # Persist to database
        await self._save_session(session)
        
        return session_id
    
    async def log_event(self, session_id: str, event: Dict):
        """Log event to session"""
        if session_id not in self.active_sessions:
            # Try to load from database
            session = await self._load_session(session_id)
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            self.active_sessions[session_id] = session
        
        session = self.active_sessions[session_id]
        
        # Create session node
        node = SessionNode(
            timestamp=datetime.now(),
            session_id=session_id,
            server_name=session.server,
            client_name=session.client,
            event_type=event.get('type', 'unknown'),
            tool_name=event.get('tool'),
            parameters=event.get('params'),
            result=event.get('result'),
            threat_level=ThreatLevel(event.get('threat_level', 'low')),
            metadata=event.get('metadata', {})
        )
        
        session.add_node(node)
        
        # Persist event
        await self._save_event(node)
    
    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id].to_dict()
        
        # Try to load from database
        session = await self._load_session(session_id)
        if session:
            return session.to_dict()
        
        return None
    
    async def get_all_sessions(self) -> List[Dict]:
        """Get all sessions"""
        sessions = []
        
        # Add active sessions
        for session in self.active_sessions.values():
            sessions.append(session.to_dict())
        
        # Add persisted sessions not in memory
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT session_id, client, server, started_at, ended_at, max_threat_level, event_count
            FROM sessions
            WHERE session_id NOT IN ({})
        '''.format(','.join('?' * len(self.active_sessions))), 
            list(self.active_sessions.keys()) if self.active_sessions else [''])
        
        for row in cursor.fetchall():
            sessions.append({
                'session_id': row[0],
                'client': row[1],
                'server': row[2],
                'started_at': row[3],
                'ended_at': row[4],
                'max_threat_level': row[5],
                'event_count': row[6]
            })
        
        conn.close()
        return sessions
    
    async def end_session(self, session_id: str):
        """End a session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.ended_at = datetime.now()
            await self._save_session(session)
            del self.active_sessions[session_id]
    
    async def _save_session(self, session: Session):
        """Save session to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, client, server, started_at, ended_at, max_threat_level, event_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id,
            session.client,
            session.server,
            session.started_at.isoformat(),
            session.ended_at.isoformat() if session.ended_at else None,
            session.threat_summary['max_level'].value,
            len(session.nodes)
        ))
        
        conn.commit()
        conn.close()
    
    async def _save_event(self, node: SessionNode):
        """Save event to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO events
            (session_id, timestamp, event_type, tool_name, parameters, result, threat_level, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            node.session_id,
            node.timestamp.isoformat(),
            node.event_type,
            node.tool_name,
            json.dumps(node.parameters) if node.parameters else None,
            json.dumps(node.result) if node.result else None,
            node.threat_level.value,
            json.dumps(node.metadata) if node.metadata else None
        ))
        
        conn.commit()
        conn.close()
    
    async def _load_session(self, session_id: str) -> Optional[Session]:
        """Load session from database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Load session info
        cursor.execute(
            'SELECT client, server, started_at FROM sessions WHERE session_id = ?',
            (session_id,)
        )
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        session = Session(session_id, row[0], row[1])
        session.started_at = datetime.fromisoformat(row[2])
        
        # Load events
        cursor.execute('''
            SELECT timestamp, event_type, tool_name, parameters, result, threat_level, metadata
            FROM events
            WHERE session_id = ?
            ORDER BY timestamp
        ''', (session_id,))
        
        for row in cursor.fetchall():
            node = SessionNode(
                timestamp=datetime.fromisoformat(row[0]),
                session_id=session_id,
                server_name=session.server,
                client_name=session.client,
                event_type=row[1],
                tool_name=row[2],
                parameters=json.loads(row[3]) if row[3] else None,
                result=json.loads(row[4]) if row[4] else None,
                threat_level=ThreatLevel(row[5]),
                metadata=json.loads(row[6]) if row[6] else {}
            )
            session.add_node(node)
        
        conn.close()
        return session
    
    async def save(self):
        """Save all active sessions"""
        for session in self.active_sessions.values():
            await self._save_session(session)
    
    async def query_high_risk_sessions(self) -> List[Dict]:
        """Query sessions with high risk events"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT s.session_id, s.client, s.server, s.started_at, 
                   COUNT(e.id) as risk_event_count
            FROM sessions s
            JOIN events e ON s.session_id = e.session_id
            WHERE e.threat_level IN ('high', 'critical')
            GROUP BY s.session_id
            ORDER BY risk_event_count DESC
        ''')
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'session_id': row[0],
                'client': row[1],
                'server': row[2],
                'started_at': row[3],
                'risk_event_count': row[4]
            })
        
        conn.close()
        return results