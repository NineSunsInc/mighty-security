"""
Mighty MCP Security - Signature Manager.

Advanced tool signature management system:
- SHA-512 cryptographic signatures
- Comprehensive change tracking
- Fuzzy matching for variant detection
- Machine learning integration
- Rug pull attack detection
"""

import hashlib
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
import asyncio


@dataclass
class ToolSignature:
    """Tool signature record"""
    signature: str
    tool_name: str
    server_name: str
    first_seen: str
    last_seen: str
    times_seen: int = 1
    description: Optional[str] = None
    parameters: Optional[Dict] = None
    permissions: Optional[List[str]] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SignatureVerification:
    """Signature verification result"""
    tool_name: str
    signature: str
    status: str  # new, known, modified, whitelisted, blacklisted
    changed: bool = False
    threat_level: str = "low"
    previous_signature: Optional[str] = None
    last_seen: Optional[str] = None
    reason: Optional[str] = None
    similar_tools: Optional[List[Dict]] = None


class SignatureManager:
    """
    Manage tool signatures and detect changes.
    
    Features:
    - SHA-512 signatures
    - Change detection
    - Whitelist/blacklist management
    - Fuzzy matching
    - Persistence
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize signature manager.
        
        Args:
            storage_path: Path to signature storage file
        """
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path.home() / '.secure-mcp' / 'signatures.json'
        
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing signatures
        self.signatures = self._load_signatures()
        
        # Track verification history
        self.verification_history: List[SignatureVerification] = []
    
    def _load_signatures(self) -> Dict:
        """Load existing signatures from storage"""
        
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Default structure
        return {
            'tools': {},  # tool_id -> ToolSignature
            'whitelist': [],  # List of whitelisted signatures
            'blacklist': [],  # List of blacklisted signatures
            'metadata': {
                'version': '2.0',
                'created': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
        }
    
    def _save_signatures(self):
        """Persist signatures to storage"""
        
        self.signatures['metadata']['last_updated'] = datetime.now().isoformat()
        
        with open(self.storage_path, 'w') as f:
            json.dump(self.signatures, f, indent=2, default=str)
    
    def calculate_signature(self, tool: Dict) -> str:
        """
        Calculate SHA-512 signature for tool.
        
        Args:
            tool: Tool definition
        
        Returns:
            Hex signature string
        """
        
        # Normalize tool data for consistent hashing
        normalized = {
            'name': tool.get('name', ''),
            'description': tool.get('description', ''),
            'parameters': self._normalize_parameters(tool.get('parameters', {})),
            'permissions': sorted(tool.get('permissions', [])),
            'code': tool.get('code', ''),  # Include actual code if available
            'version': tool.get('version', '')
        }
        
        # Create stable JSON representation
        content = json.dumps(normalized, sort_keys=True, ensure_ascii=True)
        
        # Calculate SHA-512
        return hashlib.sha512(content.encode('utf-8')).hexdigest()
    
    def _normalize_parameters(self, params: Any) -> Any:
        """Normalize parameters for consistent hashing"""
        
        if isinstance(params, dict):
            return {k: self._normalize_parameters(v) for k, v in sorted(params.items())}
        elif isinstance(params, list):
            return [self._normalize_parameters(item) for item in params]
        else:
            return params
    
    async def verify_tool(self, tool: Dict) -> SignatureVerification:
        """
        Verify tool signature and detect changes.
        
        Args:
            tool: Tool definition with optional server context
        
        Returns:
            Verification result
        """
        
        tool_name = tool.get('name', 'unknown')
        server_name = tool.get('server', 'unknown')
        tool_id = f"{server_name}:{tool_name}"
        
        current_sig = self.calculate_signature(tool)
        
        # Check blacklist first
        for blacklisted in self.signatures.get('blacklist', []):
            if blacklisted.get('signature') == current_sig:
                verification = SignatureVerification(
                    tool_name=tool_name,
                    signature=current_sig,
                    status='blacklisted',
                    threat_level='critical',
                    reason=blacklisted.get('reason', 'Tool is blacklisted')
                )
                self.verification_history.append(verification)
                return verification
        
        # Check whitelist
        for whitelisted in self.signatures.get('whitelist', []):
            if whitelisted.get('signature') == current_sig:
                verification = SignatureVerification(
                    tool_name=tool_name,
                    signature=current_sig,
                    status='whitelisted',
                    threat_level='safe',
                    reason='Tool is whitelisted'
                )
                self.verification_history.append(verification)
                return verification
        
        # Check known signatures
        if tool_id in self.signatures['tools']:
            stored = self.signatures['tools'][tool_id]
            
            if stored['signature'] == current_sig:
                # Known, unchanged tool
                stored['last_seen'] = datetime.now().isoformat()
                stored['times_seen'] = stored.get('times_seen', 1) + 1
                self._save_signatures()
                
                verification = SignatureVerification(
                    tool_name=tool_name,
                    signature=current_sig,
                    status='known',
                    threat_level='low'
                )
            else:
                # Tool has changed!
                verification = SignatureVerification(
                    tool_name=tool_name,
                    signature=current_sig,
                    status='modified',
                    changed=True,
                    threat_level='high',
                    previous_signature=stored['signature'],
                    last_seen=stored.get('last_seen'),
                    reason=f"Tool signature changed since {stored.get('last_seen', 'unknown')}"
                )
                
                # Check if it's a rug pull attack
                if stored.get('times_seen', 1) > 10:  # Been stable for a while
                    verification.threat_level = 'critical'
                    verification.reason = f"Possible rug pull attack - tool changed after {stored['times_seen']} uses"
                
                # Update stored signature
                stored['previous_signatures'] = stored.get('previous_signatures', [])
                stored['previous_signatures'].append({
                    'signature': stored['signature'],
                    'last_seen': stored.get('last_seen')
                })
                stored['signature'] = current_sig
                stored['last_seen'] = datetime.now().isoformat()
                self._save_signatures()
        else:
            # New tool
            self.signatures['tools'][tool_id] = {
                'signature': current_sig,
                'tool_name': tool_name,
                'server_name': server_name,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'times_seen': 1,
                'description': tool.get('description'),
                'parameters': tool.get('parameters')
            }
            self._save_signatures()
            
            verification = SignatureVerification(
                tool_name=tool_name,
                signature=current_sig,
                status='new',
                threat_level='medium',
                reason='First time seeing this tool'
            )
            
            # Find similar tools
            similar = await self.find_similar_tools(tool)
            if similar:
                verification.similar_tools = similar
                verification.reason += f" - Found {len(similar)} similar tools"
        
        self.verification_history.append(verification)
        return verification
    
    async def find_similar_tools(self, tool: Dict, threshold: float = 0.8) -> List[Dict]:
        """
        Find tools similar to the given one.
        
        Args:
            tool: Tool to compare
            threshold: Similarity threshold (0-1)
        
        Returns:
            List of similar tools with similarity scores
        """
        
        similar = []
        tool_desc = tool.get('description', '')
        tool_params = json.dumps(tool.get('parameters', {}))
        
        if not tool_desc:
            return similar
        
        # Use fuzzy matching on descriptions
        try:
            from rapidfuzz import fuzz
            
            for tool_id, stored_tool in self.signatures['tools'].items():
                stored_desc = stored_tool.get('description', '')
                
                if stored_desc:
                    # Compare descriptions
                    desc_similarity = fuzz.ratio(tool_desc, stored_desc) / 100.0
                    
                    # Compare parameters
                    stored_params = json.dumps(stored_tool.get('parameters', {}))
                    param_similarity = fuzz.ratio(tool_params, stored_params) / 100.0
                    
                    # Combined similarity
                    combined = (desc_similarity * 0.7 + param_similarity * 0.3)
                    
                    if combined >= threshold:
                        similar.append({
                            'tool_id': tool_id,
                            'tool_name': stored_tool.get('tool_name'),
                            'server_name': stored_tool.get('server_name'),
                            'similarity': combined,
                            'description_match': desc_similarity,
                            'parameter_match': param_similarity
                        })
            
            # Sort by similarity
            similar.sort(key=lambda x: x['similarity'], reverse=True)
            
        except ImportError:
            # Fallback to simple string comparison
            for tool_id, stored_tool in self.signatures['tools'].items():
                stored_desc = stored_tool.get('description', '')
                
                if stored_desc and tool_desc:
                    # Simple substring matching
                    if tool_desc in stored_desc or stored_desc in tool_desc:
                        similar.append({
                            'tool_id': tool_id,
                            'tool_name': stored_tool.get('tool_name'),
                            'server_name': stored_tool.get('server_name'),
                            'similarity': 0.5
                        })
        
        return similar[:5]  # Return top 5 matches
    
    async def whitelist_tool(self, signature: str, reason: str = ""):
        """Add tool signature to whitelist"""
        
        # Check if already whitelisted
        for item in self.signatures['whitelist']:
            if item.get('signature') == signature:
                return
        
        self.signatures['whitelist'].append({
            'signature': signature,
            'added': datetime.now().isoformat(),
            'reason': reason
        })
        
        self._save_signatures()
    
    async def blacklist_tool(self, signature: str, reason: str = ""):
        """Add tool signature to blacklist"""
        
        # Check if already blacklisted
        for item in self.signatures['blacklist']:
            if item.get('signature') == signature:
                return
        
        self.signatures['blacklist'].append({
            'signature': signature,
            'added': datetime.now().isoformat(),
            'reason': reason
        })
        
        self._save_signatures()
    
    async def remove_from_whitelist(self, signature: str):
        """Remove signature from whitelist"""
        
        self.signatures['whitelist'] = [
            item for item in self.signatures['whitelist']
            if item.get('signature') != signature
        ]
        
        self._save_signatures()
    
    async def remove_from_blacklist(self, signature: str):
        """Remove signature from blacklist"""
        
        self.signatures['blacklist'] = [
            item for item in self.signatures['blacklist']
            if item.get('signature') != signature
        ]
        
        self._save_signatures()
    
    async def get_report(self) -> Dict:
        """Generate signature database report"""
        
        tools_by_server = {}
        for tool_id, tool in self.signatures['tools'].items():
            server = tool.get('server_name', 'unknown')
            if server not in tools_by_server:
                tools_by_server[server] = 0
            tools_by_server[server] += 1
        
        # Find most frequently seen tools
        frequent_tools = sorted(
            self.signatures['tools'].items(),
            key=lambda x: x[1].get('times_seen', 0),
            reverse=True
        )[:10]
        
        # Find recently changed tools
        changed_tools = [
            tool for tool in self.signatures['tools'].values()
            if 'previous_signatures' in tool
        ]
        
        return {
            'total_tools': len(self.signatures['tools']),
            'whitelisted': len(self.signatures['whitelist']),
            'blacklisted': len(self.signatures['blacklist']),
            'tools_by_server': tools_by_server,
            'frequent_tools': [
                {
                    'name': t[1].get('tool_name'),
                    'server': t[1].get('server_name'),
                    'times_seen': t[1].get('times_seen', 0)
                }
                for t in frequent_tools
            ],
            'changed_tools_count': len(changed_tools),
            'last_updated': self.signatures['metadata'].get('last_updated'),
            'verification_history_count': len(self.verification_history)
        }
    
    def export_signatures(self, filepath: str):
        """Export signatures to file"""
        
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(self.signatures, f, indent=2, default=str)
    
    def import_signatures(self, filepath: str, merge: bool = True):
        """Import signatures from file"""
        
        with open(filepath, 'r') as f:
            imported = json.load(f)
        
        if merge:
            # Merge with existing
            self.signatures['tools'].update(imported.get('tools', {}))
            self.signatures['whitelist'].extend(imported.get('whitelist', []))
            self.signatures['blacklist'].extend(imported.get('blacklist', []))
        else:
            # Replace existing
            self.signatures = imported
        
        self._save_signatures()