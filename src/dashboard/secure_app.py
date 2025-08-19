#!/usr/bin/env python3
"""
SECURE VERSION of Mighty MCP Security Dashboard - FastAPI Version
This version includes proper security controls and input validation.
"""

import os
import sys
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import security middleware
from security_middleware import SecurityValidator, safe_error_handler, security_middleware

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer
from src.analyzers.database import AnalysisCacheDB
from src.configs.discovery import ConfigDiscovery
from src.policies.manager import PolicyManager
from src.signatures.manager import SignatureManager

app = FastAPI(
    title="Mighty MCP Security Dashboard (Secure)",
    description="Secure version with proper input validation and rate limiting",
    version="2.1.0"
)

# Add security middleware
app.middleware("http")(security_middleware)

# Add CORS middleware with strict settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],  # Only dev origins
    allow_credentials=False,  # Don't allow credentials
    allow_methods=["GET", "POST"],  # Only needed methods
    allow_headers=["Content-Type"],  # Only needed headers
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

# Check if LLM is available
try:
    from src.analyzers.llm.cerebras_analyzer import CerebrasAnalyzer
    cerebras_analyzer = CerebrasAnalyzer()
    LLM_AVAILABLE = True
except ImportError:
    cerebras_analyzer = None
    LLM_AVAILABLE = False

def get_db():
    """Get database connection for current thread"""
    return AnalysisCacheDB()

# SECURE scan modes with proper descriptions
SCAN_MODES = {
    "github_scan": {
        "name": "GitHub Repository Scanner",
        "description": "Analyze GitHub repositories for security threats",
        "capabilities": [
            "✅ Secure repository cloning",
            "✅ AST-based code analysis",
            "✅ 50+ threat pattern detection",
            "✅ Rate limited (3 scans per 5 minutes)"
        ],
        "security_notes": "Only github.com domains allowed, input validation enforced",
        "icon": "🐙"
    },
    "local_scan": {
        "name": "Local File/Directory Scanner",
        "description": "Scan files or directories with security controls",
        "capabilities": [
            "✅ Path traversal protection",
            "✅ Permission checking",
            "✅ Restricted to safe directories",
            "✅ Rate limited (5 scans per 5 minutes)"
        ],
        "security_notes": "Blocks system files, validates permissions, prevents directory traversal",
        "icon": "📁"
    }
}

@app.get("/")
async def index():
    """Serve the React app"""
    react_build = Path(__file__).parent / "static" / "dist" / "index.html"
    if react_build.exists():
        return FileResponse(react_build)
    else:
        raise HTTPException(status_code=404, detail="Dashboard not built. Run: cd src/dashboard && ./build.sh")

# Serve React app static files
react_static_dir = Path(__file__).parent / "static" / "dist"
if react_static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(react_static_dir / "assets")), name="react-assets")

@app.get("/api/scan-modes")
async def get_scan_modes():
    """Get information about available scan modes with security details"""
    return JSONResponse(content=SCAN_MODES)

@app.post("/api/scan/local")
async def scan_local_secure(request: Request, background_tasks: BackgroundTasks):
    """SECURE local file/directory scanner with input validation"""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")

    # Validate required fields
    target_path = data.get('target_path')
    if not target_path:
        raise HTTPException(status_code=400, detail="target_path is required")

    try:
        # SECURE path validation
        safe_path = SecurityValidator.validate_local_path(target_path)

        # SECURE option validation
        safe_options = SecurityValidator.validate_scan_options(data)

        # Use the analyzer with security controls
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=True,
            deep_scan=not safe_options.get('quick_mode', False),
            enable_llm=safe_options.get('enable_llm', False) and LLM_AVAILABLE,
            profile=safe_options.get('profile', 'production')
        )

        # Run analysis on validated path
        report = analyzer.analyze_repository(safe_path)

        # Store in database with validated data
        db = get_db()
        run_id = db.store_analysis_run(
            repo_url=f"file://{safe_path}",
            scan_type="local_secure",
            threat_level=report.threat_level,
            threat_score=report.threat_score * 100,
            total_threats=len(report.threats_found)
        )

        # Store threats with sanitized data
        for threat in report.threats_found:
            db.store_threat(
                run_id=run_id,
                attack_vector=str(threat.attack_vector)[:100],  # Limit length
                severity=str(threat.severity),
                confidence=threat.confidence,
                file_path=str(threat.file_path)[:500],  # Limit length
                line_numbers=threat.line_numbers[:10],  # Limit count
                description=str(threat.description)[:1000],  # Limit length
                evidence=threat.evidence[:5] if threat.evidence else []  # Limit count
            )

        return {
            'run_id': run_id,
            'target': os.path.basename(safe_path),  # Only return basename for security
            'threats': [{
                'attack_vector': str(t.attack_vector),
                'severity': t.severity,
                'confidence': f"{t.confidence * 100:.0f}%",
                'description': t.description,
                'file_path': os.path.basename(t.file_path),  # Only basename
                'line_numbers': t.line_numbers
            } for t in report.threats_found],
            'threat_score': f"{report.threat_score * 100:.1f}%",
            'threat_level': report.threat_level,
            'total_files': report.total_files_scanned,
            'total_lines': report.total_lines_analyzed,
            'analysis_complete': True,
            'security_notes': "Scan performed with security controls enabled"
        }

    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        raise safe_error_handler(e)

@app.post("/api/scan/github")
async def scan_github_secure(request: Request, background_tasks: BackgroundTasks):
    """SECURE GitHub repository scanner with URL validation"""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")

    # Validate required fields
    repo_url = data.get('repo_url')
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required")

    try:
        # SECURE URL validation
        safe_url = SecurityValidator.validate_github_url(repo_url)

        # SECURE option validation
        safe_options = SecurityValidator.validate_scan_options(data)

        # Use the analyzer with security controls
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=True,
            deep_scan=not safe_options.get('quick_mode', False),
            enable_llm=safe_options.get('enable_llm', False) and LLM_AVAILABLE,
            profile=safe_options.get('profile', 'production')
        )

        # Run analysis on validated URL
        report = analyzer.analyze_repository(safe_url)

        # Extract repo name safely
        import re
        match = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', safe_url)
        repo_name = f"{match.group(1)}/{match.group(2)}" if match else "unknown"

        # Store in database
        db = get_db()
        run_id = db.store_analysis_run(
            repo_url=safe_url,
            scan_type="github_secure",
            threat_level=report.threat_level,
            threat_score=report.threat_score * 100,
            total_threats=len(report.threats_found)
        )

        # Store threats with sanitized data
        for threat in report.threats_found:
            db.store_threat(
                run_id=run_id,
                attack_vector=str(threat.attack_vector)[:100],
                severity=str(threat.severity),
                confidence=threat.confidence,
                file_path=str(threat.file_path)[:500],
                line_numbers=threat.line_numbers[:10],
                description=str(threat.description)[:1000],
                evidence=threat.evidence[:5] if threat.evidence else []
            )

        return {
            'run_id': run_id,
            'repo': repo_name,
            'threats': [{
                'attack_vector': str(t.attack_vector),
                'severity': t.severity,
                'confidence': f"{t.confidence * 100:.0f}%",
                'description': t.description,
                'file_path': os.path.basename(t.file_path),  # Only basename for security
                'line_numbers': t.line_numbers
            } for t in report.threats_found],
            'threat_score': f"{report.threat_score * 100:.1f}%",
            'threat_level': report.threat_level,
            'confidence': f"{report.confidence * 100:.0f}%",
            'total_files': report.total_files_scanned,
            'total_lines': f"{report.total_lines_analyzed:,}",
            'analysis_complete': True,
            'security_notes': "Scan performed with URL validation and security controls"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise safe_error_handler(e)

@app.get("/api/stats")
async def get_stats_secure():
    """Get sanitized statistics"""
    try:
        db = get_db()
        stats = db.get_threat_statistics()

        # Get recent scans (sanitized)
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT r.run_id, r.scan_timestamp, r.threat_level, 
                   r.threat_score, r.total_threats, r.scan_type, r.llm_enabled
            FROM analysis_runs r
            ORDER BY r.scan_timestamp DESC
            LIMIT 10
        """)

        recent_scans = []
        for row in cursor.fetchall():
            recent_scans.append({
                'run_id': row['run_id'],
                'timestamp': row['scan_timestamp'],
                'threat_level': row['threat_level'],
                'threat_score': row['threat_score'],
                'total_threats': row['total_threats'],
                'scan_type': row['scan_type'],
                'llm_enabled': row['llm_enabled']
                # Note: No repo_url or file paths for security
            })

        return {
            'statistics': stats,
            'recent_scans': recent_scans,
            'scan_modes_available': len(SCAN_MODES),
            'llm_available': LLM_AVAILABLE,
            'security_features': {
                'rate_limiting': True,
                'input_validation': True,
                'path_traversal_protection': True,
                'url_validation': True
            }
        }

    except Exception as e:
        raise safe_error_handler(e)

@app.get("/api/run/{run_id}")
async def get_run_secure(run_id: str):
    """Get sanitized details of a specific analysis run"""

    # Validate run_id format (should be integer)
    try:
        int(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run ID format")

    try:
        db = get_db()
        data = db.export_to_json(run_id)

        # Sanitize sensitive information
        if 'repo_url' in data and data['repo_url'].startswith('file://'):
            # Don't expose full file paths
            data['repo_url'] = 'file://[sanitized]'

        # Sanitize threat file paths
        if 'threats' in data:
            for threat in data['threats']:
                if 'file_path' in threat:
                    threat['file_path'] = os.path.basename(threat['file_path'])

        return JSONResponse(content=data)
    except Exception as e:
        raise safe_error_handler(e)

# Catch-all route for React Router (SPA) - SECURE VERSION
@app.get("/{path:path}")
async def catch_all_secure(path: str):
    """Secure catch-all route to serve React app for SPA routing"""

    # Block suspicious paths
    suspicious_patterns = ['..', '.env', '.git', 'passwd', 'shadow', '.ssh']
    if any(pattern in path.lower() for pattern in suspicious_patterns):
        raise HTTPException(status_code=404, detail="Not found")

    # Skip API routes
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    # Serve React app
    react_build = Path(__file__).parent / "static" / "dist" / "index.html"
    if react_build.exists():
        return FileResponse(react_build)
    else:
        raise HTTPException(status_code=404, detail="Dashboard not found")

if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description='Secure MCP Security Dashboard')
    parser.add_argument('--port', type=int, default=8080, help='Port to run on')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind to (secure default)')
    args = parser.parse_args()

    print("🔒 Starting SECURE MCP Security Dashboard")
    print("🛡️  Security features enabled:")
    print("   - Input validation and sanitization")
    print("   - Rate limiting")
    print("   - Path traversal protection")
    print("   - URL validation")
    print("   - Error information disclosure prevention")
    print(f"🌐 Dashboard: http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
