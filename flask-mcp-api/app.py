#!/usr/bin/env python3
"""
Flask API for MCP Security Analyzer
Provides HTTP endpoint to analyze GitHub repositories with optional LLM support
"""

import os
import sys
import json
import tempfile
import traceback
from pathlib import Path
from datetime import datetime
from dataclasses import asdict
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Add parent directory to path to import analyzer modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the MCP analyzer and report formatter
from analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer, SecurityReport
from analyzers.report_formatter import ComprehensiveReportFormatter

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size
app.config['JSON_SORT_KEYS'] = False


def format_assessment_summary(report: SecurityReport) -> Dict[str, Any]:
    """
    Format the assessment summary similar to the CLI output
    """
    # Count threats by severity
    critical_count = sum(1 for t in report.threats_found 
                        if 'CRITICAL' in str(t.severity))
    high_count = sum(1 for t in report.threats_found 
                    if 'HIGH' in str(t.severity))
    medium_count = sum(1 for t in report.threats_found 
                      if 'MEDIUM' in str(t.severity))
    low_count = sum(1 for t in report.threats_found 
                   if 'LOW' in str(t.severity))
    
    # Determine overall risk level
    if report.threat_score >= 0.8:
        risk_level = "CRITICAL"
        risk_color = "🔴"
        verdict = "⛔ DO NOT USE - Critical threats that will compromise your system"
        verdict_color = "🔴"
    elif report.threat_score >= 0.6:
        risk_level = "HIGH"
        risk_color = "🔴"
        verdict = "⚠️ HIGH RISK - Thorough review required, use only in isolated environment"
        verdict_color = "🟡"
    elif report.threat_score >= 0.4:
        risk_level = "MEDIUM"
        risk_color = "🟡"
        verdict = "⚠️ MODERATE RISK - Review issues and use with enhanced monitoring"
        verdict_color = "🟡"
    elif report.threat_score >= 0.2:
        risk_level = "LOW"
        risk_color = "🟢"
        verdict = "✓ LOW RISK - Standard security practices recommended"
        verdict_color = "🟢"
    else:
        risk_level = "MINIMAL"
        risk_color = "🟢"
        verdict = "✅ SAFE - No significant threats detected"
        verdict_color = "🟢"
    
    # Get AI assessment
    ai_verdict = report.combined_ai_assessment.get('verdict', 'Unknown') if report.combined_ai_assessment else 'Not analyzed'
    ai_risk = report.combined_ai_assessment.get('combined_risk', 0) if report.combined_ai_assessment else 0
    ai_files_analyzed = report.combined_ai_assessment.get('files_analyzed', 0) if report.combined_ai_assessment else 0
    ai_critical_findings = report.combined_ai_assessment.get('critical_findings', 0) if report.combined_ai_assessment else 0
    
    summary = {
        "final_assessment": {
            "overall_risk_assessment": risk_level,
            "risk_indicator": risk_color,
            "threat_score": f"{report.threat_score:.1%}",
            "confidence_level": f"{report.confidence:.1%}"
        },
        "key_findings": {
            "total_threats_identified": len(report.threats_found),
            "severity_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            }
        },
        "ai_assessment": {
            "verdict": ai_verdict,
            "combined_risk": f"{ai_risk:.1%}",
            "files_analyzed": ai_files_analyzed,
            "critical_findings": ai_critical_findings
        },
        "final_verdict": {
            "verdict": verdict,
            "indicator": verdict_color,
            "message": f"{verdict_color} {verdict}"
        },
        "formatted_output": f"""
================================================================================
📋 FINAL ASSESSMENT & SUMMARY
================================================================================

{risk_color} Overall Risk Assessment: {risk_level}
   • Threat Score: {report.threat_score:.1%}
   • Confidence Level: {report.confidence:.1%}

📊 Key Findings:
   • Total Threats Identified: {len(report.threats_found)}
   • Severity Distribution:
     - Critical: {critical_count}
     - High: {high_count}
     - Medium: {medium_count}
     - Low: {low_count}

🤖 AI Assessment:
   • AI Verdict: {ai_verdict}
   • Combined AI Risk: {ai_risk:.1%}
   • Files Analyzed by AI: {ai_files_analyzed}
   • Critical AI Findings: {ai_critical_findings}

💡 Final Verdict:
   {verdict}
   {verdict_color} {'Critical security issues detected' if risk_level == 'CRITICAL' else 
                    'High-risk issues need attention' if risk_level == 'HIGH' else
                    'Several security issues need attention' if risk_level == 'MEDIUM' else
                    'Minor issues detected' if risk_level == 'LOW' else
                    'Repository appears safe'}
"""
    }
    
    return summary


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "flask-mighty-mcp-server-security",
        "version": "0.1.0"
    })


@app.route('/analyze', methods=['POST'])
def analyze_repository():
    """
    Main endpoint to analyze a repository
    
    Expected JSON payload:
    {
        "github_url": "https://github.com/user/repo" or "/path/to/local/repo",
        "llm": true/false (optional, default: false),
        "quick": true/false (optional, default: false)
    }
    
    Returns the complete analysis report with:
    - All threats found (as shown in your example)
    - Summary assessment
    - AI analysis results
    - Complete JSON report data
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                "error": "No JSON data provided",
                "message": "Please provide a JSON payload with 'github_url' field"
            }), 400
        
        github_url = data.get('github_url')
        if not github_url:
            return jsonify({
                "error": "Missing required field",
                "message": "Please provide 'github_url' in the request body"
            }), 400
        
        # Get optional parameters
        enable_llm = data.get('llm', False)
        quick_mode = data.get('quick', False)
        
        # Log the analysis request
        print(f"\n📊 Starting analysis for: {github_url}")
        print(f"   LLM enabled: {enable_llm}")
        print(f"   Quick mode: {quick_mode}")
        
        # Check for Cerebras API key if LLM is enabled
        if enable_llm:
            api_key = os.environ.get("CEREBRAS_API_KEY")
            if not api_key:
                # Try loading from .env file in parent directory
                env_file = Path(__file__).parent.parent / '.env'
                if env_file.exists():
                    load_dotenv(env_file)
                    api_key = os.environ.get("CEREBRAS_API_KEY")
            
            if not api_key:
                return jsonify({
                    "error": "LLM configuration error",
                    "message": "CEREBRAS_API_KEY not found. Please set it in environment variables or .env file"
                }), 400
        
        # Create analyzer instance
        analyzer = ComprehensiveMCPAnalyzer(
            verbose=True,
            deep_scan=not quick_mode,
            enable_llm=enable_llm
        )
        
        # Run analysis
        print("🔍 Running security analysis...")
        report = analyzer.analyze_repository(github_url)
        
        # Convert report to dictionary - this preserves the exact structure
        report_dict = asdict(report)
        
        # Convert enums to strings for JSON serialization (keeping the format you showed)
        for threat in report_dict['threats_found']:
            # Convert attack_vector enum to string format like "AttackVector.OBFUSCATION"
            if hasattr(threat.get('attack_vector'), 'value'):
                threat['attack_vector'] = f"AttackVector.{threat['attack_vector'].name}"
            elif 'attack_vector' in threat and not threat['attack_vector'].startswith('AttackVector.'):
                threat['attack_vector'] = f"AttackVector.{threat['attack_vector']}"
            
            # Convert severity enum to string format like "ThreatSeverity.MEDIUM"
            if hasattr(threat.get('severity'), 'value'):
                threat['severity'] = f"ThreatSeverity.{threat['severity'].name}"
            elif 'severity' in threat and not threat['severity'].startswith('ThreatSeverity.'):
                threat['severity'] = f"ThreatSeverity.{threat['severity']}"
        
        # Generate formatted summary
        summary = format_assessment_summary(report)
        
        # Create the exact response structure with all the data from the report
        response = {
            "status": "success",
            "repository": github_url,
            "scan_timestamp": report.scan_timestamp,
            
            # Include the formatted summary (like shown when running locally)
            "assessment_summary": summary['formatted_output'],
            
            # Include ALL the raw data from the report (exactly as in the JSON files)
            "threat_level": report.threat_level,
            "threat_score": report.threat_score,
            "confidence": report.confidence,
            "sha512_fingerprint": report.sha512_fingerprint,
            "sha3_512_fingerprint": report.sha3_512_fingerprint,
            "file_fingerprints": report_dict['file_fingerprints'],
            "merkle_root": report.merkle_root,
            
            # The complete threats_found array (as shown in your example)
            "threats_found": report_dict['threats_found'],
            
            # Data flows and behavior patterns
            "data_flows": report_dict['data_flows'],
            "behavior_patterns": report_dict['behavior_patterns'],
            
            # Statistics
            "total_files_scanned": report.total_files_scanned,
            "total_lines_analyzed": report.total_lines_analyzed,
            "languages_detected": report.languages_detected,
            
            # Dependencies
            "dependencies": report_dict['dependencies'],
            "vulnerable_dependencies": report_dict['vulnerable_dependencies'],
            
            # Recommendations and mitigations
            "recommendations": report.recommendations,
            "mitigations": report.mitigations,
            
            # ML and LLM analysis results
            "ml_maliciousness_score": report.ml_maliciousness_score,
            "ml_explanations": report.ml_explanations,
            "llm_analysis": report_dict['llm_analysis'],
            "advanced_ml_analysis": report_dict['advanced_ml_analysis'],
            "combined_ai_assessment": report_dict['combined_ai_assessment']
        }
        
        # Save complete report to file
        reports_dir = Path(__file__).parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if github_url.startswith(('http://', 'https://')):
            # Extract repo name from URL
            parts = github_url.rstrip('/').split('/')
            repo_name = f"{parts[-2]}-{parts[-1]}" if len(parts) >= 2 else "unknown"
        else:
            # Local path
            repo_name = Path(github_url).name or "local"
        
        report_filename = f"api_report_{repo_name}_{timestamp}.json"
        report_path = reports_dir / report_filename
        
        with open(report_path, 'w') as f:
            json.dump(response, f, indent=2, default=str)
        
        print(f"✅ Analysis complete. Report saved to: {report_path}")
        
        return jsonify(response), 200
        
    except Exception as e:
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        
        print(f"❌ Error during analysis: {error_msg}")
        print(traceback_str)
        
        return jsonify({
            "status": "error",
            "error": error_msg,
            "traceback": traceback_str,
            "message": "An error occurred during analysis. Please check the logs for details."
        }), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with API documentation"""
    return jsonify({
        "service": "Flask Mighty MCP Server Security API",
        "version": "0.1.0",
        "endpoints": {
            "/": "This documentation",
            "/health": "Health check endpoint",
            "/analyze": {
                "method": "POST",
                "description": "Analyze a GitHub repository or local directory",
                "payload": {
                    "github_url": "Required - GitHub URL or local path",
                    "llm": "Optional - Enable LLM analysis (default: false)",
                    "quick": "Optional - Enable quick mode (default: false)"
                },
                "example": {
                    "github_url": "https://github.com/user/repo",
                    "llm": True,
                    "quick": False
                }
            }
        },
        "environment_variables": {
            "CEREBRAS_API_KEY": "Required for LLM analysis"
        }
    })


if __name__ == '__main__':
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
    ================================================
    🚀 Flask Mighty MCP Server Security API
    ================================================
    
    Server running on: http://localhost:{port}
    
    Endpoints:
    - GET  /         : API documentation
    - GET  /health   : Health check
    - POST /analyze  : Analyze repository
    
    Example usage:
    curl -X POST http://localhost:{port}/analyze \\
      -H "Content-Type: application/json" \\
      -d '{{"github_url": "https://github.com/user/repo", "llm": true}}'
    
    ================================================
    """)
    
    # Run Flask app
    app.run(host='0.0.0.0', port=port, debug=True)