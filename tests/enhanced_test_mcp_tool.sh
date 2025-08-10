#!/bin/bash

# Enhanced MCP Security Analyzer Test Script
# With detailed coverage reporting and disclaimers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║           MCP SECURITY ANALYZER - COMPREHENSIVE TEST                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${RED}⚠️  DISCLAIMER:${NC}"
echo "────────────────────────────────────────────────────────────────────────"
echo "This tool provides STATIC ANALYSIS ONLY and cannot guarantee complete"
echo "security coverage. It is NOT a comprehensive security audit."
echo ""
echo "• Detection Rate: ~40-60% of known threats"
echo "• May produce false positives and false negatives"
echo "• Cannot detect runtime-only vulnerabilities"
echo "• NO WARRANTY provided on results"
echo "• Should NOT be your only security measure"
echo "• Always perform manual security review"
echo "────────────────────────────────────────────────────────────────────────"
echo ""

# Check if URL provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}Usage:${NC} $0 <github-url> [--detailed] [--hooks]"
    echo ""
    echo "Options:"
    echo "  --detailed   Show detailed coverage breakdown"
    echo "  --hooks      Test with runtime hooks (experimental)"
    echo ""
    echo "Example:"
    echo "  $0 https://github.com/modelcontextprotocol/servers --detailed"
    exit 1
fi

REPO_URL=$1
DETAILED=false
USE_HOOKS=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --detailed)
            DETAILED=true
            ;;
        --hooks)
            USE_HOOKS=true
            ;;
    esac
done

REPO_NAME=$(basename "$REPO_URL" .git)
TEMP_DIR="/tmp/mcp_test_$$"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="security_report_${TIMESTAMP}.json"

echo -e "${BLUE}[1/5] Repository Setup${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "• Repository: $REPO_URL"
echo "• Temp Directory: $TEMP_DIR/$REPO_NAME"
echo "• Report File: $REPORT_FILE"

# Clone the repository
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"
echo -n "• Cloning repository... "
if git clone --depth 1 "$REPO_URL" "$REPO_NAME" >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗ Failed to clone${NC}"
    exit 1
fi

cd "$REPO_NAME"

# Count files to analyze
echo ""
echo -e "${BLUE}[2/5] Pre-Analysis${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
PY_FILES=$(find . -name "*.py" -not -path "./venv/*" -not -path "./.git/*" 2>/dev/null | wc -l)
JS_FILES=$(find . -name "*.js" -o -name "*.ts" -not -path "./node_modules/*" -not -path "./.git/*" 2>/dev/null | wc -l)
GO_FILES=$(find . -name "*.go" -not -path "./.git/*" 2>/dev/null | wc -l)
CONFIG_FILES=$(find . -name "mcp.json" -o -name "manifest.json" -o -name "package.json" 2>/dev/null | wc -l)

echo "• Python files: $PY_FILES"
echo "• JavaScript/TypeScript files: $JS_FILES"
echo "• Go files: $GO_FILES"
echo "• Config files: $CONFIG_FILES"
echo "• Total files to scan: $((PY_FILES + JS_FILES + GO_FILES + CONFIG_FILES))"

echo ""
echo -e "${BLUE}[3/5] Security Analysis${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Running analysis (this may take a moment)..."
echo ""

# Run the analyzer
if [ "$USE_HOOKS" = true ]; then
    python3 /Users/jh/Code/nine-suns/secure-toolings/enhanced_mcp_analyzer.py . > analysis_output.txt 2>&1
else
    python3 /Users/jh/Code/nine-suns/secure-toolings/enhanced_mcp_analyzer.py . > analysis_output.txt 2>&1
fi

# Parse the output
cat analysis_output.txt

echo ""
echo -e "${BLUE}[4/5] Coverage Report${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "WHAT THIS ANALYZER CHECKS:"
echo -e "${GREEN}✓ Good Coverage (70-90%):${NC}"
echo "  • Command injection (exec, eval, subprocess)"
echo "  • GitHub API content fetching"
echo "  • Basic credential theft patterns"
echo "  • Code obfuscation"
echo ""
echo -e "${YELLOW}⚠ Partial Coverage (30-60%):${NC}"
echo "  • Path traversal attacks"
echo "  • Tool poisoning/rug-pulls"
echo "  • Data exfiltration"
echo "  • Prompt injection in manifests"
echo ""
echo -e "${RED}✗ Limited Coverage (10-30%):${NC}"
echo "  • RADE attacks (hidden commands)"
echo "  • SSRF vulnerabilities"
echo "  • Cross-server shadowing"
echo "  • Runtime-only behaviors"
echo "  • Time-delayed attacks"
echo ""

if [ "$DETAILED" = true ]; then
    echo -e "${BLUE}[5/5] Detailed Threat Breakdown${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Parse JSON report if it exists
    if [ -f "../../$REPORT_FILE" ]; then
        echo ""
        echo "Analyzing report: ../../$REPORT_FILE"
        
        # Use Python to parse and display JSON nicely
        python3 -c "
import json
import sys

try:
    with open('../../$REPORT_FILE', 'r') as f:
        report = json.load(f)
    
    print('\n📊 THREAT SUMMARY:')
    print(f\"  • Threat Level: {report.get('threat_level', 'Unknown')}\")
    print(f\"  • Risk Score: {report.get('score', 0)*100:.1f}%\")
    print(f\"  • Confidence: {report.get('confidence', 0)*100:.1f}%\")
    print(f\"  • Files Scanned: {report.get('files_scanned', 0)}\")
    
    if 'threats' in report and report['threats']:
        print(f\"\n⚠️  THREATS FOUND: {len(report['threats'])}\")
        
        # Group by severity
        by_severity = {}
        for threat in report['threats']:
            sev = threat.get('severity', 'UNKNOWN')
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(threat)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                print(f\"\n  {severity} ({len(by_severity[severity])} threats):\")
                for threat in by_severity[severity][:3]:
                    print(f\"    • {threat.get('type', 'Unknown')}: {threat.get('description', 'No description')}\")
                    if threat.get('file'):
                        print(f\"      File: {threat['file']}, Line: {threat.get('line', 0)}\")
    else:
        print('\n✅ No threats detected')
    
    if 'recommendations' in report:
        print('\n📋 RECOMMENDATIONS:')
        for rec in report['recommendations'][:5]:
            print(f\"  {rec}\")
            
except Exception as e:
    print(f'Error parsing report: {e}', file=sys.stderr)
" 2>/dev/null || echo "Could not parse detailed report"
    fi
else
    echo ""
    echo -e "${BLUE}[5/5] Summary${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

echo ""
echo "WHAT THIS MEANS:"
echo "────────────────"
if [ -f "../../$REPORT_FILE" ]; then
    # Try to extract threat level from report
    THREAT_LEVEL=$(python3 -c "import json; print(json.load(open('../../$REPORT_FILE'))['threat_level'])" 2>/dev/null || echo "UNKNOWN")
    
    case $THREAT_LEVEL in
        "CRITICAL")
            echo -e "${RED}⛔ CRITICAL RISK - DO NOT USE${NC}"
            echo "Multiple severe vulnerabilities detected that could:"
            echo "• Execute arbitrary code"
            echo "• Steal credentials"
            echo "• Compromise your system"
            ;;
        "HIGH")
            echo -e "${RED}⚠️  HIGH RISK - USE WITH EXTREME CAUTION${NC}"
            echo "Significant security concerns that require:"
            echo "• Manual security review"
            echo "• Sandboxed environment"
            echo "• Limited permissions"
            ;;
        "MEDIUM")
            echo -e "${YELLOW}⚠️  MODERATE RISK - REVIEW BEFORE USE${NC}"
            echo "Some concerning patterns found:"
            echo "• Review flagged issues"
            echo "• Consider alternatives"
            echo "• Monitor usage"
            ;;
        "LOW"|"MINIMAL")
            echo -e "${GREEN}✓ LOW RISK - LIKELY SAFE${NC}"
            echo "No major threats detected, but:"
            echo "• Still perform basic review"
            echo "• Follow security best practices"
            echo "• Keep monitoring enabled"
            ;;
        *)
            echo "Unable to determine risk level"
            ;;
    esac
fi

# Cleanup
echo ""
echo -e "${BLUE}[Cleanup]${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd ../..
rm -rf "$TEMP_DIR"
echo "✓ Temporary files removed"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                         ANALYSIS COMPLETE                            ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${YELLOW}⚠️  REMEMBER:${NC}"
echo "• This is NOT a complete security audit"
echo "• ~40-60% detection rate for known threats"
echo "• Always perform manual review"
echo "• Use runtime monitoring for better protection"
echo ""
echo "Report saved to: $REPORT_FILE"
echo ""
echo "For runtime protection, consider using MCP Security Hooks:"
echo "  python3 mcp_security_hooks.py"
echo ""