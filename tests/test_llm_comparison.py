#!/usr/bin/env python3
"""
LLM Comparison Test Script
Evaluates security analysis performance with:
1. Static analysis only
2. LLM analysis only  
3. Combined static + LLM analysis
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


def run_analysis(repo_url: str, enable_llm: bool = False, quick_mode: bool = False) -> dict[str, Any]:
    """Run security analysis and return results with timing"""
    start_time = time.time()

    analyzer = ComprehensiveMCPAnalyzer(
        verbose=True,
        deep_scan=not quick_mode,
        enable_llm=enable_llm
    )

    try:
        report = analyzer.analyze_repository(repo_url)
        elapsed_time = time.time() - start_time

        # Convert report to dict for comparison
        report_dict = {
            'threat_level': report.threat_level,
            'threat_score': report.threat_score,
            'confidence': report.confidence,
            'ml_score': report.ml_maliciousness_score,
            'total_threats': len(report.threats_found),
            'critical_threats': sum(1 for t in report.threats_found if str(t.severity) == 'CRITICAL'),
            'high_threats': sum(1 for t in report.threats_found if str(t.severity) == 'HIGH'),
            'medium_threats': sum(1 for t in report.threats_found if str(t.severity) == 'MEDIUM'),
            'low_threats': sum(1 for t in report.threats_found if str(t.severity) == 'LOW'),
            'analysis_time': elapsed_time,
            'files_scanned': report.total_files_scanned,
            'lines_analyzed': report.total_lines_analyzed
        }

        # Add LLM-specific results if available
        if hasattr(report, 'combined_ai_assessment') and report.combined_ai_assessment:
            report_dict['llm_risk'] = report.llm_analysis.get('aggregate_risk', 0)
            report_dict['ai_verdict'] = report.combined_ai_assessment.get('verdict', 'Unknown')
            report_dict['ai_confidence'] = report.combined_ai_assessment.get('confidence', 0)
            report_dict['ai_files_analyzed'] = report.combined_ai_assessment.get('files_analyzed', 0)

        return {
            'success': True,
            'report': report_dict,
            'raw_report': report
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'analysis_time': time.time() - start_time
        }


def compare_results(static_result: dict, llm_result: dict) -> dict[str, Any]:
    """Compare results from different analysis modes"""
    comparison = {
        'agreement': {},
        'differences': {},
        'performance': {}
    }

    if not (static_result['success'] and llm_result['success']):
        return {
            'error': 'One or both analyses failed',
            'static_success': static_result['success'],
            'llm_success': llm_result['success']
        }

    static = static_result['report']
    llm = llm_result['report']

    # Check agreement on threat level
    comparison['agreement']['threat_level'] = static['threat_level'] == llm['threat_level']
    comparison['agreement']['threat_score_diff'] = abs(static['threat_score'] - llm['threat_score'])

    # Compare threat counts
    comparison['differences']['total_threats'] = {
        'static': static['total_threats'],
        'llm': llm['total_threats'],
        'difference': llm['total_threats'] - static['total_threats']
    }

    comparison['differences']['critical_threats'] = {
        'static': static['critical_threats'],
        'llm': llm['critical_threats'],
        'difference': llm['critical_threats'] - static['critical_threats']
    }

    # Performance comparison
    comparison['performance']['time'] = {
        'static': static['analysis_time'],
        'llm': llm['analysis_time'],
        'overhead': llm['analysis_time'] - static['analysis_time']
    }

    # LLM-specific insights
    if 'llm_risk' in llm:
        comparison['llm_insights'] = {
            'llm_risk_score': llm['llm_risk'],
            'ai_verdict': llm['ai_verdict'],
            'ai_confidence': llm['ai_confidence'],
            'files_analyzed_by_ai': llm['ai_files_analyzed']
        }

    return comparison


def print_comparison_report(comparison: dict, static_result: dict, llm_result: dict):
    """Print formatted comparison report"""
    print("\n" + "="*70)
    print("ANALYSIS COMPARISON REPORT")
    print("="*70)

    if 'error' in comparison:
        print(f"\n❌ Error: {comparison['error']}")
        return

    # Agreement metrics
    print("\n📊 AGREEMENT METRICS")
    print(f"   Threat Level Match: {'✅ Yes' if comparison['agreement']['threat_level'] else '❌ No'}")
    print(f"   Threat Score Difference: {comparison['agreement']['threat_score_diff']:.2%}")

    # Threat detection comparison
    print("\n🔍 THREAT DETECTION")
    diff = comparison['differences']['total_threats']
    print("   Total Threats:")
    print(f"      Static Only: {diff['static']}")
    print(f"      With LLM: {diff['llm']}")
    print(f"      Difference: {'+' if diff['difference'] > 0 else ''}{diff['difference']}")

    crit_diff = comparison['differences']['critical_threats']
    if crit_diff['difference'] != 0:
        print("   Critical Threats:")
        print(f"      Static Only: {crit_diff['static']}")
        print(f"      With LLM: {crit_diff['llm']}")
        print(f"      Difference: {'+' if crit_diff['difference'] > 0 else ''}{crit_diff['difference']}")

    # Performance metrics
    print("\n⚡ PERFORMANCE")
    perf = comparison['performance']['time']
    print(f"   Static Analysis: {perf['static']:.2f}s")
    print(f"   With LLM: {perf['llm']:.2f}s")
    print(f"   Overhead: {perf['overhead']:.2f}s ({(perf['overhead']/perf['static']*100):.1f}% increase)")

    # LLM-specific insights
    if 'llm_insights' in comparison:
        print("\n🤖 LLM INSIGHTS")
        insights = comparison['llm_insights']
        print(f"   LLM Risk Score: {insights['llm_risk_score']:.2%}")
        print(f"   AI Verdict: {insights['ai_verdict']}")
        print(f"   AI Confidence: {insights['ai_confidence']:.2%}")
        print(f"   Files Analyzed by AI: {insights['files_analyzed_by_ai']}")

    # Summary
    print("\n📋 SUMMARY")
    static_report = static_result['report']
    llm_report = llm_result['report']

    print("\n   Static Analysis Only:")
    print(f"      Threat Level: {static_report['threat_level']}")
    print(f"      Threat Score: {static_report['threat_score']:.2%}")
    print(f"      Confidence: {static_report['confidence']:.2%}")

    print("\n   With LLM Enhancement:")
    print(f"      Threat Level: {llm_report['threat_level']}")
    print(f"      Threat Score: {llm_report['threat_score']:.2%}")
    print(f"      Confidence: {llm_report['confidence']:.2%}")

    # Recommendation
    print("\n💡 RECOMMENDATION:")
    if comparison['differences']['total_threats']['difference'] > 0:
        print("   LLM analysis discovered additional threats not found by static analysis.")
        print("   Consider using LLM for comprehensive security assessment.")
    elif perf['overhead'] < 30:
        print("   LLM overhead is reasonable. Recommended for thorough analysis.")
    else:
        print("   Significant performance overhead. Use LLM for critical assessments only.")


def main():
    """Main comparison test"""
    if len(sys.argv) < 2:
        # Run a default test on current directory when no args provided
        print("\n🔬 LLM Comparison Test - Running default test on current directory")
        repo_url = "."
        quick_mode = True
    else:
        repo_url = sys.argv[1]
        quick_mode = '--quick' in sys.argv

    # Check for API key
    if not os.environ.get("CEREBRAS_API_KEY"):
        print("\n⚠️  Warning: CEREBRAS_API_KEY not set. LLM analysis will be skipped.")
        print("   To enable LLM analysis, set your API key:")
        print("   export CEREBRAS_API_KEY='your-api-key'")
        print()

    print("\n" + "="*70)
    print("🔬 RUNNING COMPARISON TEST")
    print("="*70)
    print(f"Repository: {repo_url}")
    print(f"Mode: {'Quick' if quick_mode else 'Deep'} Scan")
    print("="*70)

    # Run static analysis only
    print("\n1️⃣  Running static analysis only...")
    static_result = run_analysis(repo_url, enable_llm=False, quick_mode=quick_mode)

    if not static_result['success']:
        print(f"❌ Static analysis failed: {static_result.get('error', 'Unknown error')}")
        sys.exit(1)

    print(f"✅ Static analysis complete in {static_result['report']['analysis_time']:.2f}s")

    # Run with LLM if API key is available
    if os.environ.get("CEREBRAS_API_KEY"):
        print("\n2️⃣  Running analysis with LLM enhancement...")
        llm_result = run_analysis(repo_url, enable_llm=True, quick_mode=quick_mode)

        if not llm_result['success']:
            print(f"❌ LLM analysis failed: {llm_result.get('error', 'Unknown error')}")
        else:
            print(f"✅ LLM analysis complete in {llm_result['report']['analysis_time']:.2f}s")

            # Compare results
            print("\n3️⃣  Comparing results...")
            comparison = compare_results(static_result, llm_result)

            # Print comparison report
            print_comparison_report(comparison, static_result, llm_result)

            # Save detailed comparison
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            comparison_file = f"comparison_{timestamp}.json"

            with open(comparison_file, 'w') as f:
                json.dump({
                    'repo_url': repo_url,
                    'timestamp': timestamp,
                    'static_result': static_result['report'],
                    'llm_result': llm_result['report'],
                    'comparison': comparison
                }, f, indent=2, default=str)

            print(f"\n📁 Detailed comparison saved to: {comparison_file}")
    else:
        print("\n⚠️  Skipping LLM comparison (no API key)")
        print("\nStatic Analysis Results:")
        print(f"   Threat Level: {static_result['report']['threat_level']}")
        print(f"   Threat Score: {static_result['report']['threat_score']:.2%}")
        print(f"   Total Threats: {static_result['report']['total_threats']}")
        print(f"   Analysis Time: {static_result['report']['analysis_time']:.2f}s")


if __name__ == "__main__":
    main()
