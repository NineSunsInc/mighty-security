#!/usr/bin/env python3
"""
Comprehensive Report Formatter for MCP Security Analyzer
Generates detailed, structured security reports with multiple sections
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict
import json
import textwrap

class ComprehensiveReportFormatter:
    """Generate detailed security analysis reports"""
    
    def __init__(self):
        self.width = 80
        self.indent = "   "
        
    def format_report(self, report: Any) -> str:
        """Generate comprehensive formatted report"""
        sections = []
        
        # Header
        sections.append(self._format_header(report))
        
        # Risk Assessment Matrix - FIRST to show actual findings
        sections.append(self._format_risk_matrix(report))
        
        # Detailed Threat Analysis - Show what was found
        sections.append(self._format_threat_analysis(report))
        
        # AI Analysis Results (if available)
        if hasattr(report, 'llm_analysis') and report.llm_analysis:
            sections.append(self._format_ai_analysis(report))
        
        # Data Flow Analysis (if available)
        if hasattr(report, 'data_flows') and report.data_flows:
            sections.append(self._format_data_flows(report))
        
        # Dependency Analysis
        if hasattr(report, 'vulnerable_dependencies') and report.vulnerable_dependencies:
            sections.append(self._format_dependencies(report))
        
        # Code Quality Metrics
        sections.append(self._format_code_metrics(report))
        
        # Recommendations & Mitigations
        sections.append(self._format_recommendations(report))
        
        # Technical Details
        sections.append(self._format_technical_details(report))
        
        # Executive Summary - LAST, after all analysis is complete
        sections.append(self._format_executive_summary(report))
        
        return "\n\n".join(filter(None, sections))
    
    def _format_header(self, report: Any) -> str:
        """Format report header"""
        lines = []
        lines.append("=" * self.width)
        lines.append("🔒 COMPREHENSIVE SECURITY ANALYSIS REPORT")
        lines.append("=" * self.width)
        lines.append(f"Repository: {report.repository_url}")
        lines.append(f"Scan Date: {datetime.fromisoformat(report.scan_timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Analysis Mode: {'Deep Scan' if hasattr(report, 'deep_scan') else 'Standard'}")
        if hasattr(report, 'llm_analysis') and report.llm_analysis:
            lines.append(f"AI-Enhanced: ✅ (Cerebras GPT-OSS-120B)")
        lines.append("=" * self.width)
        return "\n".join(lines)
    
    def _format_executive_summary(self, report: Any) -> str:
        """Format final assessment and summary section"""
        lines = []
        lines.append("=" * self.width)
        lines.append("📋 FINAL ASSESSMENT & SUMMARY")
        lines.append("=" * self.width)
        
        # Overall verdict with explanations
        threat_emoji = self._get_threat_emoji(report.threat_level)
        lines.append(f"\n{threat_emoji} Overall Risk Assessment: {report.threat_level}")
        lines.append(f"{self.indent}• Threat Score: {report.threat_score:.1%} (combined maliciousness rating)")
        lines.append(f"{self.indent}• Confidence Level: {report.confidence:.1%} (analysis coverage & certainty)")
        
        # CRITICAL WARNING if any critical threats exist
        critical_count = sum(1 for t in report.threats_found if str(t.severity) == 'ThreatSeverity.CRITICAL' or str(t.severity) == 'CRITICAL')
        if critical_count > 0:
            lines.append(f"\n🚨 CRITICAL SECURITY ALERT 🚨")
            lines.append(f"{self.indent}⛔ {critical_count} CRITICAL severity threat(s) detected!")
            lines.append(f"{self.indent}⚠️  This code poses IMMEDIATE security risks!")
            lines.append(f"{self.indent}🔴 DO NOT USE IN PRODUCTION")
        
        # Key findings
        lines.append(f"\n📊 Key Findings:")
        lines.append(f"{self.indent}• Total Threats Identified: {len(report.threats_found)}")
        
        # Count threats by severity
        severity_counts = defaultdict(int)
        for threat in report.threats_found:
            severity = threat.severity if hasattr(threat, 'severity') else 'UNKNOWN'
            severity_counts[severity] += 1
        
        if severity_counts:
            lines.append(f"{self.indent}• Severity Distribution:")
            severity_info = {
                'CRITICAL': '🔴 immediate compromise',
                'HIGH': '🟠 significant risk',
                'MEDIUM': '🟡 potential vulnerability',
                'LOW': '🟢 minor concern',
                'INFO': 'ℹ️ informational'
            }
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in severity_counts:
                    info = severity_info.get(severity, '')
                    lines.append(f"{self.indent}  - {severity}: {severity_counts[severity]} ({info})")
        
        # AI insights if available
        if hasattr(report, 'combined_ai_assessment') and report.combined_ai_assessment:
            ai_assess = report.combined_ai_assessment
            lines.append(f"\n🤖 AI Assessment:")
            lines.append(f"{self.indent}• AI Verdict: {ai_assess.get('verdict', 'Unknown')}")
            lines.append(f"{self.indent}• Combined AI Risk: {ai_assess.get('combined_risk', 0):.1%}")
            lines.append(f"{self.indent}• Files Analyzed by AI: {ai_assess.get('files_analyzed', 0)}")
            lines.append(f"{self.indent}• Critical AI Findings: {ai_assess.get('critical_findings', 0)}")
        
        # Find the highest severity in all threats
        highest_severity = 'INFO'
        severity_order = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
        
        for threat in report.threats_found:
            threat_sev = str(threat.severity).replace('ThreatSeverity.', '')
            if severity_order.get(threat_sev, 0) > severity_order.get(highest_severity, 0):
                highest_severity = threat_sev
        
        # Summary recommendation based on threat_score primarily, using severity as secondary indicator
        lines.append(f"\n💡 Final Verdict:")
        
        # Use threat_score as primary determinant, aligning with threat_level from analyzer
        if report.threat_score >= 0.8:
            lines.append(f"{self.indent}⛔ CRITICAL RISK - Do not use")
            lines.append(f"{self.indent}🔴 This code poses immediate and severe security risks")
        elif report.threat_score >= 0.6:
            lines.append(f"{self.indent}⚠️ HIGH RISK - Extensive review and remediation required")
            lines.append(f"{self.indent}🟠 Significant security concerns must be addressed")
        elif report.threat_score >= 0.4:
            lines.append(f"{self.indent}⚠️ MODERATE RISK - Review and address issues before use")
            lines.append(f"{self.indent}🟡 Several security issues need attention")
        elif report.threat_score >= 0.2:
            lines.append(f"{self.indent}ℹ️ LOW RISK - Minor issues to address")
            lines.append(f"{self.indent}🟢 Generally safe with some improvements needed")
        else:
            lines.append(f"{self.indent}✅ MINIMAL RISK - Safe for use with standard precautions")
            lines.append(f"{self.indent}✅ No significant security concerns identified")
        
        return "\n".join(lines)
    
    def _format_risk_matrix(self, report: Any) -> str:
        """Format risk assessment matrix"""
        lines = []
        lines.append("🎯 RISK ASSESSMENT MATRIX")
        lines.append("-" * self.width)
        
        # Create risk categories with count and max severity
        risk_categories = {
            'Code Execution': {'count': 0, 'max_severity': None},
            'Data Exposure': {'count': 0, 'max_severity': None},
            'Authentication': {'count': 0, 'max_severity': None},
            'Input Validation': {'count': 0, 'max_severity': None},
            'Network Security': {'count': 0, 'max_severity': None},
            'Cryptography': {'count': 0, 'max_severity': None},
            'Configuration': {'count': 0, 'max_severity': None}
        }
        
        # Helper function to update max severity
        def update_severity(category, threat):
            severity_str = str(threat.severity).replace('ThreatSeverity.', '')
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            
            current_max = risk_categories[category]['max_severity']
            if current_max is None:
                risk_categories[category]['max_severity'] = severity_str
            else:
                if severity_order.get(severity_str, 0) > severity_order.get(current_max, 0):
                    risk_categories[category]['max_severity'] = severity_str
        
        # Map threats to categories
        for threat in report.threats_found:
            vector = str(threat.attack_vector.value if hasattr(threat.attack_vector, 'value') else threat.attack_vector).upper()
            
            # Code Execution risks
            if any(x in vector for x in ['COMMAND', 'EXEC', 'INJECTION', 'EVAL', 'SYSTEM']):
                risk_categories['Code Execution']['count'] += 1
                update_severity('Code Execution', threat)
            
            # Data Exposure risks
            if any(x in vector for x in ['DATA', 'EXFIL', 'LEAK', 'CREDENTIAL', 'SECRET']):
                risk_categories['Data Exposure']['count'] += 1
                update_severity('Data Exposure', threat)
            
            # Authentication risks
            if any(x in vector for x in ['AUTH', 'PRIVILEGE', 'ESCALATION', 'BYPASS']):
                risk_categories['Authentication']['count'] += 1
                update_severity('Authentication', threat)
            
            # Input Validation risks
            if any(x in vector for x in ['INPUT', 'VALIDATION', 'PROMPT', 'SANITIZ']):
                risk_categories['Input Validation']['count'] += 1
                update_severity('Input Validation', threat)
            
            # Network Security risks
            if any(x in vector for x in ['NETWORK', 'REMOTE', 'SSRF', 'REQUEST']):
                risk_categories['Network Security']['count'] += 1
                update_severity('Network Security', threat)
            
            # Cryptography risks
            if any(x in vector for x in ['CRYPTO', 'ENCRYPTION', 'HASH', 'RANDOM']):
                risk_categories['Cryptography']['count'] += 1
                update_severity('Cryptography', threat)
            
            # Configuration risks (including obfuscation, persistence)
            if any(x in vector for x in ['CONFIG', 'MISCONFIGURATION', 'PERMISSION', 'PERSISTENCE', 'OBFUSCAT']):
                risk_categories['Configuration']['count'] += 1
                update_severity('Configuration', threat)
        
        # Display matrix
        lines.append("\n┌" + "─" * 30 + "┬" + "─" * 15 + "┬" + "─" * 20 + "┐")
        lines.append("│ " + "Risk Category".ljust(28) + " │ " + "Issues Found".ljust(13) + " │ " + "Risk Level".ljust(18) + " │")
        lines.append("├" + "─" * 30 + "┼" + "─" * 15 + "┼" + "─" * 20 + "┤")
        
        for category, data in sorted(risk_categories.items(), key=lambda x: x[1]['count'], reverse=True):
            count = data['count']
            severity = data['max_severity']
            risk_level = self._get_risk_level_text(count, severity)
            lines.append(f"│ {category.ljust(28)} │ {str(count).center(13)} │ {risk_level.ljust(18)} │")
        
        lines.append("└" + "─" * 30 + "┴" + "─" * 15 + "┴" + "─" * 20 + "┘")
        
        return "\n".join(lines)
    
    def _format_ai_analysis(self, report: Any) -> str:
        """Format AI analysis results"""
        lines = []
        lines.append("🤖 AI-POWERED ANALYSIS RESULTS")
        lines.append("-" * self.width)
        
        # LLM Analysis
        if report.llm_analysis:
            lines.append("\n📝 Large Language Model Analysis:")
            lines.append(f"{self.indent}• Total Findings: {report.llm_analysis.get('total_findings', 0)}")
            lines.append(f"{self.indent}• Critical Findings: {report.llm_analysis.get('critical_findings', 0)}")
            lines.append(f"{self.indent}• High-Risk Findings: {report.llm_analysis.get('high_findings', 0)}")
            lines.append(f"{self.indent}• Aggregate Risk Score: {report.llm_analysis.get('aggregate_risk', 0):.1%}")
            
            # Findings by type
            if 'findings_by_type' in report.llm_analysis:
                lines.append(f"\n{self.indent}Finding Categories:")
                for finding_type, count in report.llm_analysis['findings_by_type'].items():
                    lines.append(f"{self.indent}  • {finding_type}: {count}")
        
        # ML Analysis
        if hasattr(report, 'advanced_ml_analysis') and report.advanced_ml_analysis:
            lines.append("\n🧠 Machine Learning Analysis:")
            lines.append(f"{self.indent}• ML Risk Score: {report.advanced_ml_analysis.get('aggregate_risk', 0):.1%}")
            lines.append(f"{self.indent}• Total ML Threats: {report.advanced_ml_analysis.get('total_threats', 0)}")
            
            if 'threat_types' in report.advanced_ml_analysis:
                lines.append(f"\n{self.indent}ML Threat Categories:")
                for threat_type, count in report.advanced_ml_analysis['threat_types'].items():
                    lines.append(f"{self.indent}  • {threat_type}: {count}")
        
        # Combined insights
        if hasattr(report, 'ml_explanations') and report.ml_explanations:
            lines.append("\n📊 AI Insights:")
            for explanation in report.ml_explanations[:5]:  # Top 5 insights
                lines.append(f"{self.indent}• {explanation}")
        
        return "\n".join(lines)
    
    def _format_threat_analysis(self, report: Any) -> str:
        """Format detailed threat analysis"""
        lines = []
        lines.append("⚠️ DETAILED THREAT ANALYSIS")
        lines.append("-" * self.width)
        
        if not report.threats_found:
            lines.append("\n✅ No threats detected")
            return "\n".join(lines)
        
        # First, categorize threats by severity
        severity_breakdown = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for threat in report.threats_found:
            severity_str = str(threat.severity).replace('ThreatSeverity.', '')
            if severity_str in severity_breakdown:
                severity_breakdown[severity_str].append(threat)
        
        # Show severity breakdown
        lines.append("\n📊 Threat Severity Breakdown:")
        for severity, threats in severity_breakdown.items():
            if threats:
                emoji = self._get_severity_emoji(severity)
                lines.append(f"{self.indent}{emoji} {severity}: {len(threats)} threat(s)")
        
        # HIGHLIGHT CRITICAL THREATS FIRST
        if severity_breakdown['CRITICAL']:
            lines.append("\n" + "=" * 60)
            lines.append("🚨 CRITICAL THREATS - IMMEDIATE ACTION REQUIRED 🚨")
            lines.append("=" * 60)
            for threat in severity_breakdown['CRITICAL']:
                vector = str(threat.attack_vector.value if hasattr(threat.attack_vector, 'value') else threat.attack_vector)
                lines.append(f"\n🔴 {vector.replace('_', ' ').title()}")
                lines.append(f"📁 File: {threat.file_path}")
                if hasattr(threat, 'line_numbers') and threat.line_numbers:
                    lines.append(f"📍 Lines: {threat.line_numbers}")
                lines.append(f"⚠️  {threat.description}")
                if hasattr(threat, 'code_snippet') and threat.code_snippet:
                    lines.append(f"\nCode:")
                    for line in threat.code_snippet.split('\n')[:3]:
                        lines.append(f"  {line}")
            lines.append("=" * 60)
        
        # Group threats by attack vector
        threats_by_vector = defaultdict(list)
        for threat in report.threats_found:
            vector = str(threat.attack_vector.value if hasattr(threat.attack_vector, 'value') else threat.attack_vector)
            threats_by_vector[vector].append(threat)
        
        # Sort by threat count
        sorted_vectors = sorted(threats_by_vector.items(), key=lambda x: len(x[1]), reverse=True)
        
        for vector, threats in sorted_vectors[:5]:  # Top 5 threat categories
            lines.append(f"\n🔴 {vector.replace('_', ' ').title()} ({len(threats)} instances)")
            lines.append("─" * 40)
            
            # Show up to 3 examples per category
            for threat in threats[:3]:
                severity_emoji = self._get_severity_emoji(threat.severity)
                lines.append(f"\n{severity_emoji} Severity: {threat.severity}")
                lines.append(f"📁 File: {threat.file_path}")
                
                if hasattr(threat, 'line_numbers') and threat.line_numbers:
                    lines.append(f"📍 Lines: {threat.line_numbers}")
                
                lines.append(f"📝 Description: {threat.description}")
                
                if hasattr(threat, 'confidence'):
                    lines.append(f"🎯 Confidence: {threat.confidence:.1%}")
                
                # Show code snippet if available
                if hasattr(threat, 'code_snippet') and threat.code_snippet:
                    lines.append(f"\n{self.indent}Code Context:")
                    for line in threat.code_snippet.split('\n')[:5]:  # First 5 lines
                        lines.append(f"{self.indent}  {line}")
                
                # Show evidence if available
                if hasattr(threat, 'evidence') and threat.evidence:
                    if isinstance(threat.evidence, dict):
                        if 'pattern' in threat.evidence:
                            lines.append(f"\n{self.indent}Pattern Matched: {threat.evidence['pattern']}")
                        if 'match' in threat.evidence:
                            lines.append(f"{self.indent}Match: {threat.evidence['match']}")
        
        # Summary statistics
        lines.append("\n" + "─" * 40)
        lines.append("📊 Threat Statistics:")
        lines.append(f"{self.indent}• Total Threats: {len(report.threats_found)}")
        lines.append(f"{self.indent}• Unique Attack Vectors: {len(threats_by_vector)}")
        lines.append(f"{self.indent}• Average Confidence: {sum(t.confidence for t in report.threats_found if hasattr(t, 'confidence')) / len(report.threats_found):.1%}")
        
        return "\n".join(lines)
    
    def _format_data_flows(self, report: Any) -> str:
        """Format data flow analysis"""
        lines = []
        lines.append("🔄 DATA FLOW ANALYSIS")
        lines.append("-" * self.width)
        
        if not report.data_flows:
            lines.append("\nNo data flows detected")
            return "\n".join(lines)
        
        tainted_flows = [f for f in report.data_flows if f.is_tainted]
        safe_flows = [f for f in report.data_flows if not f.is_tainted]
        
        if tainted_flows:
            lines.append(f"\n⚠️ Tainted Data Flows ({len(tainted_flows)}):")
            for flow in tainted_flows[:5]:
                lines.append(f"{self.indent}• {flow.source_type} → {flow.sink_type}")
                lines.append(f"{self.indent}  Risk Score: {flow.risk_score:.1%}")
                if hasattr(flow, 'description'):
                    lines.append(f"{self.indent}  Description: {flow.description}")
        
        if safe_flows:
            lines.append(f"\n✅ Safe Data Flows ({len(safe_flows)}):")
            for flow in safe_flows[:3]:
                lines.append(f"{self.indent}• {flow.source_type} → {flow.sink_type}")
        
        return "\n".join(lines)
    
    def _format_dependencies(self, report: Any) -> str:
        """Format dependency analysis"""
        lines = []
        lines.append("📦 DEPENDENCY ANALYSIS")
        lines.append("-" * self.width)
        
        if report.vulnerable_dependencies:
            lines.append(f"\n⚠️ Vulnerable Dependencies ({len(report.vulnerable_dependencies)}):")
            for dep in report.vulnerable_dependencies[:10]:
                lines.append(f"{self.indent}• {dep['name']} v{dep['version']}")
                lines.append(f"{self.indent}  Vulnerability: {dep['vulnerability']}")
                lines.append(f"{self.indent}  Severity: {dep['severity']}")
        else:
            lines.append("\n✅ No known vulnerable dependencies detected")
        
        if hasattr(report, 'dependencies') and report.dependencies:
            lines.append(f"\n📊 Total Dependencies: {len(report.dependencies)}")
        
        return "\n".join(lines)
    
    def _format_code_metrics(self, report: Any) -> str:
        """Format code quality metrics"""
        lines = []
        lines.append("📈 CODE METRICS & STATISTICS")
        lines.append("-" * self.width)
        
        lines.append(f"\n📁 Repository Statistics:")
        lines.append(f"{self.indent}• Files Scanned: {report.total_files_scanned}")
        lines.append(f"{self.indent}• Lines Analyzed: {report.total_lines_analyzed:,}")
        
        if report.languages_detected:
            lines.append(f"\n💻 Languages Detected:")
            sorted_langs = sorted(report.languages_detected.items(), key=lambda x: x[1], reverse=True)
            for lang, count in sorted_langs[:5]:
                lines.append(f"{self.indent}• {lang}: {count} files")
        
        # Fingerprints
        lines.append(f"\n🔐 Security Fingerprints:")
        lines.append(f"{self.indent}• SHA-512: {report.sha512_fingerprint[:64]}...")
        lines.append(f"{self.indent}• SHA3-512: {report.sha3_512_fingerprint[:64]}...")
        lines.append(f"{self.indent}• Merkle Root: {report.merkle_root}")
        
        return "\n".join(lines)
    
    def _format_recommendations(self, report: Any) -> str:
        """Format recommendations and mitigations"""
        lines = []
        lines.append("💡 RECOMMENDATIONS & MITIGATIONS")
        lines.append("-" * self.width)
        
        # Priority recommendations
        lines.append("\n🎯 Priority Actions:")
        
        priority_actions = self._get_priority_actions(report)
        for i, action in enumerate(priority_actions, 1):
            lines.append(f"{self.indent}{i}. {action}")
        
        # Specific recommendations
        if report.recommendations:
            lines.append("\n📋 Detailed Recommendations:")
            for rec in report.recommendations[:10]:
                lines.append(f"{self.indent}• {rec}")
        
        # Mitigations
        if report.mitigations:
            lines.append("\n🛡️ Suggested Mitigations:")
            for mit in report.mitigations[:10]:
                lines.append(f"{self.indent}• {mit}")
        
        return "\n".join(lines)
    
    def _format_technical_details(self, report: Any) -> str:
        """Format technical details section"""
        lines = []
        lines.append("🔧 TECHNICAL DETAILS")
        lines.append("-" * self.width)
        
        # Scan metadata
        lines.append(f"\n📊 Scan Metadata:")
        lines.append(f"{self.indent}• Scan Timestamp: {report.scan_timestamp}")
        lines.append(f"{self.indent}• Repository URL: {report.repository_url}")
        
        # Performance metrics
        if hasattr(report, 'scan_duration'):
            lines.append(f"{self.indent}• Scan Duration: {report.scan_duration}s")
        
        # File fingerprints sample
        if report.file_fingerprints:
            lines.append(f"\n🔍 Sample File Fingerprints (first 3):")
            for file_path, fingerprint in list(report.file_fingerprints.items())[:3]:
                lines.append(f"{self.indent}• {file_path}:")
                lines.append(f"{self.indent}  SHA-512: {fingerprint['sha512'][:32]}...")
                lines.append(f"{self.indent}  Size: {fingerprint['size']} bytes")
                if 'entropy' in fingerprint:
                    lines.append(f"{self.indent}  Entropy: {fingerprint['entropy']:.2f}")
        
        return "\n".join(lines)
    
    # Helper methods
    def _get_threat_emoji(self, threat_level: str) -> str:
        """Get emoji for threat level"""
        emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '✅'
        }
        return emojis.get(threat_level.upper(), '⚪')
    
    def _get_severity_emoji(self, severity) -> str:
        """Get emoji for severity level"""
        emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }
        # Handle both enum and string values
        severity_str = str(severity.value if hasattr(severity, 'value') else severity)
        return emojis.get(severity_str.upper(), '⚪')
    
    def _get_risk_level_text(self, count: int, severity_level: str = None) -> str:
        """Get risk level text based on count AND severity of threats"""
        if count == 0:
            return "✅ None"
        
        # If we have severity info, use that instead of just count
        if severity_level:
            if severity_level == 'CRITICAL':
                return "🔴 Critical"
            elif severity_level == 'HIGH':
                return "🟠 High"
            elif severity_level == 'MEDIUM':
                return "🟡 Medium"
            else:
                return "🟢 Low"
        
        # Fallback to count-based if no severity
        if count <= 5:
            return "🟢 Low"
        elif count <= 10:
            return "🟡 Medium"
        elif count <= 20:
            return "🟠 High"
        else:
            return "🔴 Critical"
    
    def _get_priority_actions(self, report: Any) -> List[str]:
        """Get priority actions based on findings"""
        actions = []
        
        # Check for critical threats
        critical_threats = [t for t in report.threats_found if t.severity == 'CRITICAL']
        if critical_threats:
            actions.append("🔴 IMMEDIATE: Address all CRITICAL severity issues before any deployment")
        
        # Check for command injection
        cmd_threats = [t for t in report.threats_found if 'COMMAND' in str(t.attack_vector).upper()]
        if cmd_threats:
            actions.append("⚠️ HIGH: Review and sanitize all command execution patterns")
        
        # Check for data exposure
        data_threats = [t for t in report.threats_found if 'DATA' in str(t.attack_vector).upper()]
        if data_threats:
            actions.append("⚠️ HIGH: Implement proper data protection and access controls")
        
        # Check for vulnerable dependencies
        if report.vulnerable_dependencies:
            actions.append("📦 MEDIUM: Update all vulnerable dependencies to patched versions")
        
        # General recommendations based on score
        if report.threat_score >= 0.6:
            actions.append("🔒 Conduct thorough security review with security team")
            actions.append("📝 Document all security decisions and accepted risks")
        elif report.threat_score >= 0.4:
            actions.append("🔍 Review identified issues and create remediation plan")
            actions.append("✅ Implement security testing in CI/CD pipeline")
        else:
            actions.append("✅ Maintain regular security scanning schedule")
            actions.append("📚 Keep dependencies updated and monitor for new vulnerabilities")
        
        return actions