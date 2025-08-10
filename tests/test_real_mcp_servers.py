#!/usr/bin/env python3
"""
Test runner for analyzing real MCP servers using our existing analyzer
"""

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any
import json
import tempfile
import shutil
from datetime import datetime

# Import our existing analyzer
from comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer, SecurityReport

class MCPServerTester:
    """Test real MCP servers from GitHub"""
    
    def __init__(self):
        self.analyzer = ComprehensiveMCPAnalyzer()
        self.test_servers = self._get_test_servers()
        self.results = []
        
    def _get_test_servers(self) -> List[Dict[str, Any]]:
        """List of real MCP servers to test"""
        return [
            # Official Anthropic servers (should be safe)
            {
                "name": "Official MCP Servers",
                "url": "https://github.com/modelcontextprotocol/servers",
                "expected_safe": True,
                "description": "Anthropic's official MCP server implementations"
            },
            
            # Community servers (various risk levels)
            {
                "name": "Kubectl MCP Server",
                "url": "https://github.com/pierrebrunelle/mcp-server-kubectl",
                "expected_safe": True,
                "description": "Kubernetes control via MCP"
            },
            {
                "name": "Zue AI MCP Server",
                "url": "https://github.com/zueai/zueai-mcp-server", 
                "expected_safe": True,
                "description": "AI-powered MCP server"
            },
            {
                "name": "Browser Automation MCP",
                "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer",
                "expected_safe": True,
                "description": "Browser automation server"
            },
            {
                "name": "Filesystem MCP",
                "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
                "expected_safe": True,
                "description": "File system access server"
            }
        ]
    
    def test_server(self, server: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single MCP server"""
        print(f"\n{'='*60}")
        print(f"Testing: {server['name']}")
        print(f"URL: {server['url']}")
        print(f"Expected: {'SAFE ✅' if server['expected_safe'] else 'SUSPICIOUS ⚠️'}")
        print(f"{'='*60}")
        
        try:
            # Analyze with our existing analyzer
            report = self.analyzer.analyze_repository(server['url'])
            
            # Determine if detection was correct
            is_safe = report.risk_score < 5.0
            detection_correct = (is_safe == server['expected_safe'])
            
            # Print results
            self._print_report(report)
            
            result = {
                "server": server['name'],
                "url": server['url'],
                "risk_score": report.risk_score,
                "threats_found": len(report.threat_indicators),
                "critical_threats": len([t for t in report.threat_indicators if t.severity.value == "CRITICAL"]),
                "ml_score": report.ml_maliciousness_score,
                "detection_correct": detection_correct,
                "expected_safe": server['expected_safe'],
                "actual_safe": is_safe,
                "timestamp": datetime.now().isoformat()
            }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            print(f"❌ Error analyzing {server['name']}: {e}")
            return {
                "server": server['name'],
                "error": str(e),
                "detection_correct": False
            }
    
    def _print_report(self, report: SecurityReport):
        """Print analysis report"""
        print(f"\n📊 ANALYSIS RESULTS")
        print(f"{'─'*40}")
        print(f"Risk Score: {report.risk_score:.1f}/10")
        print(f"ML Maliciousness: {report.ml_maliciousness_score:.1%}")
        print(f"Total Threats: {len(report.threat_indicators)}")
        
        # Risk level
        if report.risk_score < 3:
            print("🟢 LOW RISK - Appears safe")
        elif report.risk_score < 6:
            print("🟡 MEDIUM RISK - Review recommended")
        else:
            print("🔴 HIGH RISK - Potentially malicious")
        
        # Show critical threats
        critical = [t for t in report.threat_indicators if t.severity.value == "CRITICAL"]
        if critical:
            print(f"\n⚠️  CRITICAL THREATS ({len(critical)}):")
            for threat in critical[:3]:  # Show top 3
                print(f"  • {threat.attack_vector.value}: {threat.description}")
                if threat.file_path:
                    print(f"    File: {Path(threat.file_path).name}")
        
        # Show high-risk threats
        high = [t for t in report.threat_indicators if t.severity.value == "HIGH"]
        if high:
            print(f"\n⚠️  HIGH RISK THREATS ({len(high)}):")
            for threat in high[:3]:
                print(f"  • {threat.attack_vector.value}: {threat.description}")
        
        # Data flows
        if report.data_flows:
            risky_flows = [f for f in report.data_flows if f.is_tainted]
            if risky_flows:
                print(f"\n🔄 RISKY DATA FLOWS ({len(risky_flows)}):")
                for flow in risky_flows[:2]:
                    print(f"  • {flow.source_type} → {flow.sink_type}")
    
    def run_all_tests(self):
        """Run tests on all configured servers"""
        print("\n" + "="*60)
        print("🔍 MCP SERVER SECURITY TESTING")
        print("="*60)
        print(f"Testing {len(self.test_servers)} MCP servers...")
        
        for server in self.test_servers:
            self.test_server(server)
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        
        total = len(self.results)
        correct = sum(1 for r in self.results if r.get('detection_correct', False))
        errors = sum(1 for r in self.results if 'error' in r)
        
        print(f"Total Servers Tested: {total}")
        print(f"Correct Detections: {correct}/{total - errors} ({correct/(total-errors)*100:.1f}%)")
        print(f"Errors: {errors}")
        
        # Calculate metrics
        safe_servers = [r for r in self.results if r.get('expected_safe', False) and 'error' not in r]
        malicious_servers = [r for r in self.results if not r.get('expected_safe', True) and 'error' not in r]
        
        if safe_servers:
            avg_safe_score = sum(r['risk_score'] for r in safe_servers) / len(safe_servers)
            print(f"\nSafe Servers:")
            print(f"  Average Risk Score: {avg_safe_score:.1f}")
            false_positives = sum(1 for r in safe_servers if not r['actual_safe'])
            print(f"  False Positives: {false_positives}/{len(safe_servers)}")
        
        if malicious_servers:
            avg_mal_score = sum(r['risk_score'] for r in malicious_servers) / len(malicious_servers)
            print(f"\nMalicious Servers:")
            print(f"  Average Risk Score: {avg_mal_score:.1f}")
            false_negatives = sum(1 for r in malicious_servers if r['actual_safe'])
            print(f"  False Negatives: {false_negatives}/{len(malicious_servers)}")
        
        # Save results
        self._save_results()
    
    def _save_results(self):
        """Save test results to file"""
        output_file = Path("mcp_test_results.json")
        with open(output_file, 'w') as f:
            json.dump({
                "test_date": datetime.now().isoformat(),
                "analyzer_version": "1.0.0",
                "results": self.results,
                "summary": {
                    "total_tested": len(self.results),
                    "correct_detections": sum(1 for r in self.results if r.get('detection_correct', False))
                }
            }, f, indent=2)
        print(f"\n💾 Results saved to {output_file}")


class ProactiveMonitor:
    """Monitor GitHub for new MCP servers"""
    
    def __init__(self):
        self.analyzer = ComprehensiveMCPAnalyzer()
        self.monitored_repos = set()
        
    async def scan_github_trending(self):
        """Scan GitHub for trending MCP repositories"""
        print("\n🔎 Scanning GitHub for MCP servers...")
        
        # Search queries for finding MCP servers
        search_queries = [
            "mcp-server language:typescript stars:>10",
            "mcp-server language:python stars:>10",
            "modelcontextprotocol server",
            '"mcp.json" OR "mcp.yaml"'
        ]
        
        discovered = []
        
        for query in search_queries:
            try:
                # Use GitHub CLI if available
                result = subprocess.run(
                    ["gh", "search", "repos", query, "--limit", "10", "--json", "url,name,description"],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    repos = json.loads(result.stdout)
                    for repo in repos:
                        if repo['url'] not in self.monitored_repos:
                            discovered.append(repo)
                            self.monitored_repos.add(repo['url'])
            except FileNotFoundError:
                print("  ℹ️  GitHub CLI not found. Install 'gh' for better scanning.")
                break
            except Exception as e:
                print(f"  ⚠️  Search error: {e}")
        
        return discovered
    
    async def analyze_discovered(self, repos: List[Dict]):
        """Analyze discovered repositories"""
        high_risk = []
        
        for repo in repos:
            print(f"\n  Analyzing: {repo['name']}")
            try:
                report = self.analyzer.analyze_repository(repo['url'])
                
                if report.risk_score > 6:
                    high_risk.append({
                        "repo": repo,
                        "risk_score": report.risk_score,
                        "threats": len(report.threat_indicators)
                    })
                    print(f"    🔴 HIGH RISK: Score {report.risk_score:.1f}")
                elif report.risk_score > 3:
                    print(f"    🟡 Medium Risk: Score {report.risk_score:.1f}")
                else:
                    print(f"    🟢 Low Risk: Score {report.risk_score:.1f}")
                    
            except Exception as e:
                print(f"    ❌ Error: {e}")
        
        return high_risk
    
    async def monitor_loop(self):
        """Continuous monitoring loop"""
        print("\n🚨 Starting Proactive MCP Security Monitor")
        print("=" * 60)
        
        while True:
            discovered = await self.scan_github_trending()
            
            if discovered:
                print(f"\n📦 Found {len(discovered)} new MCP servers")
                high_risk = await self.analyze_discovered(discovered)
                
                if high_risk:
                    print(f"\n⚠️  ALERT: {len(high_risk)} high-risk repositories detected!")
                    for item in high_risk:
                        print(f"  • {item['repo']['name']}: Risk {item['risk_score']:.1f}")
            
            print(f"\n💤 Next scan in 1 hour...")
            await asyncio.sleep(3600)  # 1 hour


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test MCP servers for security')
    parser.add_argument('--monitor', action='store_true', help='Run continuous monitoring')
    parser.add_argument('--test-all', action='store_true', help='Test all configured servers')
    parser.add_argument('--url', help='Test a specific MCP server URL')
    
    args = parser.parse_args()
    
    if args.monitor:
        # Run monitoring
        monitor = ProactiveMonitor()
        asyncio.run(monitor.monitor_loop())
        
    elif args.url:
        # Test specific URL
        tester = MCPServerTester()
        server = {
            "name": "Custom Server",
            "url": args.url,
            "expected_safe": True,
            "description": "User-provided server"
        }
        tester.test_server(server)
        
    else:
        # Test all configured servers
        tester = MCPServerTester()
        tester.run_all_tests()


if __name__ == "__main__":
    main()