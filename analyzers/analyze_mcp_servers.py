#!/usr/bin/env python3
"""
Analyze specific MCP servers from the official repository
Shows detailed security analysis of each server type
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any
import tempfile
import shutil

from comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


class MCPServerAnalyzer:
    """Analyze individual MCP servers from the repository"""
    
    def __init__(self):
        self.analyzer = ComprehensiveMCPAnalyzer()
        self.servers_to_analyze = [
            "filesystem",  # File system operations
            "git",         # Git operations
            "memory",      # Memory/state management
            "postgres",    # Database operations
            "puppeteer",   # Browser automation
            "slack",       # Slack integration
            "sqlite",      # SQLite database
            "time",        # Time operations
            "sequential-thinking",  # Sequential processing
        ]
    
    def clone_repository(self, repo_url: str, target_dir: Path) -> bool:
        """Clone the repository"""
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            print("❌ Git not found. Please install git.")
            return False
    
    def analyze_server(self, server_path: Path, server_name: str) -> Dict[str, Any]:
        """Analyze a specific MCP server"""
        print(f"\n{'='*60}")
        print(f"📦 Analyzing: {server_name}")
        print(f"{'='*60}")
        
        if not server_path.exists():
            print(f"  ⚠️  Server not found: {server_path}")
            return {"name": server_name, "error": "Not found"}
        
        try:
            # Run analysis
            report = self.analyzer._comprehensive_scan(server_path, str(server_path), [])
            
            # Extract key metrics
            result = {
                "name": server_name,
                "threat_score": report.threat_score,
                "threat_level": report.threat_level,
                "threats_count": len(report.threats_found),
                "files_scanned": len(report.file_fingerprints),
                "critical_threats": [],
                "high_threats": [],
                "capabilities": self._identify_capabilities(server_path)
            }
            
            # Categorize threats
            for threat in report.threats_found:
                if threat.severity.value == "CRITICAL":
                    result["critical_threats"].append({
                        "type": threat.attack_vector.value,
                        "description": threat.description
                    })
                elif threat.severity.value == "HIGH":
                    result["high_threats"].append({
                        "type": threat.attack_vector.value,
                        "description": threat.description
                    })
            
            # Print summary
            self._print_server_summary(result)
            
            return result
            
        except Exception as e:
            print(f"  ❌ Error analyzing {server_name}: {e}")
            return {"name": server_name, "error": str(e)}
    
    def _identify_capabilities(self, server_path: Path) -> List[str]:
        """Identify what capabilities this server has"""
        capabilities = []
        
        # Check for common patterns
        for file_path in server_path.rglob("*.py"):
            try:
                content = file_path.read_text()
                if "open(" in content or "Path(" in content:
                    capabilities.append("file_access")
                if "subprocess" in content or "os.system" in content:
                    capabilities.append("command_execution")
                if "requests" in content or "urllib" in content:
                    capabilities.append("network_access")
                if "sqlite" in content or "postgres" in content:
                    capabilities.append("database_access")
            except:
                pass
        
        for file_path in server_path.rglob("*.ts"):
            try:
                content = file_path.read_text()
                if "fs." in content or "readFile" in content:
                    capabilities.append("file_access")
                if "exec" in content or "spawn" in content:
                    capabilities.append("command_execution")
                if "fetch" in content or "axios" in content:
                    capabilities.append("network_access")
            except:
                pass
        
        return list(set(capabilities))
    
    def _print_server_summary(self, result: Dict[str, Any]):
        """Print a summary of server analysis"""
        print(f"\n  📊 {result['name'].upper()} Analysis:")
        print(f"  ├─ Threat Score: {result['threat_score']:.1f}%")
        print(f"  ├─ Threat Level: {result['threat_level']}")
        print(f"  ├─ Files Scanned: {result['files_scanned']}")
        print(f"  ├─ Total Threats: {result['threats_count']}")
        
        if result['capabilities']:
            print(f"  ├─ Capabilities: {', '.join(result['capabilities'])}")
        
        if result['critical_threats']:
            print(f"  ├─ ⚠️  CRITICAL Threats: {len(result['critical_threats'])}")
            for threat in result['critical_threats'][:2]:
                print(f"  │   └─ {threat['type']}: {threat['description'][:50]}...")
        
        if result['high_threats']:
            print(f"  └─ ⚠️  HIGH Threats: {len(result['high_threats'])}")
            for threat in result['high_threats'][:2]:
                print(f"      └─ {threat['type']}: {threat['description'][:50]}...")
        
        # Safety verdict
        if result['threat_score'] < 20:
            print(f"\n  ✅ VERDICT: Safe to use")
        elif result['threat_score'] < 50:
            print(f"\n  ⚠️  VERDICT: Review before use")
        else:
            print(f"\n  🚨 VERDICT: High risk - careful review required")
    
    def analyze_all_servers(self):
        """Analyze all MCP servers in the repository"""
        print("\n" + "="*60)
        print("🔍 MCP SERVERS SECURITY ANALYSIS")
        print("="*60)
        print("\nAnalyzing official MCP server implementations...")
        
        # Clone repository
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "servers"
            
            print("\n📥 Cloning repository...")
            if not self.clone_repository("https://github.com/modelcontextprotocol/servers", repo_path):
                print("Failed to clone repository")
                return
            
            print("✅ Repository cloned successfully")
            
            # Find all servers
            src_path = repo_path / "src"
            if not src_path.exists():
                print(f"❌ Source directory not found: {src_path}")
                return
            
            results = []
            
            # Analyze each server
            for server_dir in sorted(src_path.iterdir()):
                if server_dir.is_dir() and not server_dir.name.startswith('.'):
                    result = self.analyze_server(server_dir, server_dir.name)
                    results.append(result)
            
            # Print summary
            self._print_overall_summary(results)
            
            # Save detailed report
            self._save_report(results)
    
    def _print_overall_summary(self, results: List[Dict[str, Any]]):
        """Print overall summary of all servers"""
        print("\n" + "="*60)
        print("📊 OVERALL SUMMARY")
        print("="*60)
        
        total_servers = len(results)
        safe_servers = sum(1 for r in results if r.get('threat_score', 100) < 20)
        risky_servers = sum(1 for r in results if r.get('threat_score', 0) >= 50)
        
        print(f"\nTotal Servers Analyzed: {total_servers}")
        print(f"├─ ✅ Safe: {safe_servers}")
        print(f"├─ ⚠️  Review Needed: {total_servers - safe_servers - risky_servers}")
        print(f"└─ 🚨 High Risk: {risky_servers}")
        
        # Sort by threat score
        sorted_results = sorted(results, key=lambda x: x.get('threat_score', 0), reverse=True)
        
        print("\n🏆 Safest Servers:")
        for result in sorted_results[-3:]:
            if 'error' not in result:
                print(f"  • {result['name']}: {result['threat_score']:.1f}% threat score")
        
        if risky_servers > 0:
            print("\n⚠️  Highest Risk Servers:")
            for result in sorted_results[:3]:
                if 'error' not in result and result['threat_score'] >= 20:
                    print(f"  • {result['name']}: {result['threat_score']:.1f}% threat score")
        
        # Capability summary
        all_capabilities = set()
        for result in results:
            if 'capabilities' in result:
                all_capabilities.update(result['capabilities'])
        
        if all_capabilities:
            print(f"\n🔧 Capabilities Found Across All Servers:")
            for cap in sorted(all_capabilities):
                count = sum(1 for r in results if cap in r.get('capabilities', []))
                print(f"  • {cap}: {count} servers")
    
    def _save_report(self, results: List[Dict[str, Any]]):
        """Save detailed report to file"""
        report_file = Path("mcp_servers_analysis.json")
        
        report = {
            "analysis_date": str(Path("comprehensive_report_*.json").glob("*")),
            "servers_analyzed": len(results),
            "results": results
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Detailed report saved to: {report_file}")


def main():
    """Main entry point"""
    analyzer = MCPServerAnalyzer()
    analyzer.analyze_all_servers()


if __name__ == "__main__":
    main()