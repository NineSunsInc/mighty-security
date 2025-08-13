#!/usr/bin/env python3
"""
Test script to analyze MCP servers from awesome-mcp-servers repository
Pulls samples from various categories and runs security analysis
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple
import subprocess
import time

# Add parent directory to path to import our analyzer
sys.path.append(str(Path(__file__).parent.parent))

# Selected MCP servers from different categories
# URLs taken from https://github.com/punkpeye/awesome-mcp-servers

MCP_SERVERS_TO_TEST = {
    "Knowledge & Memory": [
        "https://github.com/evalstate/mcp-knowledge-graph",
        "https://github.com/chatmcp/mcp-memory",
        "https://github.com/c0d3-jay/mcp-memory",
        "https://github.com/kaiban-ai/mcp-ragbox",
        "https://github.com/mark3labs/mcp-knowledge-graph-neo4j"
    ],
    "Gaming": [
        "https://github.com/modelcontextprotocol/servers/tree/main/src/everart",
        "https://github.com/cngarrison/mcp-server-yjs-google-drive",
        "https://github.com/cngarrison/mcp-server-yjs-websocket", 
        "https://github.com/cngarrison/mcp-server-twitch",
        "https://github.com/cngarrison/mcp-server-epic-games"
    ],
    "Location Services": [
        "https://github.com/micahk-moto/places",
        "https://github.com/BritishCryptoGuy/mcp-server-osgrid",
        "https://github.com/danthegoodman1/mcp-memory",
        "https://github.com/klaussilveira/mcp-geocode",
        "https://github.com/modelcontextprotocol/servers/tree/main/src/weather"
    ],
    "Security": [
        "https://github.com/fr0gger/MCP_Security",
        "https://github.com/atomicchonk/roadrecon_mcp_server",
        "https://github.com/intruder-io/intruder-mcp",
        "https://github.com/LaurieWired/GhidraMCP",
        "https://github.com/qianniuspace/mcp-security-audit"
    ],
    "Travel & Transportation": [
        "https://github.com/sunsetcoder/mcp-amadeus",
        "https://github.com/sunsetcoder/mcp-skyscanner",
        "https://github.com/sunsetcoder/mcp-travel-assistant",
        "https://github.com/bhardwajRahul/mcp-flight-tracker",
        "https://github.com/modelcontextprotocol/servers/tree/main/src/maps"
    ],
    "Databases": [
        "https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite",
        "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres",
        "https://github.com/BasedHardware/Whomane",
        "https://github.com/ktanaka101/mcp-server-duckdb", 
        "https://github.com/benborla/mcp-server-bigquery"
    ]
}

class MCPServerTester:
    """Test MCP servers from awesome-mcp-servers repository"""
    
    def __init__(self, quick_mode: bool = True):
        self.quick_mode = quick_mode
        self.results = {}
        self.analyzer_path = Path(__file__).parent.parent / "mighty_mcp.py"
        self.servers_to_test = MCP_SERVERS_TO_TEST  # Default to all servers
        
    def test_server(self, url: str, category: str) -> Dict:
        """Test a single MCP server"""
        print(f"\n{'='*60}")
        print(f"Testing: {url}")
        print(f"Category: {category}")
        print(f"{'='*60}")
        
        result = {
            "url": url,
            "category": category,
            "status": "pending",
            "threat_level": None,
            "threat_score": None,
            "threats_found": 0,
            "error": None,
            "scan_time": 0
        }
        
        try:
            start_time = time.time()
            
            # Run the analyzer
            cmd = [
                "python3", str(self.analyzer_path),
                "check", url,
                "--profile", "production",
                "--no-cache"
            ]
            
            if self.quick_mode:
                cmd.append("--quick")
            else:
                cmd.append("--deep")
            
            # Run with timeout
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            scan_time = time.time() - start_time
            result["scan_time"] = round(scan_time, 2)
            
            # Parse output
            output = process.stdout + process.stderr
            
            # Extract key metrics from output - handle both formats
            if "SECURITY REPORT" in output:
                for line in output.split("\n"):
                    if "Threat Level:" in line:
                        result["threat_level"] = line.split("Threat Level:")[-1].strip()
                    elif "Threat Score:" in line:
                        score_str = line.split("Threat Score:")[-1].strip().replace("%", "")
                        try:
                            result["threat_score"] = float(score_str)
                        except:
                            result["threat_score"] = None
                    elif "Total Threats:" in line:
                        try:
                            result["threats_found"] = int(line.split("Total Threats:")[-1].strip())
                        except:
                            pass
                
                # Check if we got at least threats count (minimal output)
                if "Total Threats:" in output:
                    result["status"] = "completed"
                    # If no threat level specified, assume SAFE if 0 threats
                    if result["threats_found"] == 0 and not result["threat_level"]:
                        result["threat_level"] = "SAFE"
                        result["threat_score"] = 0.0
                else:
                    result["status"] = "failed"
                    result["error"] = "Incomplete output"
            else:
                result["status"] = "failed"
                result["error"] = "Could not parse output"
                
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["error"] = "Analysis timed out after 120 seconds"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        # Print summary
        self._print_result(result)
        
        return result
    
    def _print_result(self, result: Dict):
        """Print a formatted result"""
        if result["status"] == "completed":
            # Color code based on threat level
            threat_level = result.get("threat_level", "UNKNOWN")
            if "CRITICAL" in threat_level:
                emoji = "🔴"
            elif "HIGH" in threat_level:
                emoji = "🟠"
            elif "MEDIUM" in threat_level:
                emoji = "🟡"
            elif "LOW" in threat_level or "MINIMAL" in threat_level:
                emoji = "🟢"
            else:
                emoji = "⚪"
            
            print(f"{emoji} Threat Level: {threat_level}")
            print(f"   Score: {result.get('threat_score', 'N/A')}%")
            print(f"   Threats Found: {result.get('threats_found', 0)}")
            print(f"   Scan Time: {result.get('scan_time', 0)}s")
        else:
            print(f"❌ Status: {result['status']}")
            if result.get("error"):
                print(f"   Error: {result['error']}")
    
    def run_all_tests(self) -> Dict:
        """Run tests on all configured servers"""
        print("\n" + "="*70)
        print("MCP SERVER SECURITY ANALYSIS")
        print(f"Mode: {'QUICK' if self.quick_mode else 'DEEP'}")
        print(f"Testing {sum(len(v) for v in self.servers_to_test.values())} servers across {len(self.servers_to_test)} categories")
        print("="*70)
        
        all_results = {}
        
        for category, urls in self.servers_to_test.items():
            print(f"\n\n{'#'*70}")
            print(f"# CATEGORY: {category}")
            print(f"{'#'*70}")
            
            category_results = []
            for url in urls:
                result = self.test_server(url, category)
                category_results.append(result)
                
                # Small delay between tests to avoid overwhelming
                time.sleep(2)
            
            all_results[category] = category_results
        
        self.results = all_results
        return all_results
    
    def generate_summary(self) -> str:
        """Generate a summary report"""
        if not self.results:
            return "No results to summarize"
        
        summary = []
        summary.append("\n" + "="*70)
        summary.append("SECURITY ANALYSIS SUMMARY")
        summary.append("="*70)
        
        total_servers = 0
        threat_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "MINIMAL": 0,
            "SAFE": 0,
            "UNKNOWN": 0
        }
        
        for category, results in self.results.items():
            summary.append(f"\n{category}:")
            for result in results:
                total_servers += 1
                threat_level = result.get("threat_level", "UNKNOWN")
                
                # Categorize threat level
                found_category = False
                for threat_key in threat_distribution:
                    if threat_key in str(threat_level).upper():
                        threat_distribution[threat_key] += 1
                        found_category = True
                        break
                
                if not found_category:
                    threat_distribution["UNKNOWN"] += 1
                
                # Build summary line
                if result["status"] == "completed":
                    summary.append(f"  - {result['url'].split('/')[-1]}: {threat_level} ({result.get('threat_score', 0)}%)")
                else:
                    summary.append(f"  - {result['url'].split('/')[-1]}: {result['status'].upper()}")
        
        # Overall statistics
        summary.append(f"\n{'='*70}")
        summary.append("OVERALL STATISTICS")
        summary.append(f"{'='*70}")
        summary.append(f"Total Servers Tested: {total_servers}")
        summary.append("\nThreat Distribution:")
        for level, count in threat_distribution.items():
            if count > 0:
                percentage = (count / total_servers) * 100
                summary.append(f"  {level}: {count} ({percentage:.1f}%)")
        
        # Calculate average threat score
        all_scores = []
        for category_results in self.results.values():
            for result in category_results:
                if result.get("threat_score") is not None:
                    all_scores.append(result["threat_score"])
        
        if all_scores:
            avg_score = sum(all_scores) / len(all_scores)
            summary.append(f"\nAverage Threat Score: {avg_score:.1f}%")
        
        # Save results to file
        self._save_results()
        
        return "\n".join(summary)
    
    def _save_results(self):
        """Save results to JSON file"""
        output_file = Path(__file__).parent / "awesome_mcp_servers_results.json"
        
        # Add metadata
        output_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "quick" if self.quick_mode else "deep",
            "total_servers": sum(len(v) for v in self.results.values()),
            "results": self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\nResults saved to: {output_file}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test MCP servers from awesome-mcp-servers")
    parser.add_argument("--deep", action="store_true", help="Use deep analysis mode (slower)")
    parser.add_argument("--category", help="Test only a specific category")
    args = parser.parse_args()
    
    # Check if analyzer exists
    analyzer_path = Path(__file__).parent.parent / "mighty_mcp.py"
    if not analyzer_path.exists():
        print(f"Error: Analyzer not found at {analyzer_path}")
        sys.exit(1)
    
    # Filter categories if specified
    servers_to_test = MCP_SERVERS_TO_TEST
    if args.category:
        if args.category in MCP_SERVERS_TO_TEST:
            servers_to_test = {args.category: MCP_SERVERS_TO_TEST[args.category]}
        else:
            print(f"Error: Unknown category '{args.category}'")
            print(f"Available categories: {', '.join(MCP_SERVERS_TO_TEST.keys())}")
            sys.exit(1)
    
    # Run tests
    tester = MCPServerTester(quick_mode=not args.deep)
    
    # Store the servers to test in the tester
    tester.servers_to_test = servers_to_test
    
    try:
        tester.run_all_tests()
        print(tester.generate_summary())
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        if tester.results:
            print(tester.generate_summary())
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()