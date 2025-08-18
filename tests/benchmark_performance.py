#!/usr/bin/env python3
"""
Comprehensive Performance Benchmark
Measures performance improvements from parallel processing and other optimizations
"""

import sys
import time
import tempfile
import json
import statistics
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.comprehensive_mcp_analyzer import ComprehensiveMCPAnalyzer


class PerformanceBenchmark:
    """Comprehensive performance benchmarking suite"""
    
    def __init__(self):
        self.results = {
            'sequential': {},
            'parallel': {},
            'improvements': {}
        }
    
    def create_test_repo(self, file_count: int = 50, complexity: str = "medium") -> Path:
        """Create a test repository with various file types and patterns"""
        temp_dir = tempfile.mkdtemp()
        test_dir = Path(temp_dir)
        
        # Different threat patterns for variety
        threat_patterns = {
            'high': [
                "exec(user_input)",
                "eval(request.params['cmd'])",
                "os.system(f'rm -rf {path}')",
                "subprocess.run(cmd, shell=True)",
            ],
            'medium': [
                "password = 'admin123'",
                "api_key = config['secret']",
                "token = os.environ.get('TOKEN')",
            ],
            'low': [
                "print(user_data)",
                "logging.info(request)",
            ]
        }
        
        # Create files with varying complexity
        for i in range(file_count):
            # Mix of Python, JavaScript, and config files
            if i % 3 == 0:
                ext = '.py'
                imports = "import os\nimport subprocess\nimport pickle\n"
            elif i % 3 == 1:
                ext = '.js'
                imports = "const exec = require('child_process').exec;\n"
            else:
                ext = '.json'
                imports = ""
            
            file_path = test_dir / f"file_{i}{ext}"
            
            # Build content based on complexity
            content = imports
            
            if complexity == "high":
                # Add many patterns
                for severity, patterns in threat_patterns.items():
                    for pattern in patterns:
                        content += f"\n# {severity} risk\n{pattern}\n"
                # Add more lines for realistic file size
                content += "\n".join(f"# Line {j}" for j in range(100))
            elif complexity == "medium":
                # Add some patterns
                content += threat_patterns['high'][i % len(threat_patterns['high'])] + "\n"
                content += threat_patterns['medium'][i % len(threat_patterns['medium'])] + "\n"
                content += "\n".join(f"# Line {j}" for j in range(50))
            else:  # low
                # Minimal patterns
                if i % 5 == 0:
                    content += threat_patterns['low'][i % len(threat_patterns['low'])] + "\n"
                content += "\n".join(f"# Line {j}" for j in range(20))
            
            file_path.write_text(content)
        
        return test_dir
    
    def benchmark_sequential(self, test_dir: Path, runs: int = 3) -> Dict:
        """Benchmark sequential processing"""
        print("\n📊 Benchmarking Sequential Processing...")
        
        times = []
        threats = []
        files_processed = []
        
        for run in range(runs):
            analyzer = ComprehensiveMCPAnalyzer(
                verbose=False, 
                enable_parallel=False,
                use_cache=False  # Disable cache for fair comparison
            )
            
            start_time = time.perf_counter()
            report = analyzer.analyze_repository(str(test_dir))
            elapsed = time.perf_counter() - start_time
            
            times.append(elapsed)
            threats.append(len(report.threats_found))
            files_processed.append(report.total_files_scanned)
            
            print(f"   Run {run+1}: {elapsed:.2f}s, {len(report.threats_found)} threats")
        
        return {
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'avg_threats': statistics.mean(threats),
            'avg_files': statistics.mean(files_processed),
            'files_per_second': statistics.mean(files_processed) / statistics.mean(times)
        }
    
    def benchmark_parallel(self, test_dir: Path, workers: int = 4, runs: int = 3) -> Dict:
        """Benchmark parallel processing"""
        print(f"\n🚀 Benchmarking Parallel Processing ({workers} workers)...")
        
        times = []
        threats = []
        files_processed = []
        
        for run in range(runs):
            analyzer = ComprehensiveMCPAnalyzer(
                verbose=False, 
                enable_parallel=True,
                max_workers=workers,
                use_cache=False  # Disable cache for fair comparison
            )
            
            start_time = time.perf_counter()
            report = analyzer.analyze_repository(str(test_dir))
            elapsed = time.perf_counter() - start_time
            
            times.append(elapsed)
            threats.append(len(report.threats_found))
            files_processed.append(report.total_files_scanned)
            
            print(f"   Run {run+1}: {elapsed:.2f}s, {len(report.threats_found)} threats")
        
        return {
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'avg_threats': statistics.mean(threats),
            'avg_files': statistics.mean(files_processed),
            'files_per_second': statistics.mean(files_processed) / statistics.mean(times),
            'workers': workers
        }
    
    def run_comprehensive_benchmark(self):
        """Run comprehensive performance benchmarks"""
        print("\n" + "="*70)
        print("🏁 COMPREHENSIVE PERFORMANCE BENCHMARK")
        print("="*70)
        
        # Test different file counts and complexities
        test_configs = [
            (20, "low", "Small/Simple"),
            (50, "medium", "Medium/Moderate"),
            (100, "high", "Large/Complex"),
        ]
        
        all_results = []
        
        for file_count, complexity, description in test_configs:
            print(f"\n\n{'='*60}")
            print(f"📁 Testing: {description} ({file_count} files, {complexity} complexity)")
            print(f"{'='*60}")
            
            # Create test repository
            test_dir = self.create_test_repo(file_count, complexity)
            
            try:
                # Run sequential benchmark
                seq_results = self.benchmark_sequential(test_dir, runs=3)
                
                # Run parallel benchmarks with different worker counts
                par_results_2 = self.benchmark_parallel(test_dir, workers=2, runs=3)
                par_results_4 = self.benchmark_parallel(test_dir, workers=4, runs=3)
                
                # Calculate improvements
                speedup_2 = seq_results['avg_time'] / par_results_2['avg_time']
                speedup_4 = seq_results['avg_time'] / par_results_4['avg_time']
                
                # Store results
                result = {
                    'config': f"{file_count} files, {complexity} complexity",
                    'sequential': seq_results,
                    'parallel_2': par_results_2,
                    'parallel_4': par_results_4,
                    'speedup_2': speedup_2,
                    'speedup_4': speedup_4,
                    'consistency': abs(seq_results['avg_threats'] - par_results_4['avg_threats']) < 2
                }
                
                all_results.append(result)
                
                # Print summary for this configuration
                print(f"\n📈 Results for {description}:")
                print(f"   Sequential: {seq_results['avg_time']:.2f}s ({seq_results['files_per_second']:.1f} files/s)")
                print(f"   Parallel (2): {par_results_2['avg_time']:.2f}s ({par_results_2['files_per_second']:.1f} files/s) - {speedup_2:.2f}x speedup")
                print(f"   Parallel (4): {par_results_4['avg_time']:.2f}s ({par_results_4['files_per_second']:.1f} files/s) - {speedup_4:.2f}x speedup")
                
                # Check threat detection consistency
                if result['consistency']:
                    print(f"   ✅ Threat detection consistent: ~{seq_results['avg_threats']:.0f} threats")
                else:
                    print(f"   ⚠️  Threat detection varies: Seq={seq_results['avg_threats']:.0f}, Par={par_results_4['avg_threats']:.0f}")
                
            finally:
                # Cleanup
                import shutil
                shutil.rmtree(test_dir)
        
        # Final summary
        self._print_final_summary(all_results)
        
        return all_results
    
    def _print_final_summary(self, results: List[Dict]):
        """Print comprehensive summary of all benchmarks"""
        print("\n\n" + "="*70)
        print("📊 FINAL PERFORMANCE SUMMARY")
        print("="*70)
        
        # Calculate overall averages
        avg_speedup_2 = statistics.mean(r['speedup_2'] for r in results)
        avg_speedup_4 = statistics.mean(r['speedup_4'] for r in results)
        
        # Best and worst speedups
        best_speedup = max(max(r['speedup_2'], r['speedup_4']) for r in results)
        worst_speedup = min(min(r['speedup_2'], r['speedup_4']) for r in results)
        
        # Consistency check
        all_consistent = all(r['consistency'] for r in results)
        
        print("\n🎯 Key Metrics:")
        print(f"   Average Speedup (2 workers): {avg_speedup_2:.2f}x")
        print(f"   Average Speedup (4 workers): {avg_speedup_4:.2f}x")
        print(f"   Best Speedup: {best_speedup:.2f}x")
        print(f"   Worst Speedup: {worst_speedup:.2f}x")
        
        print("\n📈 Performance by Configuration:")
        for r in results:
            print(f"\n   {r['config']}:")
            print(f"      Sequential: {r['sequential']['files_per_second']:.1f} files/s")
            print(f"      Parallel (4): {r['parallel_4']['files_per_second']:.1f} files/s")
            print(f"      Speedup: {r['speedup_4']:.2f}x")
        
        print("\n✅ Validation:")
        if all_consistent:
            print("   ✅ All threat detection consistent between sequential and parallel")
        else:
            print("   ⚠️  Some inconsistencies in threat detection")
        
        # Performance rating
        print("\n🏆 Performance Rating:")
        if avg_speedup_4 >= 3.0:
            print("   ⭐⭐⭐⭐⭐ EXCELLENT - Massive performance gains!")
        elif avg_speedup_4 >= 2.0:
            print("   ⭐⭐⭐⭐ GREAT - Significant performance improvement!")
        elif avg_speedup_4 >= 1.5:
            print("   ⭐⭐⭐ GOOD - Noticeable performance boost")
        elif avg_speedup_4 >= 1.2:
            print("   ⭐⭐ FAIR - Some performance improvement")
        else:
            print("   ⭐ MINIMAL - Limited performance gains")
        
        # Save results to file
        results_file = Path(__file__).parent / "benchmark_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Detailed results saved to: {results_file}")


def main():
    """Run the performance benchmark suite"""
    benchmark = PerformanceBenchmark()
    
    print("🚀 Starting Comprehensive Performance Benchmark...")
    print("This will test parallel processing performance across various scenarios.")
    print("Please wait, this may take a few minutes...\n")
    
    try:
        results = benchmark.run_comprehensive_benchmark()
        
        # Determine exit code based on performance
        avg_speedup = statistics.mean(r['speedup_4'] for r in results)
        if avg_speedup >= 1.2:
            print("\n✅ Performance improvements validated!")
            sys.exit(0)
        else:
            print("\n⚠️  Limited performance improvements detected")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()