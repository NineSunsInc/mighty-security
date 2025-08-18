"""
Sample pytest tests using the new fixtures
"""

import pytest
from pathlib import Path


class TestAnalyzerWithFixtures:
    """Test analyzer using pytest fixtures"""
    
    def test_analyzer_initialization(self, analyzer):
        """Test that analyzer initializes correctly"""
        assert analyzer is not None
        assert not analyzer.enable_parallel
        assert not analyzer.use_cache
    
    def test_parallel_analyzer(self, parallel_analyzer):
        """Test parallel analyzer configuration"""
        assert parallel_analyzer.enable_parallel
        assert parallel_analyzer.max_workers == 2
    
    def test_safe_code_analysis(self, analyzer, temp_dir, safe_python_file):
        """Test that safe code produces no threats"""
        # Create safe file
        safe_file = temp_dir / "safe.py"
        safe_file.write_text(safe_python_file)
        
        # Analyze
        report = analyzer.analyze_repository(str(temp_dir))
        
        # Should find minimal or no threats
        assert report.threat_score < 0.3
        assert report.total_files_scanned > 0
    
    def test_malicious_code_detection(self, analyzer, temp_dir, malicious_python_file):
        """Test that malicious code is detected"""
        # Create malicious file
        mal_file = temp_dir / "malicious.py"
        mal_file.write_text(malicious_python_file)
        
        # Analyze
        report = analyzer.analyze_repository(str(temp_dir))
        
        # Should find threats
        assert len(report.threats_found) > 0
        assert report.threat_score > 0.5
    
    @pytest.mark.slow
    def test_performance_with_many_files(self, analyzer, performance_test_files):
        """Test performance with 100 files"""
        import time
        
        start = time.perf_counter()
        report = analyzer.analyze_repository(str(performance_test_files[0].parent))
        duration = time.perf_counter() - start
        
        files_per_second = report.total_files_scanned / duration
        
        # Should process at least 100 files/second
        assert files_per_second >= 100
        assert report.total_files_scanned == 100


class TestMCPProjectAnalysis:
    """Test MCP-specific project analysis"""
    
    def test_mcp_project_structure(self, analyzer, mcp_project):
        """Test analysis of MCP project"""
        report = analyzer.analyze_repository(str(mcp_project))
        
        assert report.total_files_scanned >= 2  # At least server.py and test_tool.py
        assert "mcp.json" in str(mcp_project / "mcp.json")
    
    def test_malicious_mcp_tool(self, analyzer, temp_dir, malicious_mcp_tool):
        """Test detection of malicious MCP tool"""
        tool_file = temp_dir / "dangerous_tool.py"
        tool_file.write_text(malicious_mcp_tool)
        
        report = analyzer.analyze_repository(str(temp_dir))
        
        # Should detect command injection and eval
        threat_types = {str(t.attack_vector) for t in report.threats_found}
        assert any("COMMAND_INJECTION" in t for t in threat_types)
    
    def test_safe_mcp_tool(self, analyzer, temp_dir, safe_mcp_tool):
        """Test that safe MCP tool is not flagged"""
        tool_file = temp_dir / "json_formatter.py"
        tool_file.write_text(safe_mcp_tool)
        
        report = analyzer.analyze_repository(str(temp_dir))
        
        # Should not find significant threats
        assert report.threat_score < 0.3


class TestHelperFixtures:
    """Test the helper assertion fixtures"""
    
    def test_assert_no_threats_helper(self, analyzer, temp_dir, safe_python_file, assert_no_threats):
        """Test the assert_no_threats helper"""
        safe_file = temp_dir / "safe.py"
        safe_file.write_text(safe_python_file)
        
        report = analyzer.analyze_repository(str(temp_dir))
        assert_no_threats(report)
    
    def test_assert_has_threats_helper(self, analyzer, temp_dir, malicious_python_file, assert_has_threats):
        """Test the assert_has_threats helper"""
        mal_file = temp_dir / "mal.py"
        mal_file.write_text(malicious_python_file)
        
        report = analyzer.analyze_repository(str(temp_dir))
        assert_has_threats(report, min_threats=5)
    
    def test_timer_fixture(self, benchmark_timer):
        """Test the benchmark timer fixture"""
        import time
        
        benchmark_timer.start()
        time.sleep(0.1)
        benchmark_timer.stop()
        
        assert 0.09 < benchmark_timer.elapsed < 0.11