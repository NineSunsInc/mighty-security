#!/usr/bin/env python3
"""
SQL Injection Detection Patterns for MCP Database Servers
Specifically designed for MySQL, PostgreSQL, SQLite MCP servers
"""

import re
from typing import List, Dict

# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    # String concatenation SQL
    (r'["\']SELECT.*["\'].*\+(?!.*\?)', 'SQL_CONCAT_SELECT', 'CRITICAL', 'SQL injection via string concatenation in SELECT'),
    (r'["\']INSERT.*["\'].*\+(?!.*\?)', 'SQL_CONCAT_INSERT', 'CRITICAL', 'SQL injection via string concatenation in INSERT'),
    (r'["\']UPDATE.*["\'].*\+(?!.*\?)', 'SQL_CONCAT_UPDATE', 'CRITICAL', 'SQL injection via string concatenation in UPDATE'),
    (r'["\']DELETE.*["\'].*\+(?!.*\?)', 'SQL_CONCAT_DELETE', 'CRITICAL', 'SQL injection via string concatenation in DELETE'),
    
    # Template literal SQL injection
    (r'`.*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{[^}]+\}.*`', 'SQL_TEMPLATE_LITERAL', 'CRITICAL', 'SQL injection via template literals'),
    
    # Format string SQL
    (r'(?:query|execute|run)\s*\([^)]*%[sd]', 'SQL_FORMAT_STRING', 'CRITICAL', 'SQL injection via format strings'),
    (r'(?:sprintf|format)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', 'SQL_SPRINTF', 'CRITICAL', 'SQL built with sprintf/format'),
    
    # Direct query execution without parameters
    (r'\.(?:query|execute|run)\s*\([^,)]*(?:SELECT|INSERT|UPDATE|DELETE)[^,)]*\)(?!\s*,)', 'SQL_NO_PARAMS', 'HIGH', 'SQL query without parameters'),
    
    # Dynamic table/column names
    (r'(?:FROM|INTO|UPDATE)\s+["\']?\s*\+[^+]+\+', 'DYNAMIC_TABLE_NAME', 'HIGH', 'Dynamic table name in SQL'),
    (r'(?:SELECT|SET)\s+["\']?\s*\+[^+]+\+', 'DYNAMIC_COLUMN_NAME', 'HIGH', 'Dynamic column name in SQL'),
    
    # Dangerous SQL functions
    (r'LOAD_FILE\s*\(', 'SQL_LOAD_FILE', 'CRITICAL', 'LOAD_FILE can read server files'),
    (r'INTO\s+OUTFILE', 'SQL_INTO_OUTFILE', 'CRITICAL', 'INTO OUTFILE can write server files'),
    (r'INTO\s+DUMPFILE', 'SQL_INTO_DUMPFILE', 'CRITICAL', 'INTO DUMPFILE can write server files'),
    
    # NoSQL Injection patterns
    (r'\$where.*:.*["\'].*\+', 'NOSQL_WHERE_INJECTION', 'CRITICAL', 'NoSQL $where injection'),
    (r'\$regex.*:.*(?:req\.|request\.|params\.)', 'NOSQL_REGEX_INJECTION', 'HIGH', 'NoSQL $regex injection'),
    
    # SQL command execution
    (r'xp_cmdshell', 'SQL_XP_CMDSHELL', 'CRITICAL', 'SQL Server command execution'),
    (r'sys_exec|sys_eval', 'MYSQL_SYS_EXEC', 'CRITICAL', 'MySQL UDF command execution'),
    
    # Common vulnerable patterns
    (r'mysql_query\s*\([^)]*\$_(?:GET|POST|REQUEST)', 'PHP_SQL_INJECTION', 'CRITICAL', 'Direct PHP SQL injection'),
    (r'mysqli?_query\s*\([^)]*\.\s*\$', 'PHP_MYSQLI_INJECTION', 'CRITICAL', 'MySQLi SQL injection'),
]

# Database credential patterns
DB_CREDENTIAL_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']', 'DB_PASSWORD_HARDCODED', 'HIGH', 'Hardcoded database password'),
    (r'(?:mysql|postgres|mongodb)://[^@]+@', 'DB_CONNECTION_STRING', 'HIGH', 'Database connection string with credentials'),
    (r'Data Source=.*;Password=', 'SQL_SERVER_CONN_STRING', 'HIGH', 'SQL Server connection string with password'),
]

# Unsafe database operations
UNSAFE_DB_PATTERNS = [
    (r'GRANT ALL PRIVILEGES', 'GRANT_ALL_PRIVILEGES', 'HIGH', 'Granting all privileges is dangerous'),
    (r'IDENTIFIED BY\s+["\'][^"\']+["\']', 'PASSWORD_IN_GRANT', 'HIGH', 'Password visible in GRANT statement'),
    (r'CREATE USER.*IDENTIFIED BY', 'CREATE_USER_PASSWORD', 'HIGH', 'Password in CREATE USER'),
    (r'(?:DROP|TRUNCATE)\s+(?:DATABASE|TABLE)', 'DESTRUCTIVE_SQL', 'HIGH', 'Destructive SQL operation'),
    (r'SET GLOBAL', 'SET_GLOBAL_VAR', 'MEDIUM', 'Changing global database variables'),
]

def detect_sql_injection(code: str, filename: str = "") -> List[Dict]:
    """
    Detect SQL injection vulnerabilities in code
    """
    threats = []
    
    all_patterns = [
        ('SQL_INJECTION', SQL_INJECTION_PATTERNS),
        ('DB_CREDENTIAL', DB_CREDENTIAL_PATTERNS),
        ('UNSAFE_DB', UNSAFE_DB_PATTERNS)
    ]
    
    for category, patterns in all_patterns:
        for pattern, threat_type, severity, description in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                threats.append({
                    'category': category,
                    'type': threat_type,
                    'severity': severity,
                    'description': description,
                    'file': filename,
                    'line': code[:match.start()].count('\n') + 1,
                    'evidence': match.group(0)[:100]
                })
    
    return threats

def test_sql_detection():
    """Test SQL injection detection"""
    
    test_cases = [
        # Vulnerable
        ("query = 'SELECT * FROM users WHERE id = ' + userId", True),
        ("sql = `DELETE FROM table WHERE name = '${userInput}'`", True),
        ("db.query('SELECT * FROM ' + tableName)", True),
        ("mysql_query('SELECT * FROM users WHERE id = ' . $_GET['id'])", True),
        
        # Safe
        ("db.query('SELECT * FROM users WHERE id = ?', [userId])", False),
        ("stmt = conn.prepare('INSERT INTO users VALUES (?, ?)')", False),
    ]
    
    print("SQL Injection Detection Test")
    print("="*50)
    
    for code, should_detect in test_cases:
        threats = detect_sql_injection(code)
        detected = len(threats) > 0
        
        if detected == should_detect:
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        print(f"{status}: {code[:50]}...")
        if threats:
            print(f"   Found: {threats[0]['type']}")
    
    print("\n✅ SQL injection patterns loaded!")

if __name__ == "__main__":
    test_sql_detection()