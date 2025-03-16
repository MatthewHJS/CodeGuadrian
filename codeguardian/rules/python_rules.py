"""
Python security rules for CodeGuardian.

This module defines patterns and rules for detecting security vulnerabilities
in Python code.
"""

# List of rules for Python code
PYTHON_RULES = [
    {
        "id": "PY001",
        "name": "Use of exec function",
        "pattern": r"\bexec\s*\(",
        "severity": "high",
        "description": "The exec function can execute arbitrary code, which is a security risk.",
        "recommendation": "Avoid using exec. Use safer alternatives."
    },
    {
        "id": "PY002",
        "name": "Use of eval function",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "description": "The eval function can execute arbitrary code, which is a security risk.",
        "recommendation": "Avoid using eval. Use safer alternatives like ast.literal_eval for parsing safe expressions."
    },
    {
        "id": "PY003",
        "name": "SQL Injection Risk",
        "pattern": r"cursor\.execute\s*\(\s*[\"'][^\"']*\s*%\s*[^\"']*[\"']",
        "severity": "critical",
        "description": "String formatting in SQL queries can lead to SQL injection vulnerabilities.",
        "recommendation": "Use parameterized queries with placeholders (?, :name) instead of string formatting."
    },
    {
        "id": "PY004",
        "name": "Insecure Pickle Usage",
        "pattern": r"(pickle|cPickle)\.(loads|load)",
        "severity": "high",
        "description": "Unpickling data from untrusted sources can lead to remote code execution.",
        "recommendation": "Avoid using pickle for untrusted data. Consider using JSON or other safer alternatives."
    },
    {
        "id": "PY005",
        "name": "Insecure YAML Loading",
        "pattern": r"yaml\.load\s*\(",
        "severity": "medium",
        "description": "Using yaml.load can lead to arbitrary code execution if the YAML is from an untrusted source.",
        "recommendation": "Use yaml.safe_load() instead of yaml.load()."
    },
    {
        "id": "PY006",
        "name": "Command Injection Risk",
        "pattern": r"(os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\(\s*[\"'][^\"']*\s*\+",
        "severity": "critical",
        "description": "String concatenation in shell commands can lead to command injection vulnerabilities.",
        "recommendation": "Use subprocess.run with a list of arguments instead of string concatenation."
    },
    {
        "id": "PY007",
        "name": "Insecure Temporary File Creation",
        "pattern": r"(tempfile\.mktemp|os\.tempnam|os\.tmpnam)",
        "severity": "medium",
        "description": "These functions create temporary files insecurely, which can lead to race conditions.",
        "recommendation": "Use tempfile.mkstemp(), tempfile.mkdtemp(), or tempfile.TemporaryFile() instead."
    },
    {
        "id": "PY008",
        "name": "Hardcoded Password",
        "pattern": r"(password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']",
        "severity": "high",
        "description": "Hardcoded passwords in source code are a security risk.",
        "recommendation": "Store passwords in environment variables or a secure vault."
    },
    {
        "id": "PY009",
        "name": "Insecure Hash Function",
        "pattern": r"(hashlib\.(md5|sha1)|md5|sha1)\(",
        "severity": "medium",
        "description": "MD5 and SHA1 are cryptographically weak hash functions.",
        "recommendation": "Use stronger hash functions like SHA-256, SHA-3, or bcrypt for passwords."
    },
    {
        "id": "PY010",
        "name": "Debug Mode Enabled",
        "pattern": r"(DEBUG|debug)\s*=\s*(True|1)",
        "severity": "low",
        "description": "Debug mode should not be enabled in production code.",
        "recommendation": "Disable debug mode in production environments."
    },
    {
        "id": "PY011",
        "name": "Insecure Random Number Generation",
        "pattern": r"random\.(random|randint|randrange|choice|choices|sample|shuffle)",
        "severity": "medium",
        "description": "The random module uses a predictable algorithm and should not be used for security purposes.",
        "recommendation": "Use secrets module for cryptographic purposes instead of the random module."
    },
    {
        "id": "PY012",
        "name": "Flask Debug Mode",
        "pattern": r"app\.run\s*\(.*debug\s*=\s*True",
        "severity": "medium",
        "description": "Flask debug mode should not be enabled in production.",
        "recommendation": "Disable Flask debug mode in production environments."
    },
    {
        "id": "PY013",
        "name": "Django CSRF Protection Disabled",
        "pattern": r"@csrf_exempt",
        "severity": "high",
        "description": "CSRF protection is disabled for this view, which can lead to CSRF vulnerabilities.",
        "recommendation": "Only disable CSRF protection when absolutely necessary, and implement alternative protections."
    },
    {
        "id": "PY014",
        "name": "Insecure File Permissions",
        "pattern": r"os\.chmod\s*\(.*0o*777",
        "severity": "medium",
        "description": "Setting file permissions to 777 (world-writable) is insecure.",
        "recommendation": "Use more restrictive permissions, such as 0o600 for sensitive files."
    },
    {
        "id": "PY015",
        "name": "Use of assert Statements",
        "pattern": r"\bassert\b",
        "severity": "low",
        "description": "Assert statements are removed when compiling to optimized byte code (python -O).",
        "recommendation": "Use proper error handling instead of assert statements."
    }
]

def get_rules():
    """Return the list of Python rules."""
    return PYTHON_RULES
