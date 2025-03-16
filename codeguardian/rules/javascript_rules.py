"""
JavaScript security rules for CodeGuardian.

This module defines patterns and rules for detecting security vulnerabilities
in JavaScript code.
"""

# List of rules for JavaScript code
JAVASCRIPT_RULES = [
    {
        "id": "JS001",
        "name": "Use of eval function",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "description": "The eval function can execute arbitrary code, which is a security risk.",
        "recommendation": "Avoid using eval. Use safer alternatives."
    },
    {
        "id": "JS002",
        "name": "Use of document.write",
        "pattern": r"document\.write\s*\(",
        "severity": "medium",
        "description": "document.write can lead to XSS vulnerabilities and is considered bad practice.",
        "recommendation": "Use DOM manipulation methods instead, such as appendChild or innerHTML with proper sanitization."
    },
    {
        "id": "JS003",
        "name": "Insecure innerHTML Usage",
        "pattern": r"\.innerHTML\s*=",
        "severity": "medium",
        "description": "Setting innerHTML with unsanitized input can lead to XSS vulnerabilities.",
        "recommendation": "Use textContent for text or DOMPurify to sanitize HTML before using innerHTML."
    },
    {
        "id": "JS004",
        "name": "Use of setTimeout with String",
        "pattern": r"setTimeout\s*\(\s*['\"]",
        "severity": "medium",
        "description": "Using setTimeout with a string argument is similar to eval and can lead to code injection.",
        "recommendation": "Use a function reference instead of a string in setTimeout."
    },
    {
        "id": "JS005",
        "name": "Use of setInterval with String",
        "pattern": r"setInterval\s*\(\s*['\"]",
        "severity": "medium",
        "description": "Using setInterval with a string argument is similar to eval and can lead to code injection.",
        "recommendation": "Use a function reference instead of a string in setInterval."
    },
    {
        "id": "JS006",
        "name": "Hardcoded JWT Secret",
        "pattern": r"(jwt\.sign|jwt\.verify)\s*\(.*['\"][^'\"]+['\"]",
        "severity": "high",
        "description": "Hardcoded JWT secrets in source code are a security risk.",
        "recommendation": "Store JWT secrets in environment variables or a secure vault."
    },
    {
        "id": "JS007",
        "name": "Insecure Cryptographic Algorithm",
        "pattern": r"(createHash|crypto\.createHash)\s*\(\s*['\"]md5['\"]",
        "severity": "medium",
        "description": "MD5 is a cryptographically weak hash function.",
        "recommendation": "Use stronger hash functions like SHA-256 or SHA-3."
    },
    {
        "id": "JS008",
        "name": "Insecure Randomness",
        "pattern": r"Math\.random\s*\(",
        "severity": "low",
        "description": "Math.random() is not cryptographically secure and should not be used for security purposes.",
        "recommendation": "Use crypto.getRandomValues() for cryptographic purposes."
    },
    {
        "id": "JS009",
        "name": "Hardcoded Password",
        "pattern": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "high",
        "description": "Hardcoded passwords in source code are a security risk.",
        "recommendation": "Store passwords in environment variables or a secure vault."
    },
    {
        "id": "JS010",
        "name": "Insecure Cookie Settings",
        "pattern": r"document\.cookie\s*=\s*[^;]+((?!secure).)*$",
        "severity": "medium",
        "description": "Cookies without the 'secure' flag can be transmitted over unencrypted connections.",
        "recommendation": "Set the 'secure' and 'httpOnly' flags for sensitive cookies."
    },
    {
        "id": "JS011",
        "name": "Potential Prototype Pollution",
        "pattern": r"Object\.assign\s*\(\s*[^,]+\s*,",
        "severity": "medium",
        "description": "Merging objects without proper validation can lead to prototype pollution.",
        "recommendation": "Use a safe object merging library or validate inputs before merging."
    },
    {
        "id": "JS012",
        "name": "Use of console.log",
        "pattern": r"console\.log\s*\(",
        "severity": "info",
        "description": "console.log statements should not be included in production code.",
        "recommendation": "Remove console.log statements or use a proper logging library."
    },
    {
        "id": "JS013",
        "name": "Insecure Regular Expression",
        "pattern": r"(\.match|\.test|\.exec|RegExp)\s*\(\s*['\"][^'\"]*(\.\*|\.\+|\\\w\+)[^'\"]*['\"]",
        "severity": "medium",
        "description": "Regular expressions with unbounded repetition can lead to ReDoS (Regular Expression Denial of Service) attacks.",
        "recommendation": "Avoid using patterns with unbounded repetition or implement proper input validation."
    },
    {
        "id": "JS014",
        "name": "Insecure Cross-Origin Resource Sharing",
        "pattern": r"(Access-Control-Allow-Origin:\s*\*|res\.header\s*\(\s*['\"]Access-Control-Allow-Origin['\"]?\s*,\s*['\"]?\*['\"]?\s*\))",
        "severity": "medium",
        "description": "CORS is configured to allow all origins, which may lead to security issues.",
        "recommendation": "Restrict CORS to specific trusted origins instead of using a wildcard."
    },
    {
        "id": "JS015",
        "name": "Use of Function Constructor",
        "pattern": r"new\s+Function\s*\(",
        "severity": "high",
        "description": "The Function constructor is similar to eval and can execute arbitrary code.",
        "recommendation": "Avoid using the Function constructor. Use regular functions instead."
    }
]

def get_rules():
    """Return the list of JavaScript rules."""
    return JAVASCRIPT_RULES
