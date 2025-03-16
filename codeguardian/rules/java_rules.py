"""
Java security rules for CodeGuardian.

This module defines patterns and rules for detecting security vulnerabilities
in Java code.
"""

# List of rules for Java code
JAVA_RULES = [
    {
        "id": "JV001",
        "name": "Use of System.out.println",
        "pattern": r"System\.out\.println\s*\(",
        "severity": "low",
        "description": "System.out.println should not be used in production code.",
        "recommendation": "Use a proper logging framework like SLF4J or Log4j."
    },
    {
        "id": "JV002",
        "name": "Catching Generic Exception",
        "pattern": r"catch\s*\(\s*Exception\s+",
        "severity": "medium",
        "description": "Catching generic exceptions can hide errors and make debugging difficult.",
        "recommendation": "Catch specific exceptions instead of generic Exception class."
    },
    {
        "id": "JV003",
        "name": "SQL Injection Risk",
        "pattern": r"(executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\s*\+\s*[^\"]*\"",
        "severity": "critical",
        "description": "String concatenation in SQL queries can lead to SQL injection vulnerabilities.",
        "recommendation": "Use PreparedStatement with placeholders (?) instead of string concatenation."
    },
    {
        "id": "JV004",
        "name": "Hardcoded Password",
        "pattern": r"(password|passwd|pwd)\s*=\s*\"[^\"]+\"",
        "severity": "high",
        "description": "Hardcoded passwords in source code are a security risk.",
        "recommendation": "Store passwords in environment variables or a secure vault."
    },
    {
        "id": "JV005",
        "name": "Insecure Random Number Generation",
        "pattern": r"new\s+Random\s*\(",
        "severity": "medium",
        "description": "java.util.Random is not cryptographically secure and should not be used for security purposes.",
        "recommendation": "Use java.security.SecureRandom for cryptographic purposes."
    },
    {
        "id": "JV006",
        "name": "XML External Entity (XXE) Vulnerability",
        "pattern": r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)",
        "severity": "high",
        "description": "XML parsers are vulnerable to XXE attacks if not properly configured.",
        "recommendation": "Configure XML parsers to disable external entity resolution."
    },
    {
        "id": "JV007",
        "name": "Insecure Deserialization",
        "pattern": r"(ObjectInputStream|readObject|readUnshared)",
        "severity": "high",
        "description": "Deserializing untrusted data can lead to remote code execution.",
        "recommendation": "Validate and sanitize data before deserialization, or use safer alternatives like JSON."
    },
    {
        "id": "JV008",
        "name": "Insecure Cryptographic Algorithm",
        "pattern": r"(\"DES\"|\"RC2\"|\"RC4\"|\"Blowfish\"|\"MD5\"|\"SHA-1\")",
        "severity": "medium",
        "description": "Weak cryptographic algorithms should not be used.",
        "recommendation": "Use strong cryptographic algorithms like AES-256, SHA-256, or SHA-3."
    },
    {
        "id": "JV009",
        "name": "Insecure File Permissions",
        "pattern": r"setReadable\s*\(\s*true\s*,\s*false\s*\)",
        "severity": "medium",
        "description": "Setting file permissions to world-readable is insecure.",
        "recommendation": "Use more restrictive file permissions."
    },
    {
        "id": "JV010",
        "name": "Command Injection Risk",
        "pattern": r"(Runtime\.exec|ProcessBuilder)\s*\(\s*\"[^\"]*\s*\+\s*[^\"]*\"",
        "severity": "critical",
        "description": "String concatenation in shell commands can lead to command injection vulnerabilities.",
        "recommendation": "Use ProcessBuilder with a list of arguments instead of string concatenation."
    },
    {
        "id": "JV011",
        "name": "Insecure Cookie Settings",
        "pattern": r"(Cookie|HttpCookie).*setSecure\s*\(\s*false\s*\)",
        "severity": "medium",
        "description": "Cookies without the 'secure' flag can be transmitted over unencrypted connections.",
        "recommendation": "Set the 'secure' and 'httpOnly' flags for sensitive cookies."
    },
    {
        "id": "JV012",
        "name": "Path Traversal Risk",
        "pattern": r"new\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(\s*[^)]*\s*\+\s*[^)]*\)",
        "severity": "high",
        "description": "String concatenation in file paths can lead to path traversal vulnerabilities.",
        "recommendation": "Validate and sanitize file paths. Use Path.normalize() to resolve paths safely."
    },
    {
        "id": "JV013",
        "name": "Insecure Cipher Mode",
        "pattern": r"Cipher\.getInstance\s*\(\s*\"[^\"]*\/ECB[^\"]*\"",
        "severity": "high",
        "description": "ECB mode is cryptographically weak and should not be used.",
        "recommendation": "Use a secure mode like CBC or GCM with proper padding and IV."
    },
    {
        "id": "JV014",
        "name": "Hardcoded IP Address",
        "pattern": r"\"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\"",
        "severity": "low",
        "description": "Hardcoded IP addresses in source code make it difficult to change environments.",
        "recommendation": "Store IP addresses in configuration files or environment variables."
    },
    {
        "id": "JV015",
        "name": "Insecure Hash Storage",
        "pattern": r"(MD5|SHA1).*password",
        "severity": "high",
        "description": "Passwords should not be hashed with weak algorithms like MD5 or SHA-1.",
        "recommendation": "Use bcrypt, PBKDF2, or Argon2 for password hashing."
    }
]

def get_rules():
    """Return the list of Java rules."""
    return JAVA_RULES
