import re
from pathlib import Path
from typing import List, Dict, Any

class SASTScanner:
    """
    Static Application Security Testing (SAST) scanner.
    This scanner analyzes code for security vulnerabilities using static analysis techniques.
    """
    
    def __init__(self):
        # Initialize language-specific analyzers
        self.analyzers = {
            "python": self._analyze_python,
            "javascript": self._analyze_javascript,
            "java": self._analyze_java,
        }
        
        # Common vulnerability patterns
        self.common_patterns = {
            "hardcoded_secrets": r'(?i)(password|secret|token|key|api_key|apikey|access_key)\s*=\s*["\'][^"\']+["\']',
            "sql_injection": r'(?i)(execute|query)\s*\(\s*["\'][^"\']*\s*\+\s*',
            "command_injection": r'(?i)(system|exec|popen|subprocess\.call|subprocess\.Popen|eval|os\.system)\s*\(',
            "path_traversal": r'(?i)(open|file|read|write)\s*\(\s*["\'][^"\']*\.\.[^"\']*["\']',
            "insecure_hash": r'(?i)(md5|sha1)\s*\(',
        }
    
    def scan(self, file_path: Path, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Scan a file for security vulnerabilities using SAST techniques.
        
        Args:
            file_path: Path to the file
            content: Content of the file
            language: Programming language of the file
            
        Returns:
            List of vulnerability findings
        """
        results = []
        
        # Check for common vulnerabilities across all languages
        common_results = self._check_common_patterns(file_path, content)
        results.extend(common_results)
        
        # Run language-specific analysis if available
        if language.lower() in self.analyzers:
            language_results = self.analyzers[language.lower()](file_path, content)
            results.extend(language_results)
        
        return results
    
    def _check_common_patterns(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Check for common vulnerability patterns across all languages."""
        results = []
        
        for vuln_type, pattern in self.common_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Calculate line number
                line_number = content[:match.start()].count('\n') + 1
                
                # Map vulnerability type to a more readable name and severity
                vuln_info = self._get_vulnerability_info(vuln_type)
                
                results.append({
                    "vulnerability_type": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "line_number": line_number,
                    "file_path": str(file_path),
                    "description": vuln_info["description"],
                    "recommendation": vuln_info["recommendation"]
                })
        
        return results
    
    def _get_vulnerability_info(self, vuln_type: str) -> Dict[str, str]:
        """Get detailed information about a vulnerability type."""
        vulnerability_info = {
            "hardcoded_secrets": {
                "name": "Hardcoded Secrets",
                "severity": "high",
                "description": "Hardcoded credentials or secrets were found in the code.",
                "recommendation": "Store secrets in environment variables or a secure vault."
            },
            "sql_injection": {
                "name": "SQL Injection",
                "severity": "critical",
                "description": "Potential SQL injection vulnerability detected.",
                "recommendation": "Use parameterized queries or prepared statements."
            },
            "command_injection": {
                "name": "Command Injection",
                "severity": "critical",
                "description": "Potential command injection vulnerability detected.",
                "recommendation": "Avoid using shell commands with user input. If necessary, use proper input validation and sanitization."
            },
            "path_traversal": {
                "name": "Path Traversal",
                "severity": "high",
                "description": "Potential path traversal vulnerability detected.",
                "recommendation": "Validate and sanitize file paths. Use path normalization functions."
            },
            "insecure_hash": {
                "name": "Insecure Hash Algorithm",
                "severity": "medium",
                "description": "Usage of cryptographically weak hash algorithm detected.",
                "recommendation": "Use strong cryptographic hash functions like SHA-256 or SHA-3."
            }
        }
        
        return vulnerability_info.get(vuln_type, {
            "name": vuln_type.replace("_", " ").title(),
            "severity": "medium",
            "description": f"Potential {vuln_type.replace('_', ' ')} issue detected.",
            "recommendation": "Review the code for security issues."
        })
    
    def _analyze_python(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Analyze Python code for security vulnerabilities."""
        results = []
        
        # Python-specific patterns
        python_patterns = {
            "pickle_deserialization": (
                r'(?i)(pickle\.loads|pickle\.load|cPickle\.loads|cPickle\.load)',
                {
                    "name": "Insecure Deserialization",
                    "severity": "high",
                    "description": "Insecure deserialization using pickle module detected.",
                    "recommendation": "Avoid using pickle for untrusted data. Consider using JSON or other safer alternatives."
                }
            ),
            "yaml_load": (
                r'(?i)yaml\.load\s*\(',
                {
                    "name": "Unsafe YAML Loading",
                    "severity": "medium",
                    "description": "Unsafe YAML loading detected. This can lead to arbitrary code execution.",
                    "recommendation": "Use yaml.safe_load() instead of yaml.load()."
                }
            ),
            "debug_enabled": (
                r'(?i)(DEBUG\s*=\s*True|DEBUG\s*=\s*1)',
                {
                    "name": "Debug Mode Enabled",
                    "severity": "low",
                    "description": "Debug mode appears to be enabled in production code.",
                    "recommendation": "Disable debug mode in production environments."
                }
            ),
            "flask_debug": (
                r'(?i)app\.run\s*\(.*debug\s*=\s*True',
                {
                    "name": "Flask Debug Mode",
                    "severity": "medium",
                    "description": "Flask application is running in debug mode, which is not secure for production.",
                    "recommendation": "Disable Flask debug mode in production environments."
                }
            ),
        }
        
        for vuln_type, (pattern, vuln_info) in python_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                results.append({
                    "vulnerability_type": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "line_number": line_number,
                    "file_path": str(file_path),
                    "description": vuln_info["description"],
                    "recommendation": vuln_info["recommendation"]
                })
        
        return results
    
    def _analyze_javascript(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript code for security vulnerabilities."""
        results = []
        
        # JavaScript-specific patterns
        js_patterns = {
            "eval_usage": (
                r'(?i)(eval|setTimeout|setInterval)\s*\(\s*["\']',
                {
                    "name": "Dangerous Function Evaluation",
                    "severity": "high",
                    "description": "Usage of eval() or other functions that can execute strings as code.",
                    "recommendation": "Avoid using eval() and similar functions. Use safer alternatives."
                }
            ),
            "dom_xss": (
                r'(?i)(innerHTML|outerHTML|document\.write|document\.writeln)\s*=',
                {
                    "name": "DOM-based XSS",
                    "severity": "high",
                    "description": "Potential DOM-based XSS vulnerability detected.",
                    "recommendation": "Use textContent or innerText instead of innerHTML when possible. Otherwise, sanitize input properly."
                }
            ),
            "insecure_jwt": (
                r'(?i)(jwt\.sign|jwt\.verify).*algorithm\s*:\s*["\']none["\']',
                {
                    "name": "Insecure JWT Configuration",
                    "severity": "critical",
                    "description": "JWT is configured with 'none' algorithm, which is insecure.",
                    "recommendation": "Use a secure algorithm like HS256 or RS256 for JWT."
                }
            ),
            "cors_all_origins": (
                r'(?i)(Access-Control-Allow-Origin\s*:\s*\*|res\.header\s*\(\s*["\']Access-Control-Allow-Origin["\']?\s*,\s*["\']?\*["\']?\s*\))',
                {
                    "name": "Insecure CORS Configuration",
                    "severity": "medium",
                    "description": "CORS is configured to allow all origins, which may lead to security issues.",
                    "recommendation": "Restrict CORS to specific trusted origins instead of using a wildcard."
                }
            ),
        }
        
        for vuln_type, (pattern, vuln_info) in js_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                results.append({
                    "vulnerability_type": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "line_number": line_number,
                    "file_path": str(file_path),
                    "description": vuln_info["description"],
                    "recommendation": vuln_info["recommendation"]
                })
        
        return results
    
    def _analyze_java(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Analyze Java code for security vulnerabilities."""
        results = []
        
        # Java-specific patterns
        java_patterns = {
            "xxe_vulnerability": (
                r'(?i)(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory).*\.setFeature\s*\(\s*["\']http://javax\.xml\.XMLConstants/feature/secure-processing["\']?\s*,\s*false\s*\)',
                {
                    "name": "XML External Entity (XXE) Vulnerability",
                    "severity": "critical",
                    "description": "XML processing is configured insecurely, which may lead to XXE attacks.",
                    "recommendation": "Enable secure XML processing features and disable external entity resolution."
                }
            ),
            "weak_cipher": (
                r'(?i)(DES|DESede|RC2|RC4|Blowfish)(?!.*AES)',
                {
                    "name": "Weak Cryptographic Algorithm",
                    "severity": "high",
                    "description": "Usage of cryptographically weak algorithm detected.",
                    "recommendation": "Use strong cryptographic algorithms like AES with appropriate key sizes."
                }
            ),
            "predictable_random": (
                r'(?i)new\s+Random\s*\(\s*\)',
                {
                    "name": "Predictable Random",
                    "severity": "medium",
                    "description": "Usage of java.util.Random, which is not cryptographically secure.",
                    "recommendation": "Use java.security.SecureRandom for cryptographic purposes."
                }
            ),
            "hardcoded_ip": (
                r'(?i)(\b(?:\d{1,3}\.){3}\d{1,3}\b)',
                {
                    "name": "Hardcoded IP Address",
                    "severity": "low",
                    "description": "Hardcoded IP address found in the code.",
                    "recommendation": "Store IP addresses in configuration files or environment variables."
                }
            ),
        }
        
        for vuln_type, (pattern, vuln_info) in java_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                results.append({
                    "vulnerability_type": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "line_number": line_number,
                    "file_path": str(file_path),
                    "description": vuln_info["description"],
                    "recommendation": vuln_info["recommendation"]
                })
        
        return results
