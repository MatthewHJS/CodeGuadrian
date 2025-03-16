import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import os

class PatternScanner:
    """
    Pattern-based scanner that looks for specific patterns in code.
    This scanner uses regular expressions to identify potential issues.
    """
    
    def __init__(self):
        # Load rules from rules directory if available
        self.rules = self._load_rules()
    
    def _load_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load pattern rules from rules directory."""
        rules = {
            "python": [],
            "javascript": [],
            "java": [],
            "generic": []
        }
        
        # Define some default rules in case the files don't exist
        default_rules = {
            "python": [
                {
                    "id": "PY001",
                    "name": "Use of assert statements",
                    "pattern": r"\bassert\b",
                    "severity": "low",
                    "description": "Assert statements are removed when compiling to optimized byte code (python -O).",
                    "recommendation": "Use proper error handling instead of assert statements."
                },
                {
                    "id": "PY002",
                    "name": "Use of exec function",
                    "pattern": r"\bexec\s*\(",
                    "severity": "high",
                    "description": "The exec function can execute arbitrary code, which is a security risk.",
                    "recommendation": "Avoid using exec. Use safer alternatives."
                }
            ],
            "javascript": [
                {
                    "id": "JS001",
                    "name": "Use of console.log",
                    "pattern": r"console\.log\s*\(",
                    "severity": "low",
                    "description": "Console.log statements should not be included in production code.",
                    "recommendation": "Remove console.log statements or use a proper logging library."
                },
                {
                    "id": "JS002",
                    "name": "Use of document.write",
                    "pattern": r"document\.write\s*\(",
                    "severity": "medium",
                    "description": "document.write can lead to XSS vulnerabilities and is considered bad practice.",
                    "recommendation": "Use DOM manipulation methods instead."
                }
            ],
            "java": [
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
                    "name": "Catching generic Exception",
                    "pattern": r"catch\s*\(\s*Exception\s+",
                    "severity": "medium",
                    "description": "Catching generic exceptions can hide errors and make debugging difficult.",
                    "recommendation": "Catch specific exceptions instead of generic Exception class."
                }
            ],
            "generic": [
                {
                    "id": "GEN001",
                    "name": "TODO comment",
                    "pattern": r"(?://|#|/\*)\s*TODO",
                    "severity": "info",
                    "description": "TODO comment found in code.",
                    "recommendation": "Address the TODO comment before finalizing the code."
                },
                {
                    "id": "GEN002",
                    "name": "FIXME comment",
                    "pattern": r"(?://|#|/\*)\s*FIXME",
                    "severity": "low",
                    "description": "FIXME comment found in code.",
                    "recommendation": "Address the FIXME comment before finalizing the code."
                }
            ]
        }
        
        # Try to load rules from files
        try:
            # Get the directory of this file
            current_dir = Path(__file__).parent.parent
            rules_dir = current_dir / "rules"
            
            # Load Python rules
            python_rules_path = rules_dir / "python_rules.py"
            if python_rules_path.exists():
                # This is just a placeholder - in a real implementation, we would
                # actually load the rules from the file
                pass
            else:
                rules["python"] = default_rules["python"]
            
            # Load JavaScript rules
            js_rules_path = rules_dir / "javascript_rules.py"
            if js_rules_path.exists():
                # This is just a placeholder
                pass
            else:
                rules["javascript"] = default_rules["javascript"]
            
            # Load Java rules
            java_rules_path = rules_dir / "java_rules.py"
            if java_rules_path.exists():
                # This is just a placeholder
                pass
            else:
                rules["java"] = default_rules["java"]
            
            # Add generic rules
            rules["generic"] = default_rules["generic"]
            
        except Exception:
            # If there's any error, use default rules
            return default_rules
        
        return rules
    
    def scan(self, file_path: Path, content: str, language: str) -> List[Dict[str, Any]]:
        """
        Scan a file for patterns that match the rules.
        
        Args:
            file_path: Path to the file
            content: Content of the file
            language: Programming language of the file
            
        Returns:
            List of findings
        """
        results = []
        
        # Get language-specific rules
        language_rules = self.rules.get(language.lower(), [])
        
        # Also include generic rules
        all_rules = language_rules + self.rules.get("generic", [])
        
        # Check each rule
        for rule in all_rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            
            # Find all matches
            matches = re.finditer(pattern, content)
            for match in matches:
                # Calculate line number
                line_number = content[:match.start()].count('\n') + 1
                
                results.append({
                    "vulnerability_type": rule.get("name", "Unknown Pattern"),
                    "severity": rule.get("severity", "medium"),
                    "line_number": line_number,
                    "file_path": str(file_path),
                    "description": rule.get("description", "Pattern matched."),
                    "recommendation": rule.get("recommendation", "Review the code."),
                    "rule_id": rule.get("id", "UNKNOWN")
                })
        
        return results
