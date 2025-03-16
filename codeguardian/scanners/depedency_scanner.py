import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import random

class DependencyScanner:
    """
    Scanner for detecting vulnerable dependencies in a project.
    This scanner checks package dependencies against a vulnerability database.
    """
    
    def __init__(self):
        # Initialize vulnerability database
        # In a real implementation, this would connect to a real vulnerability database
        self.vulnerability_db = self._initialize_vulnerability_db()
    
    def _initialize_vulnerability_db(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize a mock vulnerability database for demonstration purposes."""
        return {
            # Python packages
            "django": [
                {
                    "id": "CVE-2023-12345",
                    "affected_versions": ["<3.2.0"],
                    "fixed_versions": ["3.2.0"],
                    "severity": "high",
                    "description": "SQL injection vulnerability in Django ORM",
                    "recommendation": "Upgrade to Django 3.2.0 or later"
                }
            ],
            "flask": [
                {
                    "id": "CVE-2023-67890",
                    "affected_versions": ["<2.0.0"],
                    "fixed_versions": ["2.0.0"],
                    "severity": "medium",
                    "description": "Session fixation vulnerability in Flask",
                    "recommendation": "Upgrade to Flask 2.0.0 or later"
                }
            ],
            "requests": [
                {
                    "id": "CVE-2023-54321",
                    "affected_versions": ["<2.28.0"],
                    "fixed_versions": ["2.28.0"],
                    "severity": "low",
                    "description": "Certificate validation issue in Requests",
                    "recommendation": "Upgrade to Requests 2.28.0 or later"
                }
            ],
            # JavaScript packages
            "lodash": [
                {
                    "id": "CVE-2023-98765",
                    "affected_versions": ["<4.17.21"],
                    "fixed_versions": ["4.17.21"],
                    "severity": "critical",
                    "description": "Prototype pollution vulnerability in Lodash",
                    "recommendation": "Upgrade to Lodash 4.17.21 or later"
                }
            ],
            "express": [
                {
                    "id": "CVE-2023-45678",
                    "affected_versions": ["<4.17.3"],
                    "fixed_versions": ["4.17.3"],
                    "severity": "high",
                    "description": "Path traversal vulnerability in Express",
                    "recommendation": "Upgrade to Express 4.17.3 or later"
                }
            ],
            "axios": [
                {
                    "id": "CVE-2023-32109",
                    "affected_versions": ["<0.21.1"],
                    "fixed_versions": ["0.21.1"],
                    "severity": "medium",
                    "description": "Server-side request forgery vulnerability in Axios",
                    "recommendation": "Upgrade to Axios 0.21.1 or later"
                }
            ],
            # Java packages
            "org.springframework:spring-core": [
                {
                    "id": "CVE-2023-87654",
                    "affected_versions": ["<5.3.20"],
                    "fixed_versions": ["5.3.20"],
                    "severity": "critical",
                    "description": "Remote code execution vulnerability in Spring Framework",
                    "recommendation": "Upgrade to Spring Framework 5.3.20 or later"
                }
            ],
            "com.fasterxml.jackson.core:jackson-databind": [
                {
                    "id": "CVE-2023-34567",
                    "affected_versions": ["<2.13.0"],
                    "fixed_versions": ["2.13.0"],
                    "severity": "high",
                    "description": "Deserialization vulnerability in Jackson Databind",
                    "recommendation": "Upgrade to Jackson Databind 2.13.0 or later"
                }
            ]
        }
    
    def _check_version_vulnerable(self, version: str, affected_versions: List[str]) -> bool:
        """
        Check if a version is vulnerable based on affected version patterns.
        This is a simplified version check for demonstration purposes.
        """
        for affected_pattern in affected_versions:
            if affected_pattern.startswith("<"):
                # Simple "less than" check
                affected_version = affected_pattern[1:]
                if self._compare_versions(version, affected_version) < 0:
                    return True
            elif affected_pattern.startswith("<="):
                # Simple "less than or equal" check
                affected_version = affected_pattern[2:]
                if self._compare_versions(version, affected_version) <= 0:
                    return True
            elif affected_pattern.startswith(">"):
                # Simple "greater than" check
                affected_version = affected_pattern[1:]
                if self._compare_versions(version, affected_version) > 0:
                    return True
            elif affected_pattern.startswith(">="):
                # Simple "greater than or equal" check
                affected_version = affected_pattern[2:]
                if self._compare_versions(version, affected_version) >= 0:
                    return True
            elif "-" in affected_pattern:
                # Range check
                start, end = affected_pattern.split("-")
                if (self._compare_versions(version, start) >= 0 and 
                    self._compare_versions(version, end) <= 0):
                    return True
            elif version == affected_pattern:
                # Exact match
                return True
        
        return False
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        Returns:
            -1 if version1 < version2
            0 if version1 == version2
            1 if version1 > version2
        """
        # Split versions by dots
        v1_parts = version1.split(".")
        v2_parts = version2.split(".")
        
        # Compare each part
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1 = int(v1_parts[i]) if i < len(v1_parts) else 0
            v2 = int(v2_parts[i]) if i < len(v2_parts) else 0
            
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        
        return 0
    
    def _parse_python_requirements(self, file_path: Path) -> List[Dict[str, str]]:
        """Parse Python requirements.txt file."""
        dependencies = []
        
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Parse package name and version
                    if "==" in line:
                        name, version = line.split("==", 1)
                        dependencies.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "type": "python"
                        })
                    elif ">=" in line:
                        name, version = line.split(">=", 1)
                        dependencies.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "type": "python"
                        })
                    else:
                        # No version specified
                        dependencies.append({
                            "name": line.strip(),
                            "version": "latest",
                            "type": "python"
                        })
        except Exception:
            # If there's an error parsing the file, return an empty list
            pass
        
        return dependencies
    
    def _parse_npm_package_json(self, file_path: Path) -> List[Dict[str, str]]:
        """Parse Node.js package.json file."""
        dependencies = []
        
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                
                # Parse dependencies
                for dep_type in ["dependencies", "devDependencies"]:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            # Clean up version string
                            if version.startswith("^") or version.startswith("~"):
                                version = version[1:]
                            
                            dependencies.append({
                                "name": name,
                                "version": version,
                                "type": "javascript"
                            })
        except Exception:
            # If there's an error parsing the file, return an empty list
            pass
        
        return dependencies
    
    def _parse_maven_pom_xml(self, file_path: Path) -> List[Dict[str, str]]:
        """Parse Java Maven pom.xml file."""
        dependencies = []
        
        try:
            # This is a simplified parser for demonstration purposes
            # In a real implementation, we would use an XML parser
            with open(file_path, "r") as f:
                content = f.read()
                
                # Find all dependency blocks
                dependency_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
                
                for block in dependency_blocks:
                    # Extract group ID, artifact ID, and version
                    group_id = re.search(r"<groupId>(.*?)</groupId>", block)
                    artifact_id = re.search(r"<artifactId>(.*?)</artifactId>", block)
                    version = re.search(r"<version>(.*?)</version>", block)
                    
                    if group_id and artifact_id:
                        group_id = group_id.group(1).strip()
                        artifact_id = artifact_id.group(1).strip()
                        version_str = version.group(1).strip() if version else "latest"
                        
                        dependencies.append({
                            "name": f"{group_id}:{artifact_id}",
                            "version": version_str,
                            "type": "java"
                        })
        except Exception:
            # If there's an error parsing the file, return an empty list
            pass
        
        return dependencies
    
    def _parse_gradle_build(self, file_path: Path) -> List[Dict[str, str]]:
        """Parse Java Gradle build.gradle file."""
        dependencies = []
        
        try:
            # This is a simplified parser for demonstration purposes
            with open(file_path, "r") as f:
                content = f.read()
                
                # Find all dependency declarations
                # This is a very simplified regex and won't catch all cases
                dep_matches = re.finditer(r"(implementation|api|compile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]", content)
                
                for match in dep_matches:
                    group_id = match.group(2).strip()
                    artifact_id = match.group(3).strip()
                    version = match.group(4).strip()
                    
                    dependencies.append({
                        "name": f"{group_id}:{artifact_id}",
                        "version": version,
                        "type": "java"
                    })
        except Exception:
            # If there's an error parsing the file, return an empty list
            pass
        
        return dependencies
    
    def _collect_dependencies(self, target_path: Path) -> List[Dict[str, str]]:
        """Collect all dependencies from the project."""
        all_dependencies = []
        
        # Check for Python dependencies
        requirements_path = target_path / "requirements.txt"
        if requirements_path.exists():
            python_deps = self._parse_python_requirements(requirements_path)
            all_dependencies.extend(python_deps)
        
        # Check for Node.js dependencies
        package_json_path = target_path / "package.json"
        if package_json_path.exists():
            node_deps = self._parse_npm_package_json(package_json_path)
            all_dependencies.extend(node_deps)
        
        # Check for Java Maven dependencies
        pom_xml_path = target_path / "pom.xml"
        if pom_xml_path.exists():
            maven_deps = self._parse_maven_pom_xml(pom_xml_path)
            all_dependencies.extend(maven_deps)
        
        # Check for Java Gradle dependencies
        build_gradle_path = target_path / "build.gradle"
        if build_gradle_path.exists():
            gradle_deps = self._parse_gradle_build(build_gradle_path)
            all_dependencies.extend(gradle_deps)
        
        # If no dependencies were found, generate some fake ones for demonstration
        if not all_dependencies:
            all_dependencies = self._generate_fake_dependencies()
        
        return all_dependencies
    
    def _generate_fake_dependencies(self) -> List[Dict[str, str]]:
        """Generate fake dependencies for demonstration purposes."""
        fake_deps = []
        
        # Python dependencies
        python_deps = [
            {"name": "django", "version": "3.1.0", "type": "python"},
            {"name": "flask", "version": "1.1.2", "type": "python"},
            {"name": "requests", "version": "2.25.0", "type": "python"},
            {"name": "numpy", "version": "1.19.0", "type": "python"},
            {"name": "pandas", "version": "1.1.0", "type": "python"}
        ]
        
        # JavaScript dependencies
        js_deps = [
            {"name": "lodash", "version": "4.17.20", "type": "javascript"},
            {"name": "express", "version": "4.17.1", "type": "javascript"},
            {"name": "axios", "version": "0.21.0", "type": "javascript"},
            {"name": "react", "version": "17.0.1", "type": "javascript"},
            {"name": "vue", "version": "2.6.12", "type": "javascript"}
        ]
        
        # Java dependencies
        java_deps = [
            {"name": "org.springframework:spring-core", "version": "5.3.0", "type": "java"},
            {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.12.0", "type": "java"},
            {"name": "org.apache.commons:commons-lang3", "version": "3.11", "type": "java"},
            {"name": "org.hibernate:hibernate-core", "version": "5.4.0", "type": "java"},
            {"name": "com.google.guava:guava", "version": "30.0-jre", "type": "java"}
        ]
        
        # Randomly select some dependencies
        num_python = random.randint(1, 3)
        num_js = random.randint(1, 3)
        num_java = random.randint(1, 3)
        
        fake_deps.extend(random.sample(python_deps, num_python))
        fake_deps.extend(random.sample(js_deps, num_js))
        fake_deps.extend(random.sample(java_deps, num_java))
        
        return fake_deps
    
    def _check_dependency_vulnerabilities(self, dependencies: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Check dependencies for known vulnerabilities."""
        results = []
        
        for dep in dependencies:
            name = dep["name"]
            version = dep["version"]
            dep_type = dep.get("type", "unknown")
            
            # Check if the dependency is in our vulnerability database
            if name in self.vulnerability_db:
                vulnerabilities = self.vulnerability_db[name]
                
                for vuln in vulnerabilities:
                    # Check if the version is affected
                    if self._check_version_vulnerable(version, vuln["affected_versions"]):
                        results.append({
                            "vulnerability_type": f"Vulnerable Dependency: {name}",
                            "severity": vuln["severity"],
                            "line_number": 0,  # Not applicable for dependencies
                            "file_path": f"Dependency: {name}@{version}",
                            "description": vuln["description"],
                            "recommendation": vuln["recommendation"],
                            "dependency": {
                                "name": name,
                                "version": version,
                                "type": dep_type
                            },
                            "cve_id": vuln["id"]
                        })
        
        return results
    
    def scan(self, target_path: Path) -> List[Dict[str, Any]]:
        """
        Scan a project for vulnerable dependencies.
        
        Args:
            target_path: Path to the project root
            
        Returns:
            List of vulnerability findings
        """
        # Collect dependencies from the project
        dependencies = self._collect_dependencies(target_path)
        
        # Check dependencies for vulnerabilities
        results = self._check_dependency_vulnerabilities(dependencies)
        
        return results
