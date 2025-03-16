import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

def get_file_language(file_path: Path) -> str:
    """
    Determine the programming language of a file based on its extension.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Language name (e.g., "python", "javascript", "java")
    """
    extension = file_path.suffix.lower()
    
    # Map file extensions to languages
    extension_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",  # TypeScript is treated as JavaScript for now
        ".tsx": "javascript",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".html": "html",
        ".css": "css",
        ".json": "json",
        ".xml": "xml",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".md": "markdown",
        ".sh": "shell",
        ".bat": "batch",
        ".ps1": "powershell"
    }
    
    return extension_map.get(extension, "unknown")

def read_file_content(file_path: Path) -> str:
    """
    Read the content of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Content of the file as a string
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        # If there's an error reading the file, return an empty string
        return ""

def is_binary_file(file_path: Path) -> bool:
    """
    Check if a file is binary.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file is binary, False otherwise
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except Exception:
        # If there's an error reading the file, assume it's not binary
        return False

def find_files(directory: Path, patterns: List[str], exclusions: List[str] = None) -> List[Path]:
    """
    Find files in a directory that match the given patterns.
    
    Args:
        directory: Directory to search in
        patterns: List of glob patterns to match
        exclusions: List of patterns to exclude
        
    Returns:
        List of file paths
    """
    exclusions = exclusions or []
    files = []
    
    for pattern in patterns:
        for file_path in directory.glob(pattern):
            if file_path.is_file() and not any(excl in str(file_path) for excl in exclusions):
                files.append(file_path)
    
    return files

def parse_severity_threshold(threshold: str) -> int:
    """
    Parse a severity threshold string to a numeric value.
    
    Args:
        threshold: Severity threshold string (e.g., "low", "medium", "high", "critical")
        
    Returns:
        Numeric value of the threshold
    """
    severity_levels = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    return severity_levels.get(threshold.lower(), 1)  # Default to "low" if not found

def filter_results_by_severity(results: List[Dict[str, Any]], threshold: str) -> List[Dict[str, Any]]:
    """
    Filter results by severity threshold.
    
    Args:
        results: List of vulnerability findings
        threshold: Severity threshold string
        
    Returns:
        Filtered list of vulnerability findings
    """
    threshold_level = parse_severity_threshold(threshold)
    
    # Map severity strings to numeric values
    severity_map = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    # Filter results
    filtered_results = [
        result for result in results
        if severity_map.get(result.get("severity", "low").lower(), 0) >= threshold_level
    ]
    
    return filtered_results

def group_results_by_file(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group results by file path.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        Dictionary mapping file paths to lists of findings
    """
    grouped = {}
    
    for result in results:
        file_path = result.get("file_path", "Unknown")
        if file_path not in grouped:
            grouped[file_path] = []
        grouped[file_path].append(result)
    
    return grouped

def count_results_by_severity(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count results by severity.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        Dictionary mapping severity levels to counts
    """
    counts = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    
    for result in results:
        severity = result.get("severity", "low").lower()
        if severity in counts:
            counts[severity] += 1
    
    return counts
