import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from tabulate import tabulate

from codeguardian.utils.helpers import count_results_by_severity, group_results_by_file

console = Console()

def generate_console_report(results: List[Dict[str, Any]]) -> str:
    """
    Generate a console report of vulnerability findings.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        Rich console output
    """
    # Count results by severity
    severity_counts = count_results_by_severity(results)
    
    # Create summary table
    summary_table = Table(title="Vulnerability Summary")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", style="bold")
    
    summary_table.add_row("Critical", f"[bold red]{severity_counts['critical']}[/bold red]")
    summary_table.add_row("High", f"[bold orange]{severity_counts['high']}[/bold orange]")
    summary_table.add_row("Medium", f"[bold yellow]{severity_counts['medium']}[/bold yellow]")
    summary_table.add_row("Low", f"[bold green]{severity_counts['low']}[/bold green]")
    summary_table.add_row("Info", f"[bold blue]{severity_counts['info']}[/bold blue]")
    summary_table.add_row("Total", f"[bold]{sum(severity_counts.values())}[/bold]")
    
    # Group results by file
    grouped_results = group_results_by_file(results)
    
    # Create detailed tables for each file
    file_tables = []
    for file_path, file_results in grouped_results.items():
        file_table = Table(title=f"Vulnerabilities in {file_path}")
        file_table.add_column("Line", style="dim")
        file_table.add_column("Severity", style="bold")
        file_table.add_column("Type", style="bold")
        file_table.add_column("Description")
        
        for result in file_results:
            severity = result.get("severity", "low").lower()
            severity_style = {
                "critical": "bold red",
                "high": "bold orange",
                "medium": "bold yellow",
                "low": "bold green",
                "info": "bold blue"
            }.get(severity, "bold")
            
            file_table.add_row(
                str(result.get("line_number", "")),
                f"[{severity_style}]{severity.upper()}[/{severity_style}]",
                result.get("vulnerability_type", "Unknown"),
                result.get("description", "")
            )
        
        file_tables.append(file_table)
    
    # Combine all tables
    output = "\n\n"
    output += str(summary_table)
    
    for file_table in file_tables:
        output += "\n\n"
        output += str(file_table)
    
    return output

def generate_json_report(results: List[Dict[str, Any]]) -> str:
    """
    Generate a JSON report of vulnerability findings.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        JSON string
    """
    # Add timestamp and summary
    severity_counts = count_results_by_severity(results)
    
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total": sum(severity_counts.values()),
            "by_severity": severity_counts
        },
        "vulnerabilities": results
    }
    
    return json.dumps(report, indent=2)

def generate_html_report(results: List[Dict[str, Any]]) -> str:
    """
    Generate an HTML report of vulnerability findings.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        HTML string
    """
    # Count results by severity
    severity_counts = count_results_by_severity(results)
    
    # Group results by file
    grouped_results = group_results_by_file(results)
    
    # Generate HTML
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CodeGuardian Security Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            .summary {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 20px;
                margin-bottom: 30px;
            }
            .summary-table {
                width: 100%;
                border-collapse: collapse;
            }
            .summary-table th, .summary-table td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            .file-section {
                margin-bottom: 40px;
            }
            .vulnerability-table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
            .vulnerability-table th, .vulnerability-table td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            .severity-critical {
                color: #e74c3c;
                font-weight: bold;
            }
            .severity-high {
                color: #e67e22;
                font-weight: bold;
            }
            .severity-medium {
                color: #f39c12;
                font-weight: bold;
            }
            .severity-low {
                color: #27ae60;
                font-weight: bold;
            }
            .severity-info {
                color: #3498db;
                font-weight: bold;
            }
            .recommendation {
                background-color: #f8f9fa;
                border-left: 4px solid #3498db;
                padding: 10px;
                margin-top: 5px;
            }
        </style>
    </head>
    <body>
        <h1>CodeGuardian Security Report</h1>
        <p>Generated on: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <div class="summary">
            <h2>Vulnerability Summary</h2>
            <table class="summary-table">
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td><span class="severity-critical">Critical</span></td>
                    <td>""" + str(severity_counts["critical"]) + """</td>
                </tr>
                <tr>
                    <td><span class="severity-high">High</span></td>
                    <td>""" + str(severity_counts["high"]) + """</td>
                </tr>
                <tr>
                    <td><span class="severity-medium">Medium</span></td>
                    <td>""" + str(severity_counts["medium"]) + """</td>
                </tr>
                <tr>
                    <td><span class="severity-low">Low</span></td>
                    <td>""" + str(severity_counts["low"]) + """</td>
                </tr>
                <tr>
                    <td><span class="severity-info">Info</span></td>
                    <td>""" + str(severity_counts["info"]) + """</td>
                </tr>
                <tr>
                    <th>Total</th>
                    <th>""" + str(sum(severity_counts.values())) + """</th>
                </tr>
            </table>
        </div>
    """
    
    # Add file sections
    for file_path, file_results in grouped_results.items():
        html += f"""
        <div class="file-section">
            <h2>Vulnerabilities in {file_path}</h2>
            <table class="vulnerability-table">
                <tr>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
        """
        
        for result in file_results:
            severity = result.get("severity", "low").lower()
            severity_class = f"severity-{severity}"
            
            html += f"""
                <tr>
                    <td>{result.get("line_number", "")}</td>
                    <td><span class="{severity_class}">{severity.upper()}</span></td>
                    <td>{result.get("vulnerability_type", "Unknown")}</td>
                    <td>{result.get("description", "")}</td>
                    <td>
                        <div class="recommendation">
                            {result.get("recommendation", "")}
                        </div>
                    </td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    html += """
    </body>
    </html>
    """
    
    return html

def generate_markdown_report(results: List[Dict[str, Any]]) -> str:
    """
    Generate a Markdown report of vulnerability findings.
    
    Args:
        results: List of vulnerability findings
        
    Returns:
        Markdown string
    """
    # Count results by severity
    severity_counts = count_results_by_severity(results)
    
    # Group results by file
    grouped_results = group_results_by_file(results)
    
    # Generate Markdown
    markdown = f"""# CodeGuardian Security Report

Generated on: {time.strftime("%Y-%m-%d %H:%M:%S")}

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts["critical"]} |
| High     | {severity_counts["high"]} |
| Medium   | {severity_counts["medium"]} |
| Low      | {severity_counts["low"]} |
| Info     | {severity_counts["info"]} |
| **Total**    | **{sum(severity_counts.values())}** |

"""
    
    # Add file sections
    for file_path, file_results in grouped_results.items():
        markdown += f"""## Vulnerabilities in {file_path}

| Line | Severity | Type | Description | Recommendation |
|------|----------|------|-------------|---------------|
"""
        
        for result in file_results:
            severity = result.get("severity", "low").upper()
            line_number = result.get("line_number", "")
            vuln_type = result.get("vulnerability_type", "Unknown")
            description = result.get("description", "").replace("\n", " ")
            recommendation = result.get("recommendation", "").replace("\n", " ")
            
            markdown += f"| {line_number} | {severity} | {vuln_type} | {description} | {recommendation} |\n"
        
        markdown += "\n"
    
    return markdown

def generate_report(results: List[Dict[str, Any]], output_format: str = "console", output_file: Optional[str] = None) -> str:
    """
    Generate a report of vulnerability findings.
    
    Args:
        results: List of vulnerability findings
        output_format: Format of the report (console, json, html, markdown)
        output_file: Path to the output file
        
    Returns:
        Report string
    """
    # Generate report based on format
    if output_format == "json":
        report = generate_json_report(results)
    elif output_format == "html":
        report = generate_html_report(results)
    elif output_format == "markdown":
        report = generate_markdown_report(results)
    else:  # Default to console
        report = generate_console_report(results)
    
    # Write to file if specified
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)
        except Exception as e:
            console.print(f"[bold red]Error writing report to {output_file}: {str(e)}[/bold red]")
    
    return report
