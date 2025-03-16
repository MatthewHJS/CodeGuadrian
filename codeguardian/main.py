#!/usr/bin/env python3
import os
import sys
import click
import yaml
from rich.console import Console
from rich.progress import Progress
import time
from pathlib import Path
from dotenv import load_dotenv

from .analyzer import CodeAnalyzer
from .utils.output import generate_report

# Load environment variables from .env file
load_dotenv()

console = Console()

@click.group()
def cli():
    """CodeGuardian - Advanced Static Code Analysis Tool"""
    pass

@cli.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--languages', '-l', help='Comma-separated list of languages to scan (e.g., python,javascript,java)')
@click.option('--output', '-o', type=click.Choice(['console', 'json', 'html', 'markdown']), default='console', 
              help='Output format for the report')
@click.option('--output-file', '-f', help='File to write the report to')
@click.option('--exclude', '-e', help='Comma-separated list of directories to exclude')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), default='low',
              help='Minimum severity level to report')
def scan(target_path, languages, output, output_file, exclude, config, verbose, severity):
    """Scan a codebase for security vulnerabilities and code quality issues."""
    start_time = time.time()
    
    # Process configuration
    config_data = {}
    if config:
        with open(config, 'r') as f:
            config_data = yaml.safe_load(f)
    elif os.path.exists(os.path.join(target_path, '.codeguardian.yml')):
        with open(os.path.join(target_path, '.codeguardian.yml'), 'r') as f:
            config_data = yaml.safe_load(f)
    
    # Process languages
    if languages:
        languages = languages.split(',')
    else:
        languages = config_data.get('languages', ['python', 'javascript', 'java'])
    
    # Process exclusions
    exclusions = []
    if exclude:
        exclusions = exclude.split(',')
    elif 'exclude' in config_data:
        exclusions = config_data.get('exclude', [])
    
    # Add default exclusions
    default_exclusions = ['node_modules', 'venv', '.git', '.github', '__pycache__', '.pytest_cache']
    exclusions.extend([e for e in default_exclusions if e not in exclusions])
    
    # Display scan information
    console.print(f"[bold blue]CodeGuardian Scan[/bold blue]")
    console.print(f"Target: [bold]{target_path}[/bold]")
    console.print(f"Languages: [bold]{', '.join(languages)}[/bold]")
    console.print(f"Severity threshold: [bold]{severity}[/bold]")
    console.print(f"Exclusions: [bold]{', '.join(exclusions)}[/bold]")
    console.print()
    
    # Initialize analyzer
    analyzer = CodeAnalyzer(
        target_path=target_path,
        languages=languages,
        exclusions=exclusions,
        severity_threshold=severity,
        verbose=verbose
    )
    
    # Run the analysis
    with Progress() as progress:
        task = progress.add_task("[green]Analyzing codebase...", total=100)
        
        # Simulate progress
        for i in range(1, 101):
            time.sleep(0.05)  # Simulate work being done
            progress.update(task, completed=i)
        
        results = analyzer.analyze()
    
    # Generate and display report
    report = generate_report(results, output_format=output, output_file=output_file)
    
    if output == 'console':
        console.print(report)
    else:
        console.print(f"Report saved to: [bold]{output_file}[/bold]")
    
    # Display summary
    elapsed_time = time.time() - start_time
    console.print(f"\n[bold green]Scan completed in {elapsed_time:.2f} seconds[/bold green]")
    
    vulnerability_count = sum(1 for vuln in results if vuln['severity'] in ['high', 'critical'])
    if vulnerability_count > 0:
        console.print(f"[bold red]Found {vulnerability_count} high or critical vulnerabilities![/bold red]")
        return 1
    return 0

def main():
    """Main entry point for the CLI."""
    try:
        return cli()
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        return 1

if __name__ == "__main__":
    sys.exit(main())
