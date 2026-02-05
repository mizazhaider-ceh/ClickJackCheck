#!/usr/bin/env python3
import sys
import argparse
import asyncio
from typing import Dict, Any, List, Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Initialize Rich Console
console = Console()

class ClickJackAuditor:
    """
    A class to audit websites for Clickjacking vulnerabilities.
    """
    def __init__(self, url: str, timeout: int = 10):
        self.url = self._normalize_url(url)
        self.timeout = timeout
        self.results: Dict[str, Any] = {}

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a scheme."""
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url

    def print_banner(self):
        """Print the tool banner and credits."""
        banner_text = Text(justify="center")
        banner_text.append("\n🛡️  CLICKJACK CHECK  🛡️\n", style="bold cyan")
        banner_text.append("════════════════════════════════════\n", style="bold cyan")
        banner_text.append("Built by MIHx0 (Muhammad Izaz Haider)\n", style="bold yellow")
        banner_text.append("Powered by The PenTrix\n", style="italic magenta")
        
        panel = Panel(
            banner_text,
            title="[bold green]Security Assessment Tool[/bold green]",
            border_style="cyan",
            expand=False
        )
        console.print(panel)
        console.print()

    def check_protection(self) -> Dict[str, Any]:
        """Check for clickjacking protection headers."""
        try:
            # Get headers from the target URL
            response = requests.get(self.url, timeout=self.timeout)
            headers = dict(response.headers)
            
            # Check for X-Frame-Options header
            x_frame_options = headers.get('X-Frame-Options', '').strip().upper()
            x_frame_present = 'X-Frame-Options' in headers
            
            # Check for Content-Security-Policy header with frame-ancestors
            csp = headers.get('Content-Security-Policy', '')
            frame_ancestors = 'frame-ancestors' in csp.lower()
            csp_present = 'Content-Security-Policy' in headers
            
            # Determine protection level
            if x_frame_options in ['DENY', 'SAMEORIGIN']:
                protection_level = 'good'
                protection_type = 'X-Frame-Options'
                protection_value = x_frame_options
            elif frame_ancestors:
                protection_level = 'good'
                protection_type = 'Content-Security-Policy'
                protection_value = 'frame-ancestors directive present'
            elif x_frame_present or csp_present:
                protection_level = 'weak'
                if x_frame_options:
                    protection_type = 'X-Frame-Options'
                    protection_value = f"Invalid value: {x_frame_options}"
                else:
                    protection_type = 'Content-Security-Policy'
                    protection_value = 'Present but no frame-ancestors'
            else:
                protection_level = 'none'
                protection_type = 'none'
                protection_value = 'No protection headers found'
            
            self.results = {
                'url': self.url,
                'status_code': response.status_code,
                'headers': headers,
                'x_frame_options': {
                    'present': x_frame_present,
                    'value': headers.get('X-Frame-Options', 'Not present'),
                    'valid': x_frame_options in ['DENY', 'SAMEORIGIN']
                },
                'csp_frame_ancestors': {
                    'present': csp_present,
                    'value': 'frame-ancestors in CSP' if frame_ancestors else 'No frame-ancestors directive',
                    'valid': frame_ancestors
                },
                'protection_level': protection_level,
                'protection_type': protection_type,
                'protection_value': protection_value,
                'vulnerable': protection_level == 'none',
                'recommendations': []
            }
            
            self._generate_recommendations()
            return self.results
            
        except requests.exceptions.RequestException as e:
            self.results = {
                'url': self.url,
                'error': str(e),
                'vulnerable': True,
                'protection_level': 'error',
                'recommendations': [
                    'Unable to connect to the target URL',
                    'Check if the URL is correct and accessible'
                ]
            }
            return self.results

    def _generate_recommendations(self):
        """Generate recommendations based on results."""
        recs = []
        if self.results['vulnerable']:
            recs.append("Add [bold]X-Frame-Options[/bold] header with value 'DENY' or 'SAMEORIGIN'")
            recs.append("OR add [bold]Content-Security-Policy[/bold] header with 'frame-ancestors' directive")
            recs.append("For maximum protection, use both headers")
        elif self.results['protection_level'] == 'weak':
            recs.append("Fix the X-Frame-Options value to be 'DENY' or 'SAMEORIGIN'")
            recs.append("OR add proper frame-ancestors directive to Content-Security-Policy")
        else:
            recs.append("Current clickjacking protection is adequate")
            recs.append("Consider implementing both X-Frame-Options and CSP frame-ancestors for defense in depth")
        
        self.results['recommendations'] = recs

    def display_results(self):
        """Display the results using Rich tables and panels."""
        if 'error' in self.results:
            console.print(f"[bold red]❌ Error: {self.results['error']}[/bold red]")
            if self.results['recommendations']:
                console.print("\n[bold yellow]RECOMMENDATIONS:[/bold yellow]")
                for rec in self.results['recommendations']:
                    console.print(f"  • {rec}")
            return

        # Status Panel
        status_color = "green" if self.results['status_code'] == 200 else "yellow"
        console.print(f"Target: [bold blue]{self.results['url']}[/bold blue] | Status: [{status_color}]{self.results['status_code']}[/{status_color}]")
        console.print("-" * 60)

        # Protection Summary
        if self.results['vulnerable']:
            console.print(Panel("[bold red]❗ VULNERABLE TO CLICKJACKING[/bold red]\n[white]No adequate protection against clickjacking attacks[/white]", border_style="red"))
        else:
            console.print(Panel(f"[bold green]✅ PROTECTED AGAINST CLICKJACKING[/bold green]\n[white]Protection provided by: {self.results['protection_type']}[/white]", border_style="green"))

        # Details Table
        table = Table(title="Header Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details")

        # X-Frame-Options Row
        xfo = self.results['x_frame_options']
        xfo_status = "[green]Valid[/green]" if xfo['valid'] else "[red]Invalid/Missing[/red]"
        table.add_row("X-Frame-Options", xfo_status, xfo['value'])

        # CSP Row
        csp = self.results['csp_frame_ancestors']
        csp_status = "[green]Valid[/green]" if csp['valid'] else "[red]Invalid/Missing[/red]"
        table.add_row("Content-Security-Policy", csp_status, csp['value'])

        console.print(table)
        console.print()

        # Recommendations
        rec_panel = Panel(
            "\n".join([f"• {rec}" for rec in self.results['recommendations']]),
            title="[bold yellow]Recommendations[/bold yellow]",
            border_style="yellow"
        )
        console.print(rec_panel)


def main():
    parser = argparse.ArgumentParser(description="Check a website for Clickjacking vulnerabilities.")
    parser.add_argument("url", help="The URL to analyze")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    
    args = parser.parse_args()

    auditor = ClickJackAuditor(args.url, timeout=args.timeout)
    auditor.print_banner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Scanning target...", total=None)
        auditor.check_protection()
    
    auditor.display_results()

if __name__ == "__main__":
    main()
