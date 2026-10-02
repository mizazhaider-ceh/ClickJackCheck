#!/usr/bin/env python3
"""
ClickJackCheck: audit websites for clickjacking protection.

Checks the X-Frame-Options and Content-Security-Policy frame-ancestors
headers of one URL (or a whole list via --file) and reports whether the
site can be embedded in a third-party frame.
"""
import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Initialize Rich Console
console = Console()

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 ClickJackCheck/1.0"
)


def strip_rich_markup(text: str) -> str:
    """Remove [tag]...[/tag] style rich markup from a string."""
    return re.sub(r"\[[^\]]*\]", "", text)


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
        if not url.startswith(("http://", "https://")):
            return "https://" + url
        return url

    def print_banner(self):
        """Print the tool banner and credits."""
        banner_text = Text(justify="center")
        banner_text.append("\nCLICKJACK CHECK\n", style="bold cyan")
        banner_text.append("==============================\n", style="bold cyan")
        banner_text.append("Built by mizazhaider-ceh\n", style="bold yellow")
        banner_text.append("Powered by The PenTrix\n", style="italic magenta")

        panel = Panel(
            banner_text,
            title="[bold green]Security Assessment Tool[/bold green]",
            border_style="cyan",
            expand=False,
        )
        console.print(panel)
        console.print()

    def check_protection(self) -> Dict[str, Any]:
        """Check for clickjacking protection headers."""
        try:
            # Get headers from the target URL
            response = requests.get(
                self.url, timeout=self.timeout, headers={"User-Agent": USER_AGENT}
            )
            headers = dict(response.headers)

            # Check for X-Frame-Options header (requests headers are case-insensitive)
            x_frame_options = headers.get("X-Frame-Options", "").strip().upper()
            x_frame_present = "X-Frame-Options" in headers

            # Check for Content-Security-Policy header with frame-ancestors
            csp = headers.get("Content-Security-Policy", "")
            frame_ancestors = "frame-ancestors" in csp.lower()
            csp_present = "Content-Security-Policy" in headers

            # Determine protection level
            if x_frame_options in ["DENY", "SAMEORIGIN"]:
                protection_level = "good"
                protection_type = "X-Frame-Options"
                protection_value = x_frame_options
            elif x_frame_options.startswith("ALLOW-FROM"):
                # ALLOW-FROM was valid in older browsers but is obsolete and
                # ignored by modern ones, so it must not count as protection.
                protection_level = "weak"
                protection_type = "X-Frame-Options"
                protection_value = "Obsolete ALLOW-FROM value (ignored by modern browsers)"
            elif frame_ancestors:
                protection_level = "good"
                protection_type = "Content-Security-Policy"
                protection_value = "frame-ancestors directive present"
            elif x_frame_present or csp_present:
                protection_level = "weak"
                if x_frame_options:
                    protection_type = "X-Frame-Options"
                    protection_value = f"Invalid value: {x_frame_options}"
                else:
                    protection_type = "Content-Security-Policy"
                    protection_value = "Present but no frame-ancestors"
            else:
                protection_level = "none"
                protection_type = "none"
                protection_value = "No protection headers found"

            self.results = {
                "url": self.url,
                "status_code": response.status_code,
                "headers": headers,
                "x_frame_options": {
                    "present": x_frame_present,
                    "value": headers.get("X-Frame-Options", "Not present"),
                    "valid": x_frame_options in ["DENY", "SAMEORIGIN"],
                },
                "csp_frame_ancestors": {
                    "present": csp_present,
                    "value": (
                        "frame-ancestors in CSP"
                        if frame_ancestors
                        else "No frame-ancestors directive"
                    ),
                    "valid": frame_ancestors,
                },
                "protection_level": protection_level,
                "protection_type": protection_type,
                "protection_value": protection_value,
                "vulnerable": protection_level == "none",
                "recommendations": [],
            }

            self._generate_recommendations()
            return self.results

        except requests.exceptions.RequestException as e:
            self.results = {
                "url": self.url,
                "error": str(e),
                "vulnerable": True,
                "protection_level": "error",
                "recommendations": [
                    "Unable to connect to the target URL",
                    "Check if the URL is correct and accessible",
                ],
            }
            return self.results

    def _generate_recommendations(self):
        """Generate recommendations based on results."""
        recs = []
        if self.results["vulnerable"]:
            recs.append("Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'")
            recs.append(
                "OR add Content-Security-Policy header with 'frame-ancestors' directive"
            )
            recs.append("For maximum protection, use both headers")
        elif self.results["protection_level"] == "weak":
            recs.append("Fix the X-Frame-Options value to be 'DENY' or 'SAMEORIGIN'")
            recs.append(
                "OR add proper frame-ancestors directive to Content-Security-Policy"
            )
        else:
            recs.append("Current clickjacking protection is adequate")
            recs.append(
                "Consider implementing both X-Frame-Options and CSP frame-ancestors for defense in depth"
            )

        self.results["recommendations"] = recs

    def display_results(self):
        """Display the results using Rich tables and panels."""
        if "error" in self.results:
            console.print(f"[bold red]Error: {self.results['error']}[/bold red]")
            if self.results["recommendations"]:
                console.print("\n[bold yellow]RECOMMENDATIONS:[/bold yellow]")
                for rec in self.results["recommendations"]:
                    console.print(f"  - {rec}")
            return

        # Status Panel
        status_color = "green" if self.results["status_code"] == 200 else "yellow"
        console.print(
            f"Target: [bold blue]{self.results['url']}[/bold blue] | "
            f"Status: [{status_color}]{self.results['status_code']}[/{status_color}]"
        )
        console.print("-" * 60)

        # Protection Summary
        if self.results["vulnerable"]:
            console.print(
                Panel(
                    "[bold red]VULNERABLE TO CLICKJACKING[/bold red]\n"
                    "[white]No adequate protection against clickjacking attacks[/white]",
                    border_style="red",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green]PROTECTED AGAINST CLICKJACKING[/bold green]\n"
                    f"[white]Protection provided by: {self.results['protection_type']}[/white]",
                    border_style="green",
                )
            )

        # Details Table
        table = Table(
            title="Header Analysis", show_header=True, header_style="bold magenta"
        )
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details")

        # X-Frame-Options Row
        xfo = self.results["x_frame_options"]
        xfo_status = (
            "[green]Valid[/green]" if xfo["valid"] else "[red]Invalid/Missing[/red]"
        )
        table.add_row("X-Frame-Options", xfo_status, xfo["value"])

        # CSP Row
        csp = self.results["csp_frame_ancestors"]
        csp_status = (
            "[green]Valid[/green]" if csp["valid"] else "[red]Invalid/Missing[/red]"
        )
        table.add_row("Content-Security-Policy", csp_status, csp["value"])

        console.print(table)
        console.print()

        # Recommendations
        rec_panel = Panel(
            "\n".join([f"- {rec}" for rec in self.results["recommendations"]]),
            title="[bold yellow]Recommendations[/bold yellow]",
            border_style="yellow",
        )
        console.print(rec_panel)


def display_batch_summary(results: List[Dict[str, Any]]):
    """Print a summary table for --file batch scans."""
    table = Table(
        title="Batch Scan Summary", show_header=True, header_style="bold magenta"
    )
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Protection", style="white")

    vulnerable = 0
    for res in results:
        url = res.get("url", "?")
        if "error" in res:
            status = "[red]ERROR[/red]"
            protection = res["error"]
            vulnerable += 1
        elif res.get("vulnerable"):
            status = "[red]VULNERABLE[/red]"
            protection = res.get("protection_value", "")
            vulnerable += 1
        else:
            status = "[green]PROTECTED[/green]"
            protection = f"{res.get('protection_type')}: {res.get('protection_value')}"
        table.add_row(url, status, protection)

    console.print(table)
    console.print(
        f"\nScanned [bold]{len(results)}[/bold] targets, "
        f"[red]{vulnerable} vulnerable[/red]."
    )


def read_target_file(path: str) -> List[str]:
    """Read one URL per line from a file, skipping blanks and comments."""
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def plain_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of results with any rich markup stripped for JSON output."""
    clean = dict(results)
    clean["recommendations"] = [
        strip_rich_markup(r) for r in results.get("recommendations", [])
    ]
    return clean


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a website for Clickjacking vulnerabilities."
    )
    parser.add_argument("url", nargs="?", help="The URL to analyze")
    parser.add_argument(
        "--file",
        "-f",
        metavar="PATH",
        help="Scan multiple URLs, one per line, from a file",
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--json", action="store_true", help="Print results as JSON"
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if not args.url and not args.file:
        print("error: provide a URL or use --file PATH", file=sys.stderr)
        return 2

    targets = [args.url] if args.url else read_target_file(args.file)
    if not targets:
        print("error: no targets to scan", file=sys.stderr)
        return 2

    batch = len(targets) > 1
    if not args.json:
        ClickJackAuditor(targets[0]).print_banner()

    all_results: List[Dict[str, Any]] = []
    if args.json:
        for target in targets:
            auditor = ClickJackAuditor(target, timeout=args.timeout)
            all_results.append(plain_results(auditor.check_protection()))
        print(json.dumps(all_results if batch else all_results[0], indent=2))
        return 0

    if batch:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(description="Scanning targets...", total=len(targets))
            for target in targets:
                auditor = ClickJackAuditor(target, timeout=args.timeout)
                all_results.append(auditor.check_protection())
                progress.advance(task)
        display_batch_summary(all_results)
    else:
        auditor = ClickJackAuditor(targets[0], timeout=args.timeout)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Scanning target...", total=None)
            auditor.check_protection()
        auditor.display_results()
    return 0


if __name__ == "__main__":
    sys.exit(main())
