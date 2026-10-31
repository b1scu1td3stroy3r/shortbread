import argparse
import sys
import requests
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections and prevents SSL stripping.",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks by restricting resource origins.",
    "X-Frame-Options": "Protects against clickjacking by disallowing framing.",
    "X-Content-Type-Options": "Prevents MIME-sniffing away from declared content types.",
    "Referrer-Policy": "Controls referrer information exposed in outbound requests.",
    "Permissions-Policy": "Restricts browser device APIs (camera, geolocation, microphone)."
}

def audit_url(target: str):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    console.print(f"\n[bold green]Shortbread[/bold green] [dim]v1.0.0[/dim]")
    console.print(f"Auditing target: [bold cyan]{target}[/bold cyan]\n")

    try:
        response = requests.get(target, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as error:
        console.print(f"[bold red]Connection Error:[/bold red] {error}")
        sys.exit(1)

    table = Table(title="HTTP Security Header Audit")
    table.add_column("Header", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Security Purpose", style="dim")

    for header, purpose in SECURITY_HEADERS.items():
        if header.lower() in [h.lower() for h in response.headers]:
            table.add_row(header, "[green]PRESENT[/green]", purpose)
        else:
            table.add_row(header, "[red]MISSING[/red]", purpose)

    console.print(table)
    console.print(f"\n[dim]Audit completed for status code {response.status_code}.[/dim]\n")

def main():
    parser = argparse.ArgumentParser(description="Shortbread - HTTP Security Header Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain to audit")
    args = parser.parse_args()

    audit_url(args.url)

if __name__ == "__main__":
    main()
