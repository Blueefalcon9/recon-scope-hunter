#!/usr/bin/env python3
"""
Recon Scope Hunter
Author: Your Name
Description: Passive + light active recon from a single domain or list.
"""

import argparse
import requests
import json
import csv
import socket
import concurrent.futures
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

console = Console()

# -----------------------------
# Helper Functions
# -----------------------------

def fetch_crtsh(domain):
    """Get subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            subs = {entry["name_value"].lower() for entry in data}
            return subs
    except Exception as e:
        console.print(f"[red][!][/red] crt.sh error: {e}")
    return set()

def fetch_alienvault(domain):
    """Get subdomains from AlienVault OTX"""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json().get("passive_dns", [])
            subs = {entry["hostname"].lower() for entry in data if "hostname" in entry}
            return subs
    except Exception as e:
        console.print(f"[red][!][/red] AlienVault error: {e}")
    return set()

def fetch_hackertarget(domain):
    """Get subdomains from HackerTarget"""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=10)
        if "API count exceeded" in r.text:
            console.print("[yellow][!][/yellow] HackerTarget API limit reached")
            return set()
        if r.status_code == 200:
            lines = r.text.strip().split("\n")
            subs = {line.split(",")[0].lower() for line in lines if "," in line}
            return subs
    except Exception as e:
        console.print(f"[red][!][/red] HackerTarget error: {e}")
    return set()

def resolve_and_check(host):
    """Resolve IP and check HTTP status"""
    result = {"subdomain": host, "ip": None, "status_code": None, "title": None}
    try:
        result["ip"] = socket.gethostbyname(host)
        # Try basic HTTP check
        for proto in ["https://", "http://"]:
            try:
                r = requests.get(proto + host, timeout=5, verify=False)
                result["status_code"] = r.status_code
                # Extract simple title
                if "<title>" in r.text.lower():
                    start = r.text.lower().find("<title>") + 7
                    end = r.text.lower().find("</title>", start)
                    result["title"] = r.text[start:end][:80]
                break
            except:
                continue
    except socket.gaierror:
        pass
    return result

# -----------------------------
# Main Logic
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Recon Scope Hunter - Passive Recon Tool")
    parser.add_argument("-d", "--domain", help="Single domain to scan")
    parser.add_argument("-i", "--input", help="File containing list of domains")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    args = parser.parse_args()

    if not args.domain and not args.input:
        console.print("[red][!] Must provide a domain (-d) or input file (-i)[/red]")
        return

    console.print("[cyan][*][/cyan] Starting Recon Scope Hunter...")

    # Load targets
    targets = []
    if args.domain:
        targets.append(args.domain.strip())
    if args.input:
        with open(args.input, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    all_results = []

    for domain in targets:
        console.print(f"\n[bold cyan]=== Recon for {domain} ===[/bold cyan]")

        subs = set()
        subs |= fetch_crtsh(domain)
        subs |= fetch_alienvault(domain)
        subs |= fetch_hackertarget(domain)

        console.print(f"[green][+][/green] Found {len(subs)} subdomains before resolution.")

        resolved_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for result in tqdm(executor.map(resolve_and_check, subs), total=len(subs), desc="Resolving"):
                resolved_results.append(result)

        # Pretty table
        table = Table(title=f"Results for {domain}")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Title", style="green")
        for r in resolved_results:
            table.add_row(r["subdomain"], str(r["ip"]), str(r["status_code"]), str(r["title"]))
        console.print(table)

        all_results.extend(resolved_results)

        # Write to output files
        os.makedirs(args.output, exist_ok=True)
        json_path = f"{args.output}/{domain}_recon.json"
        csv_path = f"{args.output}/{domain}_recon.csv"

        with open(json_path, "w") as jf:
            json.dump(resolved_results, jf, indent=4)

        with open(csv_path, "w", newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=["subdomain", "ip", "status_code", "title"])
            writer.writeheader()
            writer.writerows(resolved_results)

        console.print(f"[blue][*][/blue] Saved results: {json_path}, {csv_path}")

if __name__ == "__main__":
    import os
    requests.packages.urllib3.disable_warnings()
    main()
