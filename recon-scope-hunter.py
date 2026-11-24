#!/usr/bin/env python3
"""
recon-scope-hunter - passive subdomain discovery and liveness triage.

Built for scoping an engagement: collection is passive (nothing is sent to the
target during discovery), every result is scope-checked against the domain you
asked for, and wildcard DNS is detected so you do not report 10,000 phantom
hosts.

Authorized use only.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("requests is required: pip install -r requirements.txt", file=sys.stderr)
    raise

try:
    from rich.console import Console
    from rich.table import Table
    _console: Optional["Console"] = Console(stderr=True)
except ImportError:
    _console = None

VERSION = "2.0.0"
UA = "recon-scope-hunter/2.0 (+authorized security assessment)"

HOSTNAME_RX = re.compile(r"\A(?=.{1,253}\Z)(?!-)[A-Za-z0-9_-]{1,63}"
                         r"(?:\.(?!-)[A-Za-z0-9_-]{1,63})*\.?\Z")


def log(msg: str, style: str = "") -> None:
    if _console:
        _console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Normalisation and scope
# --------------------------------------------------------------------------

def normalise(host: str) -> Optional[str]:
    """Clean one hostname. Returns None if it is not a usable hostname.

    Handles the things real sources actually emit: wildcards, trailing dots,
    uppercase, leading/trailing whitespace, and email addresses in cert CN
    fields.
    """
    h = host.strip().lower().rstrip(".")
    if not h:
        return None
    if h.startswith("*."):
        h = h[2:]            # keep the apex the wildcard covers
    if "*" in h or "@" in h or " " in h:
        return None
    if not HOSTNAME_RX.match(h):
        return None
    if "." not in h:
        return None
    return h


def in_scope(host: str, domain: str) -> bool:
    """True only for the apex itself or a true subdomain of it.

    This is the control that stops passive-DNS noise (which routinely returns
    unrelated domains that merely co-resolved) from entering your target list.
    """
    d = domain.lower().rstrip(".")
    return host == d or host.endswith("." + d)


# --------------------------------------------------------------------------
# HTTP session
# --------------------------------------------------------------------------

def make_session(retries: int = 3, backoff: float = 1.0) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "HEAD"]),
                  raise_on_status=False)
    ad = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
    s.mount("https://", ad)
    s.mount("http://", ad)
    return s


# --------------------------------------------------------------------------
# Passive sources
# --------------------------------------------------------------------------

def src_crtsh(session: requests.Session, domain: str, timeout: int) -> set[str]:
    """Certificate transparency via crt.sh.

    crt.sh returns `name_value` as a NEWLINE-SEPARATED list of every name on the
    certificate. Treating that field as a single hostname (as is easy to do)
    silently discards every additional SAN, which on multi-SAN certs is most of
    the data.
    """
    out: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200:
            log(f"  crt.sh: HTTP {r.status_code}", "yellow")
            return out
        for entry in r.json():
            for field_name in ("name_value", "common_name"):
                raw = entry.get(field_name) or ""
                for piece in str(raw).split("\n"):
                    h = normalise(piece)
                    if h:
                        out.add(h)
    except json.JSONDecodeError:
        log("  crt.sh: non-JSON response (rate limited?)", "yellow")
    except requests.RequestException as e:
        log(f"  crt.sh: {type(e).__name__}", "yellow")
    return out


def src_otx(session: requests.Session, domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200:
            log(f"  OTX: HTTP {r.status_code}", "yellow")
            return out
        for e in r.json().get("passive_dns", []):
            h = normalise(e.get("hostname", ""))
            if h:
                out.add(h)
    except (json.JSONDecodeError, requests.RequestException) as e:
        log(f"  OTX: {type(e).__name__}", "yellow")
    return out


def src_hackertarget(session: requests.Session, domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        timeout=timeout)
        if "API count exceeded" in r.text or "error" in r.text.lower()[:40]:
            log("  HackerTarget: quota exceeded", "yellow")
            return out
        for line in r.text.splitlines():
            h = normalise(line.split(",")[0])
            if h:
                out.add(h)
    except requests.RequestException as e:
        log(f"  HackerTarget: {type(e).__name__}", "yellow")
    return out


def src_certspotter(session: requests.Session, domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code == 429:
            log("  CertSpotter: rate limited", "yellow")
            return out
        if r.status_code != 200:
            return out
        for e in r.json():
            for name in e.get("dns_names", []):
                h = normalise(name)
                if h:
                    out.add(h)
    except (json.JSONDecodeError, requests.RequestException) as e:
        log(f"  CertSpotter: {type(e).__name__}", "yellow")
    return out


def src_rapiddns(session: requests.Session, domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = session.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                        timeout=timeout)
        if r.status_code != 200:
            return out
        for m in re.finditer(r"<td>([A-Za-z0-9_.\-*]+\." + re.escape(domain) + r")</td>",
                             r.text, re.I):
            h = normalise(m.group(1))
            if h:
                out.add(h)
    except requests.RequestException as e:
        log(f"  RapidDNS: {type(e).__name__}", "yellow")
    return out


SOURCES = {
    "crtsh": src_crtsh,
    "otx": src_otx,
    "hackertarget": src_hackertarget,
    "certspotter": src_certspotter,
    "rapiddns": src_rapiddns,
}


# --------------------------------------------------------------------------
# Wildcard DNS detection
# --------------------------------------------------------------------------

def wildcard_ips(domain: str, probes: int = 3) -> set[str]:
    """Resolve random labels to learn what a wildcard record answers with.

    Without this, a wildcard zone makes every guessed name look alive.
    """
    found: set[str] = set()
    for _ in range(probes):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        try:
            _, _, addrs = socket.gethostbyname_ex(f"{label}.{domain}")
            found.update(addrs)
        except (socket.gaierror, socket.herror, UnicodeError, OSError):
            pass
    return found


# --------------------------------------------------------------------------
# Resolution + probing
# --------------------------------------------------------------------------

@dataclass
class Host:
    host: str
    ips: list[str] = field(default_factory=list)
    cname: Optional[str] = None
    wildcard: bool = False
    scheme: Optional[str] = None
    status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    redirect: Optional[str] = None
    cert_sans: list[str] = field(default_factory=list)
    takeover: Optional[str] = None
    error: Optional[str] = None


# CNAME targets that commonly indicate a dangling/claimable resource.
TAKEOVER_CNAMES = {
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "ghost.io": "Ghost",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "zendesk.com": "Zendesk",
    "fastly.net": "Fastly",
    "netlify.app": "Netlify",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket",
    "readthedocs.io": "Read the Docs",
    "statuspage.io": "Statuspage",
    "shopify.com": "Shopify",
}

# Response bodies that, combined with a matching CNAME, suggest an unclaimed host.
TAKEOVER_BODY_SIGNS = (
    "NoSuchBucket", "There isn't a GitHub Pages site here",
    "no such app", "The specified bucket does not exist",
    "Sorry, this shop is currently unavailable", "project not found",
    "Repository not found", "Do you want to register",
    "herokucdn.com/error-pages/no-such-app.html",
    "The requested URL was not found on this server",
)

TITLE_RX = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def resolve(host: str, wc: set[str]) -> Host:
    h = Host(host=host)
    try:
        name, aliases, addrs = socket.gethostbyname_ex(host)
        h.ips = sorted(set(addrs))
        if name and name.lower().rstrip(".") != host:
            h.cname = name.lower().rstrip(".")
    except (socket.gaierror, socket.herror):
        h.error = "NXDOMAIN"
        return h
    except (UnicodeError, OSError) as e:
        h.error = type(e).__name__
        return h
    if wc and set(h.ips) <= wc:
        h.wildcard = True
    return h


def fetch_cert_sans(host: str, timeout: float) -> list[str]:
    """Pull SANs from the TLS certificate - a cheap extra discovery source."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return []
    if not cert:
        return []
    out = set()
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS":
            n = normalise(val)
            if n:
                out.add(n)
    return sorted(out)


def probe(h: Host, session: requests.Session, timeout: float, grab_certs: bool) -> Host:
    if h.error or not h.ips:
        return h
    if grab_certs:
        h.cert_sans = fetch_cert_sans(h.host, timeout)
    body = ""
    for scheme in ("https", "http"):
        try:
            r = session.get(f"{scheme}://{h.host}", timeout=timeout,
                            verify=False, allow_redirects=True)
        except requests.RequestException:
            continue
        h.scheme = scheme
        h.status = r.status_code
        h.server = r.headers.get("Server")
        if r.history:
            h.redirect = r.url
        body = r.text[:20000] if r.text else ""
        m = TITLE_RX.search(body)
        if m:
            h.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        break

    # Takeover heuristic: a CNAME at a known provider PLUS an unclaimed-looking
    # response. Either signal alone is far too noisy to report.
    target = h.cname or ""
    provider = next((p for sfx, p in TAKEOVER_CNAMES.items() if target.endswith(sfx)), None)
    if provider and body and any(sig.lower() in body.lower() for sig in TAKEOVER_BODY_SIGNS):
        h.takeover = f"possible {provider} takeover"
    return h


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_outputs(domain: str, hosts: list[Host], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    rows = [asdict(h) for h in hosts]
    stem = domain.replace("/", "_")

    (outdir / f"{stem}.json").write_text(json.dumps(
        {"tool": "recon-scope-hunter", "version": VERSION, "domain": domain,
         "count": len(rows), "hosts": rows}, indent=2))

    cols = ["host", "ips", "cname", "wildcard", "scheme", "status", "title",
            "server", "redirect", "takeover", "error"]
    with (outdir / f"{stem}.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r = dict(r)
            r["ips"] = ";".join(r["ips"])
            w.writerow(r)

    # Plain host lists, for piping into httpx / nuclei / ffuf.
    live = [h.host for h in hosts if h.ips and not h.wildcard]
    (outdir / f"{stem}.hosts.txt").write_text("\n".join(sorted(live)) + "\n")
    web = [f"{h.scheme}://{h.host}" for h in hosts if h.status]
    (outdir / f"{stem}.urls.txt").write_text("\n".join(sorted(web)) + "\n")


def print_table(domain: str, hosts: list[Host], limit: int) -> None:
    shown = [h for h in hosts if h.ips and not h.wildcard]
    if _console is None:
        for h in shown[:limit]:
            print(f"{h.host:50} {','.join(h.ips[:2]):32} {h.status or '-'}")
        return
    t = Table(title=f"{domain} - {len(shown)} live of {len(hosts)} discovered")
    t.add_column("Host", style="cyan", max_width=44, overflow="fold")
    t.add_column("IP", style="magenta", max_width=18)
    t.add_column("St", justify="right")
    t.add_column("Title", style="green", max_width=34, overflow="ellipsis")
    t.add_column("Flag", style="bold red", max_width=22)
    for h in shown[:limit]:
        code = h.status or 0
        colour = "green" if 200 <= code < 300 else "yellow" if 300 <= code < 400 else \
                 "red" if code >= 400 else "dim"
        t.add_row(h.host, h.ips[0] if h.ips else "-",
                  f"[{colour}]{h.status or '-'}[/]", h.title or "",
                  h.takeover or "")
    _console.print(t)
    if len(shown) > limit:
        log(f"... and {len(shown) - limit} more (see output files)", "dim")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run_domain(domain: str, args, session: requests.Session) -> list[Host]:
    log(f"\n=== {domain} ===", "bold cyan")

    chosen = [s.strip() for s in args.sources.split(",")] if args.sources else list(SOURCES)
    unknown = [s for s in chosen if s not in SOURCES]
    if unknown:
        log(f"Unknown source(s) ignored: {', '.join(unknown)}", "yellow")
        chosen = [s for s in chosen if s in SOURCES]

    raw: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=len(chosen) or 1) as ex:
        futs = {ex.submit(SOURCES[s], session, domain, args.timeout): s for s in chosen}
        for fut in cf.as_completed(futs):
            name = futs[fut]
            try:
                got = fut.result()
            except Exception as e:
                log(f"  {name}: {type(e).__name__}", "yellow")
                continue
            log(f"  {name}: {len(got)}", "dim")
            raw |= got

    # Scope enforcement. Passive DNS in particular returns plenty of hosts that
    # are not in the target domain at all; scanning those would be out of scope.
    scoped = {h for h in raw if in_scope(h, domain)}
    dropped = len(raw) - len(scoped)
    log(f"  collected {len(raw)}, in scope {len(scoped)}"
        + (f", dropped {dropped} out-of-scope" if dropped else ""), "green")
    if args.extra_scope:
        for extra in args.extra_scope.split(","):
            extra = extra.strip().lower()
            if extra:
                scoped |= {h for h in raw if in_scope(h, extra)}

    if not scoped:
        return []

    wc = set() if args.no_wildcard_check else wildcard_ips(domain)
    if wc:
        log(f"  wildcard DNS detected -> {', '.join(sorted(wc))}", "yellow")

    results: list[Host] = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for h in ex.map(lambda x: resolve(x, wc), sorted(scoped)):
            results.append(h)

    resolved = [h for h in results if h.ips and not h.wildcard]
    wc_count = sum(1 for h in results if h.wildcard)
    log(f"  resolved {len(resolved)}"
        + (f" ({wc_count} suppressed as wildcard)" if wc_count else ""), "green")

    if not args.no_probe and resolved:
        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            list(ex.map(lambda h: probe(h, session, args.http_timeout, args.certs),
                        resolved))

    # TLS SANs can reveal names none of the passive sources had.
    if args.certs:
        new = {n for h in resolved for n in h.cert_sans
               if in_scope(n, domain) and n not in scoped}
        if new:
            log(f"  TLS certificates revealed {len(new)} additional name(s)", "cyan")
            for h in ex_map_resolve(new, wc, args.threads):
                results.append(h)

    return results


def ex_map_resolve(names: Iterable[str], wc: set[str], threads: int) -> list[Host]:
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        return list(ex.map(lambda x: resolve(x, wc), sorted(names)))


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="recon-scope-hunter",
        description="Passive subdomain discovery with scope enforcement and liveness triage.",
        epilog="Authorized use only. Discovery is passive; --no-probe keeps it fully passive.",
    )
    ap.add_argument("-d", "--domain", help="Single domain")
    ap.add_argument("-i", "--input", help="File with one domain per line")
    ap.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    ap.add_argument("--sources", help=f"Comma list of sources (default: all of {','.join(SOURCES)})")
    ap.add_argument("--extra-scope", help="Comma list of additional in-scope apex domains")
    ap.add_argument("-t", "--threads", type=int, default=40, help="Concurrency (default: 40)")
    ap.add_argument("--timeout", type=int, default=20, help="Source API timeout (default: 20)")
    ap.add_argument("--http-timeout", type=float, default=6.0, help="Probe timeout (default: 6)")
    ap.add_argument("--no-probe", action="store_true",
                    help="Resolve only; send no HTTP to the target (fully passive)")
    ap.add_argument("--no-wildcard-check", action="store_true",
                    help="Skip wildcard DNS detection")
    ap.add_argument("--certs", action="store_true",
                    help="Pull TLS certificate SANs and feed new names back in")
    ap.add_argument("--limit", type=int, default=40, help="Rows to print (default: 40)")
    ap.add_argument("--quiet", action="store_true", help="No console table")
    ap.add_argument("--version", action="version", version=f"recon-scope-hunter {VERSION}")
    args = ap.parse_args()

    if not args.domain and not args.input:
        ap.error("provide -d/--domain or -i/--input")

    targets: list[str] = []
    if args.domain:
        targets.append(args.domain.strip().lower().rstrip("."))
    if args.input:
        try:
            targets += [ln.strip().lower().rstrip(".")
                        for ln in Path(args.input).read_text().splitlines()
                        if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            log(f"Cannot read {args.input}: {e}", "bold red")
            return 2

    bad = [t for t in targets if not normalise(t)]
    if bad:
        log(f"Skipping invalid domain(s): {', '.join(bad)}", "yellow")
    targets = [t for t in targets if normalise(t)]
    if not targets:
        log("No valid domains to scan.", "bold red")
        return 2

    session = make_session()
    outdir = Path(args.output)
    total = 0
    takeovers: list[str] = []
    for domain in dict.fromkeys(targets):
        hosts = run_domain(domain, args, session)
        if hosts:
            if not args.quiet:
                print_table(domain, hosts, args.limit)
            write_outputs(domain, hosts, outdir)
            total += len([h for h in hosts if h.ips and not h.wildcard])
            takeovers += [f"{h.host} ({h.takeover})" for h in hosts if h.takeover]
        else:
            log("  nothing in scope resolved", "yellow")
        if len(targets) > 1:
            time.sleep(1.0)  # be polite to the public APIs

    log(f"\nDone. {total} live host(s) across {len(targets)} domain(s). "
        f"Output in {outdir}/", "bold green")
    if takeovers:
        log(f"{len(takeovers)} possible takeover(s) - VERIFY MANUALLY before reporting:",
            "bold red")
        for t in takeovers:
            log(f"  - {t}", "red")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nInterrupted.", "yellow")
        sys.exit(130)
