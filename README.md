# Recon Scope Hunter

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Passive subdomain discovery with **scope enforcement** and liveness triage. Built for the first hour of
an engagement: produce a verified, in-scope target list instead of a raw dump.

Discovery is passive — nothing is sent to the target. With `--no-probe` the whole run stays passive,
so it is safe to run before authorization lands.

## Why v2

| Defect in v1 | Effect | Fix |
|---|---|---|
| crt.sh `name_value` treated as one hostname | **the field is newline-delimited; every extra SAN was silently discarded** | Split on newlines, parse `common_name` too |
| No scope filtering | passive DNS returns unrelated domains — **out-of-scope hosts entered the target list** | Every result checked against the apex |
| Wildcards kept verbatim | `*.example.com` reported as a host | Normalised to the apex it covers |
| No wildcard-DNS detection | a wildcard zone makes every name look alive | Random-label probes; wildcard hits suppressed |
| `import os` at the bottom of the file | broke if imported as a module | Imports at the top |
| Bare `except:` everywhere | errors silently swallowed | Typed exception handling, per-source reporting |
| No User-Agent, no retries | throttled or blocked silently | Identifying UA, backoff, 429 handling |

The scope guard rejects both `evil-example.com` and `example.com.attacker.net` — the classic
suffix-confusion bypass.

## Sources

crt.sh and CertSpotter (certificate transparency), AlienVault OTX (passive DNS), HackerTarget, RapidDNS.
Optionally TLS certificate SANs from live hosts, fed back in as new candidates (`--certs`).

## Install

```bash
git clone https://github.com/Blueefalcon9/recon-scope-hunter.git
cd recon-scope-hunter
pip install -r requirements.txt
```

## Usage

```bash
python3 recon-scope-hunter.py -d example.com
python3 recon-scope-hunter.py -d example.com --no-probe        # fully passive
python3 recon-scope-hunter.py -d example.com --certs           # harvest TLS SANs
python3 recon-scope-hunter.py -i domains.txt -o client-recon
```

## Options

| Flag | Default | Description |
|---|---|---|
| `-d`, `--domain` | — | Single domain |
| `-i`, `--input` | — | File with one domain per line |
| `-o`, `--output` | `output` | Output directory |
| `--sources` | all | Comma list: `crtsh,otx,hackertarget,certspotter,rapiddns` |
| `--extra-scope` | — | Additional in-scope apex domains |
| `-t`, `--threads` | `40` | Concurrency |
| `--timeout` | `20` | Source API timeout |
| `--http-timeout` | `6` | Probe timeout |
| `--no-probe` | off | Resolve only; send no HTTP to the target |
| `--no-wildcard-check` | off | Skip wildcard DNS detection |
| `--certs` | off | Pull TLS SANs and feed new names back in |
| `--limit` | `40` | Rows to print |

## Output

`<domain>.json`, `<domain>.csv`, plus two pipe-friendly files:

```bash
cat output/example.com.hosts.txt | nuclei -t cves/
cat output/example.com.urls.txt  | httpx -title -tech-detect
```

## Subdomain takeover

Flagged only when a CNAME points at a known provider **and** the response body matches an unclaimed-resource
signature. Either signal alone is far too noisy. Treat every hit as a lead: **verify manually and confirm you
are authorized to claim the resource before acting.**

## Interpreting the results

Certificate transparency returns historical names, so expect hosts that no longer resolve — the resolution
step is what filters them. The `dropped N out-of-scope` line is worth reading: a high count usually means a
source returned a shared-hosting neighbour rather than anything of yours.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized
scanning is illegal in most jurisdictions. You are responsible for staying inside your authorized scope.

## License

MIT — see [LICENSE](LICENSE).
