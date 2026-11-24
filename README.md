# Recon Scope Hunter

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Passive subdomain discovery for scoping an engagement. Pulls from three public sources, resolves what it
finds, and reports which hosts are actually live — so you start with a verified target list instead of a raw
dump.

**Passive only.** Nothing is sent to the target. All data comes from third-party sources, so this is safe to
run before authorization lands.

## What it does

1. **Collects** candidate subdomains from crt.sh (certificate transparency), AlienVault OTX, and HackerTarget
2. **Resolves** each one to an IP, concurrently
3. **Checks** HTTP status for anything that resolves
4. **Writes** `subdomains.json` and `subdomains.csv`

## Install

```bash
git clone https://github.com/Blueefalcon9/recon-scope-hunter.git
cd recon-scope-hunter
pip install -r requirements.txt
```

## Usage

```bash
python3 recon-scope-hunter.py -d example.com
python3 recon-scope-hunter.py -i domains.txt -o client-recon
```

## Options

| Flag | Default | Description |
|---|---|---|
| `-d`, `--domain` | — | Single domain to scan |
| `-i`, `--input` | — | File containing a list of domains, one per line |
| `-o`, `--output` | `output` | Output directory |

Pass either `-d` or `-i`.

## Notes

- All three sources are rate-limited and may throttle or return partial results on large domains. Cross-check
  anything you intend to rely on.
- Certificate transparency returns historical names, so expect hosts that no longer resolve — that is what
  the resolution step filters out.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized scanning and
credential discovery are illegal in most jurisdictions. You are responsible for staying inside your
authorized scope.

## License

MIT — see [LICENSE](LICENSE).
