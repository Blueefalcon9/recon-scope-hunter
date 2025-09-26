# Recon Scope Hunter
Automated passive reconnaissance tool for discovering and resolving subdomains.

## Features
- Collects from crt.sh, AlienVault OTX, HackerTarget
- Resolves DNS and checks HTTP status
- Outputs JSON & CSV
- Threaded, clean output via Rich

## Usage
```bash
python3 recon-scope-hunter.py -d example.com -o output
