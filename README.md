# portwave

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Category](https://img.shields.io/badge/recon-portscan-red)

A fast, dependency-free **async TCP port scanner**. Pure `asyncio` connect-scan — no raw sockets, no root required — with configurable concurrency, named/ranged port sets, service hints, and optional banner grabbing.

## Features
- `asyncio` connect scan, hundreds of ports in flight
- Port sets: `top100`, `all`, ranges (`1-1024`), lists (`22,80,443`)
- Service name hints + optional banner grab (`-b`)
- Tunable concurrency and timeout
- Zero dependencies

## Install
```bash
git clone https://github.com/anvarsadathk/portwave.git
cd portwave
python3 portwave.py --help
```

## Usage
```bash
# Top 100 ports (default)
python3 portwave.py scanme.nmap.org --yes-authorized

# Full range with banners
python3 portwave.py 10.0.0.5 -p all -b --yes-authorized

# Specific ports, higher concurrency, save output
python3 portwave.py target.tld -p 22,80,443,8080 -c 1000 -o ports.txt --yes-authorized
```

> portwave runs an **active** scan, so it requires `--yes-authorized` as an explicit in-scope confirmation.

## ⚠️ Responsible use
Port scanning hosts without permission is illegal in many jurisdictions. Scan only systems you own or are explicitly authorized to test.

## License
MIT © Anvar Sadath K.
