# OSINT Toolkit

A small, beginner-friendly toolkit for **ethical, passive OSINT on domains you own or are authorized to assess**. It gathers basic public technical information and does not attempt to identify, profile, or track private individuals.

## Features

- DNS lookup for a domain (A, AAAA, MX, NS, TXT)
- RDAP registration lookup for a domain
- Certificate Transparency search through `crt.sh`
- JSON output for saving results
- Clear prompts and a simple command-line interface

## Requirements

- Python 3.10+
- Internet access when running lookups
- No third-party Python packages required

## Quick start

```bash
python osint_toolkit.py example.com
```

Save results to a JSON file:

```bash
python osint_toolkit.py example.com --output results.json
```

Only assess domains you own or have permission to investigate. Public data can still be sensitive; collect the minimum necessary, respect site terms and applicable law, and do not use results for harassment, doxxing, stalking, credential attacks, or unauthorized access.

## What this tool does not do

- No people-search, face recognition, private-account access, or leaked-data searches
- No password guessing, scanning, exploitation, or bypassing access controls
- No automated bulk enumeration
- No claim that a result proves ownership or identity

## Sources

- DNS: system resolver via Python's standard library
- RDAP: `https://rdap.org/domain/`
- Certificate Transparency: `https://crt.sh/`

Availability, response formats, and rate limits of public services may change. Use the tool responsibly and avoid repeated requests.

## Project structure

```text
OSINT-Toolkit/
├── README.md
├── osint_toolkit.py
├── LICENSE
├── .gitignore
└── requirements.txt
```

## License

MIT. See [`LICENSE`](LICENSE).
