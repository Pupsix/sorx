# sorx

> A lightweight CORS security analyzer for bug bounty hunters.

`sorx` is a CLI tool for analyzing CORS configurations, testing
common CORS misconfigurations, and identifying potentially
security-relevant CORS issues with a focus on **low noise and useful findings**.

![sorx UI](https://raw.githubusercontent.com/Pupsix/sorx/main/docs/demo-2.gif)

> [!WARNING]
> **sorx is currently under active development.**
> 
> This is an early test release. Features, detection rules, output formats, and CLI behavior may change in future versions.

## Features

- CORS misconfiguration detection
- Active origin fuzzing
- Credential & origin reflection checks
- Sensitive header analysis
- HTTP method analysis
- CORS combination checks
- Configurable timeout, rate limit & threads
- JSON output
- Low-noise findings

## Why sorx?

- **CLI-first** — Designed to fit naturally into recon and bug bounty pipelines.
- **Free & open source** — Free to use, inspect, modify, and contribute to.
- **Actively developed** — Continuously improved with new checks, payloads, and features.
- **Low noise** — Reports security-relevant CORS behavior without treating every permissive configuration as a vulnerability.
- **Automation-friendly** — Supports JSON output and configurable threads, rate limits, and timeouts.
- **Lightweight** — Simple setup with minimal dependencies.
- **Built for hunters and testers** — Designed around practical CORS testing workflows rather than generic HTTP scanning.
- **Exploitability-focused** — Prioritizes CORS configurations with realistic security impact over parser quirks or bypasses that do not translate into a meaningful attack.

## Installation

### pip

Install:

```
pip install sorx
```

Update:

```
pip install -U sorx
```

### pipx

Install:

```
pipx install sorx
```

Update:

```
pipx upgrade sorx
```

### From Github

Install directly from GitHub:

```
pip install git+https://github.com/Pupsix/sorx.git
```

Or with `pipx`:

```
pipx install git+https://github.com/Pupsix/sorx.git
```

### From Source

Clone the repository:

```
git clone https://github.com/Pupsix/sorx.git
cd sorx
```

Create a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
```

Install in editable mode:

```
pip install -e .
```

The editable installation allows changes to the source code to be reflected immediately without reinstalling the package.

> **Recommended:** Use `pip` or `pipx` for installation.  
> Installing from source is intended for development.

## Usage

Basic scan:

```
sorx -u https://example.com
```

Select testing mode:

```
sorx -u https://example.com -m quick
```

```
sorx -u https://example.com -m normal
```

```
sorx -u https://example.com -m deep
```

For all available options:

```
sorx --help
```

## Responsible Use

`sorx` is intended for authorized security testing, including:

- Bug bounty programs
- Penetration testing
- Security research
- Applications you own

Only test targets where you have permission to perform security testing.

Do not use active fuzzing against unauthorized systems.

## Status

`sorx` is currently under development.

The project focuses on useful findings rather than the number of checks. Some CORS configurations may be unusual without being vulnerabilities, so sorx attempts to prioritize security-relevant behavior and reduce unnecessary noise.

## License

MIT License
