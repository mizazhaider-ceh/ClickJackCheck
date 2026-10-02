# ClickJackCheck

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Security](https://img.shields.io/badge/Security-Tool-red.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**ClickJackCheck** audits websites for clickjacking protection. It inspects the `X-Frame-Options` and `Content-Security-Policy` (`frame-ancestors`) headers, tells you whether the site can be embedded in a third-party frame, and gives concrete remediation steps when it cannot.

---

## Features

- **Header auditing**: checks `X-Frame-Options` and CSP `frame-ancestors`
- **Clear verdicts**: protected, weak or vulnerable, with the reasoning shown
- **Batch scanning**: `-f targets.txt` scans a whole list and prints a summary table
- **JSON output**: `--json` for piping results into other tools
- **Sane edge cases**: obsolete `ALLOW-FROM` values are flagged as weak, not valid
- **Rich terminal UI**: color-coded tables and panels

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mizazhaider-ceh/ClickJackCheck.git
   cd ClickJackCheck
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

```bash
python clickjackcheck.py <target_url>
```

**Options:**

- `-f, --file PATH`: scan multiple URLs, one per line (lines starting with `#` are ignored)
- `--timeout SECONDS`: request timeout (default: 10)
- `--json`: print results as JSON
- `-h, --help`: show help message and exit

**Examples:**

```bash
python clickjackcheck.py https://example.com
python clickjackcheck.py example.com --json
python clickjackcheck.py -f targets.txt
```

**targets.txt format:**

```text
https://example.com
https://example.org
# lines starting with # are ignored
```

---

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

The test suite mocks all HTTP requests, so no network access is needed.

---

## Credits

<p align="center">
  <b>Built By:</b> mizazhaider-ceh (Muhammad Izaz Haider)<br>
  <b>Powered by:</b> The PenTrix
</p>

---

*Disclaimer: This tool is for educational and ethical testing purposes only. Usage for attacking targets without prior mutual consent is illegal.*
