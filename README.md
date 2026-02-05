# ClickJackCheck

![Banner](logo.png)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Security](https://img.shields.io/badge/Security-Tool-red.svg)

**ClickJackCheck** is a premium security assessment tool designed to audit websites for Clickjacking vulnerabilities. Built with modern coding standards and a beautiful command-line interface, it provides instant, actionable feedback on your web application's security posture.

---

## 🚀 Features

- **🛡️ Comprehensive Auditing**: Checks for `X-Frame-Options` and `Content-Security-Policy`.
- **🎨 Beautiful UI**: Powered by `Rich` for a visually stunning and readable output.
- **⚡ Fast & Efficient**: Streamlined execution with clean, actionable results.
- **📝 Detailed Recommendations**: Provides specific guidance on how to fix identified issues.

---

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MIHx0/ClickJackCheck.git
    cd ClickJackCheck
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Usage

Run the tool by providing the target URL as an argument:

```bash
python clickjackcheck.py <target_url>
```

**Options:**

- `-h, --help`: Show help message and exit.
- `--timeout`: Set custom timeout (default: 10s).

**Example:**

```bash
python clickjackcheck.py https://example.com
```

---

## 👨‍💻 Credits

<p align="center">
  <b>Built By:</b> MIHx0 (Muhammad Izaz Haider)<br>
  <b>Powered by:</b> The PenTrix
</p>

---

*Disclaimer: This tool is for educational and ethical testing purposes only. Usage for attacking targets without prior mutual consent is illegal.*
