# ClickJackCheck

![Banner](https://img.shields.io/badge/Security-Tool-red.svg)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)

**ClickJackCheck** is a lightweight yet powerful Python tool designed to assess a website's vulnerability to Clickjacking attacks. It inspects HTTP headers to ensure proper protection mechanisms like `X-Frame-Options` and `Content-Security-Policy` (CSP) are in place.

---

## 🚀 Features

- **Header Inspection**: Checks for `X-Frame-Options` and verifies if it's set to `DENY` or `SAMEORIGIN`.
- **CSP Analysis**: Looks for the `frame-ancestors` directive in the `Content-Security-Policy` header.
- **Vulnerability Assessment**: categorizes the protection level as Good, Weak, or None.
- **Actionable Recommendations**: Provides specific advice on how to secure the target URL.

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

**Example:**

```bash
python clickjackcheck.py https://example.com
```

---

## 📊 Output Explanation

The tool provides a clear summary of the findings:

- **✅ PROTECTED**: The site checks out! It has robust headers to prevent framing.
- **❗ VULNERABLE**: The site is missing critical headers and might be susceptible to UI redressing attacks.
- **Weak**: Some headers are present but might be misconfigured.

---

## 👨‍💻 Credits

**Built By:** MIHx0 (Muhammad Izaz Haider)  
**Powered by:** The PenTrix

---

*Disclaimer: This tool is for educational and ethical testing purposes only. Usage for attacking targets without prior mutual consent is illegal.*
