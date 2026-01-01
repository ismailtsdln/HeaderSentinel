# 🛡️ HeaderSentinel

<p align="center">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Security-Red?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Quality-Production-blue?style=for-the-badge" alt="Quality">
</p>

**HeaderSentinel** is a high-performance, professional HTTP security analyzer written in Go. It performs deep inspection of HTTP response headers and status behavior to identify security misconfigurations, calculate risk scores, and provide actionable remediation advice.

---

## 🎯 Purpose

Modern web security relies heavily on correctly configured HTTP headers. **HeaderSentinel** empowers security engineers and developers to:

- **Audit** security headers (CSP, HSTS, XFO, etc.) against best practices.
- **Trace** redirect chains to detect insecure downgrades (HTTPS -> HTTP).
- **Analyze** information disclosure via `Server` and `X-Powered-By` headers.
- **Benchmark** security posture with an automated scoring system.
- **Integrate** with CI/CD pipelines via JSON and SARIF exports.

---

## ✨ Features

- 🚀 **Ultra-Fast:** Built with Go for maximum concurrency and performance.
- 🔍 **Deep Analysis:** Smart logic to detect misconfigured values, not just missing headers.
- 🔁 **Redirect Tracker:** Complete visibility into redirect hops and security transitions.
- 📊 **Security Scoring:** Automated 0-100 score based on risk severity (Critical to Info).
- 📁 **Export Ready:** Support for **Table**, **JSON**, and **SARIF** (Static Analysis Results Interchange Format) outputs.
- 🛠️ **Bulk Processing:** Scan thousands of URLs concurrently using simple input files.
- 📦 **Zero Dependencies:** Minimal footprint, easy to install and deploy.

---

## 🚀 Installation

Install HeaderSentinel directly using the Go toolchain. Using the `-v` flag is recommended to see the installation progress:

```bash
go install -v github.com/ismailtsdln/HeaderSentinel/cmd/headersentinel@latest
```

This will download, compile, and install the `headersentinel` binary into your `$GOPATH/bin` directory. Ensure that this directory is in your system's `PATH` to run the tool from anywhere.

---

## 🛠️ Usage

### Quick Scan

Analyze a single target with default settings:

```bash
headersentinel -u https://example.com
```

### Bulk Analysis

Scan multiple targets from a file with high concurrency:

```bash
headersentinel -i targets.txt -c 50
```

### Reporting

Generate machine-readable reports for automation:

```bash
headersentinel -u https://example.com -json report.json -sarif results.sarif
```

### Options Breakdown

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-u` | Single URL to scan | `""` |
| `-i` | Path to bulk input file | `""` |
| `-c` | Concurrency level | `10` |
| `-t` | Timeout in seconds | `10` |
| `-follow` | Follow redirects | `true` |
| `-json` | Path to save JSON report | `""` |
| `-sarif` | Path to save SARIF report | `""` |

---

## 🧠 Security Checks

| Header | Risk if Missing/Bad | Description |
| :--- | :--- | :--- |
| `Content-Security-Policy` | **High** | Prevents XSS and data injection attacks. |
| `Strict-Transport-Security` | **Medium** | Enforces HTTPS communication. |
| `X-Frame-Options` | **Medium** | Mitigates Clickjacking attacks. |
| `X-Content-Type-Options` | **Low** | Prevents MIME-sniffing vulnerabilities. |
| `Referrer-Policy` | **Low** | Controls information leakage in Referer headers. |
| `Permissions-Policy` | **Low** | Restricts access to sensitive browser APIs. |
| `Cross-Origin-*` | **Low** | Isolates documents and prevents side-channel attacks. |
| `Server / X-Powered-By` | **Low** | Prevents information disclosure about the tech stack. |

---

## 📊 Scoring System

HeaderSentinel assigns a security score based on the weighted severity of findings:

- **Excellent (90-100):** Strong security posture.
- **Low Risk (70-89):** Minor improvements possible.
- **Medium Risk (50-69):** Significant security configurations missing.
- **High Risk (30-49):** Critical gaps in header security.
- **Critical (0-29):** Highly vulnerable configuration.

---

## 🏗️ Architecture

The project follows a clean, modular structure for maintainability and performance:

- `cmd/headersentinel`: Main CLI entry point.
- `internal/scanner`: Analysis logic for headers and redirects.
- `internal/rules`: Definitions of security standards and risk levels.
- `internal/scoring`: Mathematical calculation of the security score.
- `internal/report`: Multi-format reporting engine.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<p align="center">
  Developed with ❤️ by <b>Ismail Tasdelen</b>
</p>
