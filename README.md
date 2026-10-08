<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-secrets-scanner</h1>
<p align="center">
  <strong>Static secrets and credential scanner with Git history analysis and SARIF export</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
  <img src="https://github.com/Vampsecure-Labs/vamp-secrets-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

---

## Overview

`vamp-secrets-scanner` is a static analysis tool that detects hardcoded secrets, credentials, and sensitive data across source code repositories, configuration files, and directory trees. It combines a database of 80+ regex patterns covering cloud keys, payment tokens, PKI material, and PII with Shannon entropy analysis to surface high-entropy strings that elude pattern matching. A dedicated Git history scanner surfaces secrets that were removed from the working tree but remain reachable in commit history.

Designed for pre-deployment code reviews, penetration testing engagements, and CI/CD pipeline integration. All analysis is fully local — no data leaves the machine.

## Features

- **80+ secret patterns** across cloud providers (AWS, GCP, Azure), VCS tokens (GitHub PAT, GitLab PAT), payment gateways (Stripe, PayPal, Braintree), messaging platforms (Slack, Telegram, Discord, Twilio), database DSNs, JWT secrets, PEM private keys, and WireGuard private keys
- **PII detection** for credit/debit card PANs (Visa, Mastercard, Amex, Discover), IBAN/BIC, CVV codes, US SSN, Spanish DNI/NIE/CIF/NUSS, and NHS numbers
- **Shannon entropy analysis** on assignment-context strings — catches generated secrets with no known format (configurable threshold, default 4.5 bits/symbol)
- **Git history scanning** — walks all commits across all branches, including deleted content, via `git log --all` + per-commit diffs
- **Four-tier severity model**: CRITICAL / HIGH / MEDIUM / LOW with deduplication by SHA-256 fingerprint
- **Allowlist support** to suppress known false positives by fingerprint, pattern name, or file prefix; also generates baseline allowlist JSON from current findings
- **SARIF 2.1.0 export** for direct integration with GitHub Advanced Security and VS Code SARIF Viewer
- **Dark-theme HTML report** — standalone, zero external dependencies, collapsible context rows per finding
- **Pre-commit hook installer** — blocks commits when MEDIUM+ findings are detected
- **Semgrep rule export** — converts the full pattern database to a Semgrep-compatible YAML ruleset
- **Unified VSL client report** (HTML/PDF) via the shared `vampsec_report` module

## Requirements

```
pip install -r requirements.txt
```

Runtime dependencies:

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library only beyond `rich`: `re`, `os`, `math`, `pathlib`, `hashlib`, `json`, `argparse`, `subprocess`.

## Installation


```bash
pip install vamp-secrets-scanner
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-secrets-scanner
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-secrets-scanner.git
cd vamp-secrets-scanner
pip install -r requirements.txt
```

## Usage

```bash
python vamp_secrets_scanner.py --help
```

```
usage: vamp-secrets-scanner [-h] [-o FICHERO] [--html FICHERO] [--sarif FICHERO]
                             [--min-severity {CRITICAL,HIGH,MEDIUM,LOW}] [--only-critical]
                             [--all-extensions] [--max-depth N] [--no-entropy]
                             [--entropy-threshold BITS] [--exclude-dir DIR]
                             [--git-history] [--max-commits N]
                             [--allowlist FICHERO] [--generate-allowlist FICHERO]
                             [--install-hook] [--export-semgrep FICHERO]
                             DIRECTORIO
```

### Examples

**Scan the current directory (all severities):**
```bash
python vamp_secrets_scanner.py .
```

**Scan a repository including full Git commit history:**
```bash
python vamp_secrets_scanner.py /path/to/repo --git-history
```

**Report only CRITICAL and HIGH findings, export SARIF for GitHub Actions:**
```bash
python vamp_secrets_scanner.py . --min-severity HIGH --sarif results.sarif
```

**Generate a baseline allowlist to suppress known false positives in CI:**
```bash
python vamp_secrets_scanner.py . --generate-allowlist baseline.json
```

**Apply allowlist, export JSON and standalone HTML report:**
```bash
python vamp_secrets_scanner.py . --allowlist baseline.json -o findings.json --html report.html
```

**Limit Git history scan to the 100 most recent commits:**
```bash
python vamp_secrets_scanner.py . --git-history --max-commits 100
```

**Install a pre-commit hook that blocks commits on MEDIUM+ findings:**
```bash
python vamp_secrets_scanner.py . --install-hook
```

**Export all patterns as a Semgrep YAML ruleset:**
```bash
python vamp_secrets_scanner.py . --export-semgrep vampsec_rules.yaml
```

**Scan only CRITICAL findings, raising entropy threshold to reduce noise:**
```bash
python vamp_secrets_scanner.py . --only-critical --entropy-threshold 5.2
```

**Verify active AWS credentials when both access key + secret are found in the same file:**
```bash
python vamp_secrets_scanner.py . --verify
```

## Sample Output

```
  vamp-secrets-scanner v3.0.0 · 271 patterns · scanning: /repo/
  ──────────────────────────────────────────────────────────────
  [CRITICAL] AWS Access Key ID                  config.py:14
             AKIAIOSFODNN7EXAMPLE
             Remediation: revoke key immediately via IAM console

  [CRITICAL] AWS Secret Access Key              config.py:15
             wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
             Remediation: rotate in IAM > Security credentials

  [HIGH]     GitHub Fine-Grained PAT            .env:3
             github_pat_11AABBCC…
             Remediation: revoke at github.com/settings/tokens

  ────────────────────────────────────
  Total: 3 findings (2 CRITICAL, 1 HIGH)
  Exit code: 2

  FASE EXTRA — Verificación activa (3 secretos)

  ✖ ACTIVO   AWS key pair [AKIAIOSS…] — config.py
  ? indeterminado GitHub Fine-Grained PAT [github_***] — .env:3

  Verificación: 1 activos · 0 revocados · 2 sin datos
  ⚠ ACCIÓN URGENTE: rota inmediatamente los secretos activos listados.
```

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Colored table + detailed panels for CRITICAL findings |
| JSON | `-o FILE` | Structured findings with summary counts, full context, and Git metadata |
| HTML | `--html FILE` | Dark-theme standalone report; rows expand to show source context |
| SARIF 2.1.0 | `--sarif FILE` | Compatible with GitHub Advanced Security, VS Code SARIF Viewer |
| Semgrep YAML | `--export-semgrep FILE` | Importable ruleset: `semgrep --config FILE DIR` |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at the selected severity level |
| `1` | One or more HIGH findings detected |
| `2` | One or more CRITICAL findings detected |
| `130` | Interrupted by user (Ctrl+C) |

## Why vamp-secrets-scanner vs. TruffleHog v3 · Gitleaks v8 · detect-secrets

| Capability | vamp-secrets-scanner | TruffleHog v3 | Gitleaks v8 | detect-secrets |
|------------|---------------------|---------------|-------------|----------------|
| Pattern count | ✅ 300+ (9 YAML modules) | ✅ ~700 detectors | ✅ ~150 rules | ✅ ~30 plugins |
| Custom rule modules (no recompile) | ✅ Drop-in YAML, hot-reload | ❌ Go source required | ✅ TOML config | ✅ Python plugins |
| Live credential verification (AWS STS) | ✅ `--verify` | ✅ Built-in | ❌ | ❌ |
| Shannon entropy + pattern combined | ✅ Configurable threshold | ✅ | ❌ | ✅ |
| Daemon / watch mode | ✅ `--watch N` | ❌ | ❌ | ❌ |
| Delta tracking (NEW / RECURRING / RESOLVED) | ✅ `--delta FILE` | ❌ | ❌ | ❌ |
| SARIF 2.1.0 export | ✅ | ✅ | ✅ | ❌ |
| Kubernetes Secrets scan | ✅ `--k8s` | ❌ | ❌ | ❌ |
| Docker runtime scan | ✅ | ❌ | ❌ | ❌ |
| Spanish PII (DNI / NIE / CIF / NUSS) | ✅ | ❌ | ❌ | ❌ |
| Pre-commit hook installer | ✅ `--install-hook` | ❌ | ✅ | ✅ |
| Semgrep rule export | ✅ `--export-semgrep` | ❌ | ❌ | ❌ |
| Importable Python package | ✅ | ❌ | ❌ | ✅ |
| VSL engagement report (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |

- **Modular YAML** — new secret categories drop in without touching the engine; perfect for regulated environments that need custom pattern sets per client engagement.
- **Daemon + delta** — `--watch N` combined with `--delta FILE` turns the scanner into a continuous monitor that flags only new regressions, reducing alert fatigue in CI/CD.
- **Spanish PII coverage** — DNI, NIE, CIF, NUSS, and NHS numbers alongside international IBANs, enabling compliance with GDPR Art. 83 and ENS.
- **Unified report** — the shared `vampsec_report` module produces the same VSL-branded HTML/PDF as every other Labs tool, so one engagement covers the full toolkit run.

## Check Coverage

| Check category | Standard | Severity |
|----------------|----------|----------|
| AWS Access Key ID + Secret (regex + entropy) | OWASP ASVS V2.10 / CWE-798 | CRITICAL |
| GCP, Azure, Oracle Cloud service account keys | CWE-312 | CRITICAL |
| GitHub PAT / GitLab PAT / Bitbucket App password | CWE-798 | HIGH |
| Stripe live secret / PayPal / Braintree / Square | CWE-312 | CRITICAL |
| Slack / Telegram Bot Token / Discord webhook | CWE-798 | HIGH |
| Database DSN (PostgreSQL, MySQL, MongoDB Atlas, Redis) | CWE-312 | HIGH |
| PEM private keys (RSA, EC, PKCS8, WireGuard `PrivateKey=`) | CWE-321 | CRITICAL |
| JWT secret / HS256 signing key | CWE-798 | HIGH |
| IoT credentials (AWS IoT, Azure IoT, Firebase) | `iot_embedded.yaml` | HIGH |
| SaaS tokens (Salesforce, ServiceNow, HubSpot, Monday) | `enterprise_streaming.yaml` | HIGH |
| Streaming platform keys (Confluent, Pulsar, RabbitMQ) | `enterprise_streaming.yaml` | MEDIUM |
| Spanish PII — DNI / NIE / CIF / NUSS | GDPR Art. 83 / ENS | MEDIUM |
| Credit / debit card PANs (Visa, MC, Amex, Discover) | PCI-DSS / CWE-312 | HIGH |
| High-entropy assignment-context strings | OWASP ASVS V2.10 | MEDIUM–HIGH |
| Git history — deleted secrets in commit objects | CWE-312 | varies |
| Kubernetes Secret manifests (`--k8s`) | CWE-312 | HIGH |

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v3.1.0 | **+29 patrones enterprise/streaming/IoT** · `enterprise_streaming.yaml`: Salesforce, ServiceNow, HubSpot, Monday, Freshdesk, Intercom, Confluent, Pulsar, RabbitMQ, MongoDB Atlas, CockroachDB, PlanetScale, Supabase, AWS IoT, Azure IoT, Firebase, Unity, RevenueCat, Snyk, SonarQube, Checkmarx, Proxmox, VMware, Nutanix, Terraform Cloud, HashiCorp Vault · **300+ patrones totales** · 9 ficheros YAML |
| v3.0.0 | Motor YAML extensible — 8 ficheros `rules/*.yaml`, **271 patrones** (×3.5 vs v2.7); nuevas categorías: IA APIs, hardware/web3/gaming/enterprise; daemon mode `--watch N`; `--delta FILE` diff; paquete importable |
| v2.7.0 | +15 SaaS patterns (Stripe, Twilio, SendGrid, Mailgun, Resend, Postmark...); `--only-critical`; entropy threshold configurable |
| v2.6.0 | `--delta FILE` — NEW/RECURRING/RESOLVED por fingerprint SHA |
| v2.5.0 | `--watch N` daemon mode con notificaciones Telegram; `--export-semgrep` |
| v2.4.0 | Kubernetes Secrets scan (`--k8s`); `--install-hook` pre-commit |
| v2.3.0 | SARIF 2.1.0 export; `--verify` verificación live AWS |
| v2.2.0 | 77 patrones; Docker runtime scan; git history scan; SARIF beta |
| v1.0.0 | MVP 40+ patrones básicos (AWS, GCP, GitHub, Slack) |

---

© VampSecure Studios — VampSecure Labs Security Research Division
For authorized security testing only.
