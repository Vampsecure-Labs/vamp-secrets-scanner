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

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-secrets-scanner` is a static analysis tool that detects hardcoded secrets, credentials, and sensitive data across source code repositories, configuration files, and directory trees. It combines a database of 80+ regex patterns covering cloud keys, payment tokens, PKI material, and PII with Shannon entropy analysis to surface high-entropy strings that elude pattern matching. A dedicated Git history scanner surfaces secrets that were removed from the working tree but remain reachable in commit history.

Designed for pre-deployment code reviews, penetration testing engagements, and CI/CD pipeline integration. All analysis is fully local — no data leaves the machine.

### Features

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

### Requirements

```
pip install -r requirements.txt
```

Runtime dependencies:

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library only beyond `rich`: `re`, `os`, `math`, `pathlib`, `hashlib`, `json`, `argparse`, `subprocess`.

### Installation

```bash
pip install vamp-secrets-scanner
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-secrets-scanner
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-secrets-scanner.git
cd vamp-secrets-scanner
pip install -r requirements.txt
```

### Usage

```bash
python vamp_secrets_scanner.py --help
```

```
usage: vamp-secrets-scanner [-h] [-o FILE] [--html FILE] [--sarif FILE]
                             [--min-severity {CRITICAL,HIGH,MEDIUM,LOW}] [--only-critical]
                             [--all-extensions] [--max-depth N] [--no-entropy]
                             [--entropy-threshold BITS] [--exclude-dir DIR]
                             [--git-history] [--max-commits N]
                             [--allowlist FILE] [--generate-allowlist FILE]
                             [--install-hook] [--export-semgrep FILE]
                             DIRECTORY
```

#### Examples

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

### Sample Output

```
  vamp-secrets-scanner v3.1.1 · 271 patterns · scanning: /repo/
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

  EXTRA PHASE — Active verification (3 secrets)

  ✖ ACTIVE   AWS key pair [AKIAIOSS…] — config.py
  ? indeterminate GitHub Fine-Grained PAT [github_***] — .env:3

  Verification: 1 active · 0 revoked · 2 without data
  ⚠ URGENT ACTION: immediately rotate the active secrets listed above.
```

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Colored table + detailed panels for CRITICAL findings |
| JSON | `-o FILE` | Structured findings with summary counts, full context, and Git metadata |
| HTML | `--html FILE` | Dark-theme standalone report; rows expand to show source context |
| SARIF 2.1.0 | `--sarif FILE` | Compatible with GitHub Advanced Security, VS Code SARIF Viewer |
| Semgrep YAML | `--export-semgrep FILE` | Importable ruleset: `semgrep --config FILE DIR` |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at the selected severity level |
| `1` | One or more HIGH findings detected |
| `2` | One or more CRITICAL findings detected |
| `130` | Interrupted by user (Ctrl+C) |

### Why vamp-secrets-scanner vs. TruffleHog v3 · Gitleaks v8 · detect-secrets

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

### Check Coverage

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

### Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

### Version History

| Version | Main changes |
|---------|-------------|
| v3.1.1 | Bilingual README (EN/ES) |
| v3.1.0 | **+29 enterprise/streaming/IoT patterns** · `enterprise_streaming.yaml`: Salesforce, ServiceNow, HubSpot, Monday, Freshdesk, Intercom, Confluent, Pulsar, RabbitMQ, MongoDB Atlas, CockroachDB, PlanetScale, Supabase, AWS IoT, Azure IoT, Firebase, Unity, RevenueCat, Snyk, SonarQube, Checkmarx, Proxmox, VMware, Nutanix, Terraform Cloud, HashiCorp Vault · **300+ patterns total** · 9 YAML files |
| v3.0.0 | Extensible YAML engine — 8 `rules/*.yaml` files, **271 patterns** (×3.5 vs v2.7); new categories: AI APIs, hardware/web3/gaming/enterprise; daemon mode `--watch N`; `--delta FILE` diff; importable package |
| v2.7.0 | +15 SaaS patterns (Stripe, Twilio, SendGrid, Mailgun, Resend, Postmark...); `--only-critical`; configurable entropy threshold |
| v2.6.0 | `--delta FILE` — NEW/RECURRING/RESOLVED by SHA fingerprint |
| v2.5.0 | `--watch N` daemon mode with Telegram notifications; `--export-semgrep` |
| v2.4.0 | Kubernetes Secrets scan (`--k8s`); `--install-hook` pre-commit |
| v2.3.0 | SARIF 2.1.0 export; `--verify` live AWS verification |
| v2.2.0 | 77 patterns; Docker runtime scan; git history scan; SARIF beta |
| v1.0.0 | MVP 40+ basic patterns (AWS, GCP, GitHub, Slack) |

---

© VampSecure Studios — VampSecure Labs Security Research Division
For authorized security testing only.

---

<a name="español"></a>
## 🇪🇸 Español

`vamp-secrets-scanner` es una herramienta de análisis estático que detecta secretos hardcodeados, credenciales y datos sensibles en repositorios de código fuente, ficheros de configuración y árboles de directorios. Combina una base de datos de más de 80 patrones regex que cubren claves cloud, tokens de pago, material PKI y PII con análisis de entropía de Shannon para detectar strings de alta entropía que eluden la comparación por patrones. Un escáner de historial Git dedicado detecta secretos eliminados del árbol de trabajo pero accesibles en el historial de commits.

Diseñado para revisiones de código pre-despliegue, engagements de penetration testing e integración en pipelines CI/CD. Todo el análisis es completamente local — no sale ningún dato de la máquina.

### Características

- **Más de 80 patrones de secretos** en proveedores cloud (AWS, GCP, Azure), tokens VCS (GitHub PAT, GitLab PAT), pasarelas de pago (Stripe, PayPal, Braintree), plataformas de mensajería (Slack, Telegram, Discord, Twilio), DSNs de base de datos, secretos JWT, claves privadas PEM y claves privadas WireGuard
- **Detección de PII** para PANs de tarjetas de crédito/débito (Visa, Mastercard, Amex, Discover), IBAN/BIC, códigos CVV, SSN de EE.UU., DNI/NIE/CIF/NUSS españoles y números NHS
- **Análisis de entropía de Shannon** en strings de contexto de asignación — detecta secretos generados sin formato conocido (umbral configurable, por defecto 4,5 bits/símbolo)
- **Escaneo del historial Git** — recorre todos los commits en todas las ramas, incluido el contenido eliminado, via `git log --all` + diffs por commit
- **Modelo de severidad de cuatro niveles**: CRITICAL / HIGH / MEDIUM / LOW con deduplicación por huella SHA-256
- **Soporte de allowlist** para suprimir falsos positivos conocidos por huella, nombre de patrón o prefijo de fichero; también genera allowlist JSON de línea base a partir de los hallazgos actuales
- **Exportación SARIF 2.1.0** para integración directa con GitHub Advanced Security y VS Code SARIF Viewer
- **Informe HTML dark-theme** — standalone, sin dependencias externas, filas de contexto colapsables por hallazgo
- **Instalador de hook pre-commit** — bloquea commits cuando se detectan hallazgos MEDIUM o superior
- **Exportación de reglas Semgrep** — convierte la base de datos de patrones completa a un ruleset YAML compatible con Semgrep
- **Informe unificado VSL para cliente** (HTML/PDF) via el módulo compartido `vampsec_report`

### Requisitos

```
pip install -r requirements.txt
```

Dependencias en runtime:

| Paquete | Versión |
|---------|---------|
| `rich`  | >= 13.7.0 |

Solo biblioteca estándar además de `rich`: `re`, `os`, `math`, `pathlib`, `hashlib`, `json`, `argparse`, `subprocess`.

### Instalación

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

### Uso

```bash
python vamp_secrets_scanner.py --help
```

```
uso: vamp-secrets-scanner [-h] [-o FICHERO] [--html FICHERO] [--sarif FICHERO]
                           [--min-severity {CRITICAL,HIGH,MEDIUM,LOW}] [--only-critical]
                           [--all-extensions] [--max-depth N] [--no-entropy]
                           [--entropy-threshold BITS] [--exclude-dir DIR]
                           [--git-history] [--max-commits N]
                           [--allowlist FICHERO] [--generate-allowlist FICHERO]
                           [--install-hook] [--export-semgrep FICHERO]
                           DIRECTORIO
```

#### Ejemplos

**Escanear el directorio actual (todas las severidades):**
```bash
python vamp_secrets_scanner.py .
```

**Escanear un repositorio incluyendo el historial Git completo:**
```bash
python vamp_secrets_scanner.py /ruta/al/repo --git-history
```

**Reportar solo hallazgos CRITICAL y HIGH, exportar SARIF para GitHub Actions:**
```bash
python vamp_secrets_scanner.py . --min-severity HIGH --sarif resultados.sarif
```

**Generar una allowlist de línea base para suprimir falsos positivos conocidos en CI:**
```bash
python vamp_secrets_scanner.py . --generate-allowlist baseline.json
```

**Aplicar allowlist, exportar JSON e informe HTML standalone:**
```bash
python vamp_secrets_scanner.py . --allowlist baseline.json -o hallazgos.json --html informe.html
```

**Limitar el escaneo del historial Git a los 100 commits más recientes:**
```bash
python vamp_secrets_scanner.py . --git-history --max-commits 100
```

**Instalar un hook pre-commit que bloquea commits con hallazgos MEDIUM o superior:**
```bash
python vamp_secrets_scanner.py . --install-hook
```

**Exportar todos los patrones como ruleset YAML para Semgrep:**
```bash
python vamp_secrets_scanner.py . --export-semgrep vampsec_rules.yaml
```

**Escanear solo hallazgos CRITICAL, aumentando el umbral de entropía para reducir ruido:**
```bash
python vamp_secrets_scanner.py . --only-critical --entropy-threshold 5.2
```

**Verificar credenciales AWS activas cuando se encuentran clave de acceso + secreto en el mismo fichero:**
```bash
python vamp_secrets_scanner.py . --verify
```

### Sample Output

```
  vamp-secrets-scanner v3.1.1 · 271 patrones · escaneando: /repo/
  ──────────────────────────────────────────────────────────────
  [CRITICAL] AWS Access Key ID                  config.py:14
             AKIAIOSFODNN7EXAMPLE
             Remediación: revocar clave inmediatamente vía consola IAM

  [CRITICAL] AWS Secret Access Key              config.py:15
             wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
             Remediación: rotar en IAM > Security credentials

  [HIGH]     GitHub Fine-Grained PAT            .env:3
             github_pat_11AABBCC…
             Remediación: revocar en github.com/settings/tokens

  ────────────────────────────────────
  Total: 3 hallazgos (2 CRITICAL, 1 HIGH)
  Exit code: 2

  FASE EXTRA — Verificación activa (3 secretos)

  ✖ ACTIVO   AWS key pair [AKIAIOSS…] — config.py
  ? indeterminado GitHub Fine-Grained PAT [github_***] — .env:3

  Verificación: 1 activos · 0 revocados · 2 sin datos
  ⚠ ACCIÓN URGENTE: rota inmediatamente los secretos activos listados.
```

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola (Rich) | _(por defecto)_ | Tabla coloreada + paneles detallados para hallazgos CRITICAL |
| JSON | `-o FICHERO` | Hallazgos estructurados con conteos de resumen, contexto completo y metadatos Git |
| HTML | `--html FICHERO` | Informe dark-theme standalone; filas se expanden para mostrar contexto del código |
| SARIF 2.1.0 | `--sarif FICHERO` | Compatible con GitHub Advanced Security, VS Code SARIF Viewer |
| Semgrep YAML | `--export-semgrep FICHERO` | Ruleset importable: `semgrep --config FICHERO DIR` |

### Exit codes

| Código | Significado |
|--------|-------------|
| `0` | Sin hallazgos en el nivel de severidad seleccionado |
| `1` | Uno o más hallazgos HIGH detectados |
| `2` | Uno o más hallazgos CRITICAL detectados |
| `130` | Interrumpido por el usuario (Ctrl+C) |

### Why vamp-secrets-scanner vs. TruffleHog v3 · Gitleaks v8 · detect-secrets

| Capacidad | vamp-secrets-scanner | TruffleHog v3 | Gitleaks v8 | detect-secrets |
|-----------|---------------------|---------------|-------------|----------------|
| Número de patrones | ✅ 300+ (9 módulos YAML) | ✅ ~700 detectores | ✅ ~150 reglas | ✅ ~30 plugins |
| Módulos de reglas personalizadas (sin recompilar) | ✅ YAML drop-in, hot-reload | ❌ requiere fuente Go | ✅ config TOML | ✅ plugins Python |
| Verificación live de credenciales (AWS STS) | ✅ `--verify` | ✅ Integrado | ❌ | ❌ |
| Entropía Shannon + patrón combinado | ✅ Umbral configurable | ✅ | ❌ | ✅ |
| Modo daemon / watch | ✅ `--watch N` | ❌ | ❌ | ❌ |
| Seguimiento delta (NEW / RECURRING / RESOLVED) | ✅ `--delta FICHERO` | ❌ | ❌ | ❌ |
| Exportación SARIF 2.1.0 | ✅ | ✅ | ✅ | ❌ |
| Escaneo de Kubernetes Secrets | ✅ `--k8s` | ❌ | ❌ | ❌ |
| Escaneo runtime Docker | ✅ | ❌ | ❌ | ❌ |
| PII española (DNI / NIE / CIF / NUSS) | ✅ | ❌ | ❌ | ❌ |
| Instalador hook pre-commit | ✅ `--install-hook` | ❌ | ✅ | ✅ |
| Exportación de reglas Semgrep | ✅ `--export-semgrep` | ❌ | ❌ | ❌ |
| Paquete Python importable | ✅ | ❌ | ❌ | ✅ |
| Informe VSL para cliente (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |

- **YAML modular** — nuevas categorías de secretos se añaden sin tocar el motor; ideal para entornos regulados que necesitan conjuntos de patrones personalizados por cliente.
- **Daemon + delta** — `--watch N` combinado con `--delta FICHERO` convierte el escáner en un monitor continuo que solo señala nuevas regresiones, reduciendo la fatiga de alertas en CI/CD.
- **Cobertura de PII española** — DNI, NIE, CIF, NUSS y números NHS junto con IBANs internacionales, permitiendo el cumplimiento del RGPD Art. 83 y el ENS.
- **Informe unificado** — el módulo compartido `vampsec_report` genera el mismo HTML/PDF con la marca VSL que el resto de herramientas del toolkit, por lo que un engagement cubre toda la ejecución del toolkit.

### Check Coverage

| Categoría de check | Estándar | Severidad |
|--------------------|----------|-----------|
| AWS Access Key ID + Secret (regex + entropía) | OWASP ASVS V2.10 / CWE-798 | CRITICAL |
| Claves de cuenta de servicio GCP, Azure, Oracle Cloud | CWE-312 | CRITICAL |
| GitHub PAT / GitLab PAT / Bitbucket App password | CWE-798 | HIGH |
| Secreto live Stripe / PayPal / Braintree / Square | CWE-312 | CRITICAL |
| Slack / Telegram Bot Token / Discord webhook | CWE-798 | HIGH |
| DSN de base de datos (PostgreSQL, MySQL, MongoDB Atlas, Redis) | CWE-312 | HIGH |
| Claves privadas PEM (RSA, EC, PKCS8, WireGuard `PrivateKey=`) | CWE-321 | CRITICAL |
| Secreto JWT / clave de firma HS256 | CWE-798 | HIGH |
| Credenciales IoT (AWS IoT, Azure IoT, Firebase) | `iot_embedded.yaml` | HIGH |
| Tokens SaaS (Salesforce, ServiceNow, HubSpot, Monday) | `enterprise_streaming.yaml` | HIGH |
| Claves de plataformas streaming (Confluent, Pulsar, RabbitMQ) | `enterprise_streaming.yaml` | MEDIUM |
| PII española — DNI / NIE / CIF / NUSS | RGPD Art. 83 / ENS | MEDIUM |
| PANs de tarjetas de crédito/débito (Visa, MC, Amex, Discover) | PCI-DSS / CWE-312 | HIGH |
| Strings de contexto de asignación de alta entropía | OWASP ASVS V2.10 | MEDIUM–HIGH |
| Historial Git — secretos eliminados en objetos commit | CWE-312 | variable |
| Manifiestos Kubernetes Secret (`--k8s`) | CWE-312 | HIGH |

### Parte del toolkit VampSecure Labs

Esta herramienta forma parte del **VampSecure Labs Security Toolkit** — una colección de herramientas de seguridad de calidad de investigación para penetration testing y ejercicios red/blue team autorizados.

- Toolkit completo: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orquestador: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v3.1.1 | README bilingüe (EN/ES) |
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
Solo para pruebas de seguridad autorizadas.
