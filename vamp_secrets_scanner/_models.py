# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Modelos de datos, constantes y base de patrones
=============================================================
VampSecure Labs · vamp-secrets-scanner
Contiene VERSION, TOOL_NAME, patrones regex, enums y dataclasses.
Sin dependencias de I/O ni librerías externas.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Dict, List, Optional, Set

# ─────────────────────────────────────────────────────────────────────────────
# Versión y nombre de herramienta
# ─────────────────────────────────────────────────────────────────────────────

VERSION   = "3.0.0"
TOOL_NAME = "vamp-secrets-scanner"

# ─────────────────────────────────────────────────────────────────────────────
# Base de datos de patrones de secretos
# ─────────────────────────────────────────────────────────────────────────────

_RAW_PATTERNS: List[Dict[str, str]] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    {"name": "AWS Access Key ID",          "severity": "CRITICAL", "category": "Cloud · AWS",
     "regex": r"(?<![A-Z0-9])(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"},
    {"name": "AWS Secret Access Key",      "severity": "CRITICAL", "category": "Cloud · AWS",
     "regex": r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9+/]{40})['\"]"},
    {"name": "AWS Session Token",          "severity": "HIGH",     "category": "Cloud · AWS",
     "regex": r"(?i)aws.{0,20}session.token.{0,10}['\"]([A-Za-z0-9+/=]{100,})['\"]"},

    # ── GCP ──────────────────────────────────────────────────────────────────
    {"name": "Google API Key",             "severity": "CRITICAL", "category": "Cloud · GCP",
     "regex": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "GCP Service Account JSON",   "severity": "CRITICAL", "category": "Cloud · GCP",
     "regex": r'"private_key"\s*:\s*"-----BEGIN (RSA |EC )?PRIVATE KEY'},
    {"name": "Firebase API Key",           "severity": "HIGH",     "category": "Cloud · GCP",
     "regex": r"(?i)firebase.{0,20}['\"]AIza[0-9A-Za-z\-_]{35}['\"]"},

    # ── Azure ─────────────────────────────────────────────────────────────────
    {"name": "Azure Storage Key",          "severity": "CRITICAL", "category": "Cloud · Azure",
     "regex": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"},
    {"name": "Azure Client Secret",        "severity": "HIGH",     "category": "Cloud · Azure",
     "regex": r"(?i)(client.?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9~.\-_]{32,})['\"]?"},

    # ── GitHub ────────────────────────────────────────────────────────────────
    {"name": "GitHub PAT (classic)",       "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"ghp_[A-Za-z0-9]{36}"},
    {"name": "GitHub OAuth Token",         "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"gho_[A-Za-z0-9]{36}"},
    {"name": "GitHub App Token",           "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"ghs_[A-Za-z0-9]{36}"},
    {"name": "GitHub Fine-Grained PAT",    "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"github_pat_[A-Za-z0-9_]{82}"},
    {"name": "GitHub Actions Secret",      "severity": "MEDIUM",   "category": "VCS · GitHub",
     "regex": r"(?i)GITHUB_TOKEN\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"},

    # ── GitLab ────────────────────────────────────────────────────────────────
    {"name": "GitLab PAT",                 "severity": "HIGH",     "category": "VCS · GitLab",
     "regex": r"glpat-[A-Za-z0-9\-_]{20}"},
    {"name": "GitLab Runner Token",        "severity": "HIGH",     "category": "VCS · GitLab",
     "regex": r"GR1348941[A-Za-z0-9\-_]{20}"},

    # ── Stripe ────────────────────────────────────────────────────────────────
    {"name": "Stripe Live Secret Key",     "severity": "CRITICAL", "category": "Pagos · Stripe",
     "regex": r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Test Secret Key",     "severity": "MEDIUM",   "category": "Pagos · Stripe",
     "regex": r"sk_test_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Webhook Secret",      "severity": "CRITICAL", "category": "Pagos · Stripe",
     "regex": r"whsec_[A-Za-z0-9]{32,}"},
    {"name": "Stripe Publishable Key",     "severity": "LOW",      "category": "Pagos · Stripe",
     "regex": r"pk_live_[0-9a-zA-Z]{24,}"},

    # ── PayPal / Braintree ────────────────────────────────────────────────────
    {"name": "PayPal Client Secret",       "severity": "CRITICAL", "category": "Pagos · PayPal",
     "regex": r"(?i)paypal.{0,20}(client.?secret|secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{32,})['\"]?"},
    {"name": "Braintree Access Token",     "severity": "CRITICAL", "category": "Pagos · Braintree",
     "regex": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"},

    # ── Slack ─────────────────────────────────────────────────────────────────
    {"name": "Slack Bot Token",            "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}"},
    {"name": "Slack User Token",           "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32}"},
    {"name": "Slack App Token",            "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xapp-[0-9]-[A-Za-z0-9]{10}-[0-9]{13}-[A-Za-z0-9]{64}"},
    {"name": "Slack Webhook URL",          "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}"},
    {"name": "Slack Signing Secret",       "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"(?i)slack.{0,20}sign.{0,10}secret\s*[:=]\s*['\"]?([A-Za-z0-9]{32})['\"]?"},

    # ── Telegram ──────────────────────────────────────────────────────────────
    {"name": "Telegram BOT_TOKEN",         "severity": "CRITICAL", "category": "Comunicaciones · Telegram",
     "regex": r"(?<!\w)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?!\w)"},

    # ── Discord ───────────────────────────────────────────────────────────────
    {"name": "Discord Bot Token",          "severity": "HIGH",     "category": "Comunicaciones · Discord",
     "regex": r"(?i)discord.{0,20}['\"]([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})['\"]"},
    {"name": "Discord Webhook URL",        "severity": "HIGH",     "category": "Comunicaciones · Discord",
     "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}"},

    # ── Twilio ────────────────────────────────────────────────────────────────
    {"name": "Twilio Account SID",         "severity": "HIGH",     "category": "Comunicaciones · Twilio",
     "regex": r"AC[a-z0-9]{32}"},
    {"name": "Twilio Auth Token",          "severity": "CRITICAL", "category": "Comunicaciones · Twilio",
     "regex": r"(?i)twilio.{0,20}auth.?token\s*[:=]\s*['\"]?([a-z0-9]{32})['\"]?"},
    {"name": "Twilio API Key",             "severity": "HIGH",     "category": "Comunicaciones · Twilio",
     "regex": r"SK[a-z0-9]{32}"},

    # ── SendGrid ──────────────────────────────────────────────────────────────
    {"name": "SendGrid API Key",           "severity": "CRITICAL", "category": "Correo · SendGrid",
     "regex": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"},

    # ── Mailgun ───────────────────────────────────────────────────────────────
    {"name": "Mailgun API Key",            "severity": "HIGH",     "category": "Correo · Mailgun",
     "regex": r"key-[0-9a-f]{32}"},
    {"name": "Mailgun Webhook Key",        "severity": "HIGH",     "category": "Correo · Mailgun",
     "regex": r"(?i)mailgun.{0,20}['\"]([A-Za-z0-9\-]{72})['\"]"},

    # ── Claves privadas / certificados ────────────────────────────────────────
    {"name": "RSA Private Key (PEM)",      "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"},
    {"name": "EC Private Key (PEM)",       "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"},
    {"name": "OpenSSH Private Key",        "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"},
    {"name": "PKCS8 Private Key",          "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN\s+PRIVATE\s+KEY-----"},
    {"name": "PGP Private Key Block",      "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"},

    # ── WireGuard ─────────────────────────────────────────────────────────────
    {"name": "WireGuard PrivateKey",       "severity": "CRITICAL", "category": "Infraestructura · WireGuard",
     "regex": r"(?m)^PrivateKey\s*=\s*[A-Za-z0-9+/]{43}="},

    # ── Bases de datos ────────────────────────────────────────────────────────
    {"name": "PostgreSQL DSN con contraseña", "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"postgres(?:ql)?://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "MySQL DSN con contraseña",   "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"mysql://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "MongoDB URI con contraseña", "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "Redis URL con contraseña",   "severity": "HIGH",     "category": "Base de datos",
     "regex": r"redis://:([^@]{3,})@[^\s\"']+"},
    {"name": "MSSQL DSN con contraseña",   "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"(?i)Server=[^;]+;.*Password=[^;]{3,}"},

    # ── JWT ───────────────────────────────────────────────────────────────────
    {"name": "JSON Web Token (JWT)",       "severity": "HIGH",     "category": "Autenticación · JWT",
     "regex": r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"},
    {"name": "JWT Secret hardcodeado",     "severity": "CRITICAL", "category": "Autenticación · JWT",
     "regex": r"(?i)(jwt.?secret|JWT_SECRET)\s*[:=]\s*['\"](.{8,})['\"]"},

    # ── OAuth / API genéricos ─────────────────────────────────────────────────
    {"name": "Bearer Token en código",     "severity": "HIGH",     "category": "Autenticación · OAuth",
     "regex": r"(?i)Bearer\s+[A-Za-z0-9\-_=]{20,}(?=['\"\s])"},
    {"name": "OAuth client_secret",        "severity": "HIGH",     "category": "Autenticación · OAuth",
     "regex": r"(?i)client.?secret\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"},

    # ── NPM / PyPI ────────────────────────────────────────────────────────────
    {"name": "NPM Auth Token",             "severity": "HIGH",     "category": "Registros · NPM",
     "regex": r"//registry\.npmjs\.org/:_authToken\s*=\s*([A-Za-z0-9\-_]{36,})"},
    {"name": "PyPI Upload Token",          "severity": "HIGH",     "category": "Registros · PyPI",
     "regex": r"pypi-[A-Za-z0-9\-_]{80,}"},

    # ── Otros servicios ───────────────────────────────────────────────────────
    {"name": "Shopify Admin API Key",      "severity": "CRITICAL", "category": "E-commerce · Shopify",
     "regex": r"shpat_[A-Fa-f0-9]{32}"},
    {"name": "Shopify Storefront Token",   "severity": "MEDIUM",   "category": "E-commerce · Shopify",
     "regex": r"shpss_[A-Fa-f0-9]{32}"},
    {"name": "HubSpot API Key",            "severity": "HIGH",     "category": "CRM · HubSpot",
     "regex": r"(?i)hubspot.{0,20}['\"]([A-Za-z0-9\-]{36})['\"]"},

    # ── HashiCorp Vault / HCP ─────────────────────────────────────────────────
    {"name": "HashiCorp Vault Token",         "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)(?:VAULT_TOKEN|X-Vault-Token|vault.{0,10}token)\s*[:=]\s*['\"]?(s\.[a-zA-Z0-9]{24,})['\"]?"},
    {"name": "Vault Wrapped Token (HVS)",     "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"hvs\.[a-zA-Z0-9]{24,}"},
    {"name": "HCP Client Secret",             "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)HCP_CLIENT_SECRET\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{64,})['\"]?"},
    {"name": "Vault PKI Private Key (CVE-2026-5052)", "severity": "HIGH", "category": "Infraestructura · Vault",
     "regex": r"(?i)(?:vault|pki).{0,40}-----BEGIN\s*(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"},
    {"name": "Vault Unseal Key en fichero",   "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)unseal_key_\d+\s*:\s*[A-Za-z0-9+/=]{40,}"},
    {"name": "Vault Initial Root Token",      "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"Initial Root Token:\s+s\.[a-zA-Z0-9]+"},

    # ── PII — Tarjetas de pago ────────────────────────────────────────────────
    {"name": "Tarjeta Visa",               "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "Tarjeta Mastercard",         "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "Tarjeta American Express",   "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}(?!\d)"},
    {"name": "Tarjeta Discover",           "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "CVV/CVC hardcodeado",        "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?i)(?:cvv|cvc|csc|cvv2|cvc2)\s*[:=]\s*['\"]?([0-9]{3,4})['\"]?"},

    # ── PII — Cuenta bancaria ─────────────────────────────────────────────────
    {"name": "IBAN bancario",              "severity": "CRITICAL", "category": "PII · Cuenta bancaria",
     "regex": r"\b(ES|GB|DE|FR|IT|NL|BE|PT|AT|CH|SE|NO|DK|FI|PL|CZ|HU|RO|HR|BG|SK|SI|LT|LV|EE|MT|CY|LU|IE|GR|AD|MC|SM|VA|IS|LI)[0-9]{2}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{0,14}\b"},
    {"name": "BIC/SWIFT bancario",         "severity": "HIGH",     "category": "PII · Cuenta bancaria",
     "regex": r"\b[A-Z]{4}(ES|GB|DE|FR|IT|NL|BE|PT|US|CH|JP|CN|AU|CA|SG|HK|AE|SA|BR)[A-Z0-9]{2}([A-Z0-9]{3})?\b"},

    # ── PII — Identidad ───────────────────────────────────────────────────────
    {"name": "SSN EE.UU.",                 "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?!\d)"},
    {"name": "DNI español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!00000000)[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIE español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIF/CIF empresa española",   "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[ABCDEFGHJNPQRSUVW][0-9]{7}[0-9A-J](?!\w)"},
    {"name": "NUSS (Seg. Social español)", "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(0[1-9]|[1-4][0-9]|5[0-2])[/\-\s]?[0-9]{8}[/\-\s]?[0-9]{2}(?!\d)"},
    {"name": "NHS UK (número paciente)",   "severity": "CRITICAL", "category": "PII · Salud",
     "regex": r"(?<!\d)[0-9]{3}[\s\-][0-9]{3}[\s\-][0-9]{4}(?!\d)"},

    # ── PII — Contacto ────────────────────────────────────────────────────────
    {"name": "Email en contexto sensible", "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?i)(?:email|correo|mail|e-mail)\s*[:=]\s*['\"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['\"]?"},
    {"name": "Teléfono español",           "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)(?:\+34|0034)?[\s\-]?[6-9][0-9]{2}[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}(?!\d)"},
    {"name": "Teléfono internacional",     "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)\+(?!34)[1-9][0-9]{1,2}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{2,4}(?!\d)"},

    # ── PII — Cuenta bancaria ES ──────────────────────────────────────────────
    {"name": "Número de cuenta bancaria ES (CCC)", "severity": "HIGH", "category": "PII · Cuenta bancaria",
     "regex": r"(?<!\d)[0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{2}[\s\-][0-9]{10}(?!\d)"},

    # ── Patrones genéricos ────────────────────────────────────────────────────
    {"name": "Contraseña hardcodeada",     "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"},
    {"name": "API key genérica",           "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:api.?key|apikey|API_KEY)\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"},
    {"name": "Secret genérico",            "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:secret|SECRET)\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/]{16,})['\"]"},
    {"name": "Token genérico",             "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:token|TOKEN)\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/]{20,})['\"]"},
    {"name": "Private key genérica",       "severity": "HIGH",     "category": "Genérico",
     "regex": r"(?i)private.?key\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/=]{20,})['\"]"},
]

# Compilar todos los patrones una sola vez al importar
SECRET_PATTERNS = [
    {**p, "compiled": re.compile(p["regex"], re.MULTILINE)}
    for p in _RAW_PATTERNS
]

# ─────────────────────────────────────────────────────────────────────────────
# Configuración de descubrimiento
# ─────────────────────────────────────────────────────────────────────────────

EXCLUDE_DIRS: Set[str] = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "build", "dist", "target", ".gradle", ".idea", ".vscode",
    "vendor", "third_party", "external", "deps",
}

INCLUDE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".swift", ".c", ".cpp", ".h",
    ".cs", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".env", ".env.example", ".env.local", ".env.production", ".env.staging",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".xml", ".properties", ".gradle", ".tf", ".tfvars",
    ".Dockerfile", ".dockercompose",
    ".htaccess", ".htpasswd",
    ".pem", ".key", ".crt", ".cer",
    ".txt", ".md",
    ".hcl",
}

INCLUDE_FILENAMES: Set[str] = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Procfile", ".env", ".envrc",
    "webpack.config.js", "next.config.js", "vite.config.js",
    "settings.py", "config.py", "database.py",
    "application.properties", "application.yml",
    "secrets.yaml", "values.yaml",
}

BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".lock", ".sum",
}

# ─────────────────────────────────────────────────────────────────────────────
# Modelos de datos
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


@dataclass
class Finding:
    """Hallazgo de secreto en un fichero o en el historial git."""
    file:       str
    line_no:    int
    pattern:    str
    category:   str
    severity:   Severity
    preview:    str           # extracto censurado
    context:    List[str]     # líneas de contexto (±2)
    fingerprint: str          # hash del valor detectado (para dedup)
    # Campos opcionales para hallazgos de historial git
    git_commit: Optional[str] = None
    git_author: Optional[str] = None
    git_date:   Optional[str] = None
    allowlisted: bool = False
    delta_state: Optional[str] = None  # "new" | "recurring" cuando se usa --delta

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        if d.get("delta_state") is None:
            del d["delta_state"]
        return d
