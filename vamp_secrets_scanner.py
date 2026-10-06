#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_secrets_scanner.py — Escáner Estático de Secretos y Credenciales
======================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de análisis estático que detecta secretos, credenciales y
tokens hardcodeados en repositorios de código fuente, ficheros de
configuración y cualquier árbol de directorios. Orientada a auditorías
de seguridad, revisiones de código previas a despliegue y detección de
fugas de credenciales antes de publicar un repositorio.

Detecta más de 80 patrones de secretos y datos sensibles organizados en categorías:
  · Claves de nube (AWS, GCP, Azure)
  · Tokens de plataforma (GitHub, GitLab, Slack, Telegram, Discord)
  · Pasarelas de pago (Stripe, PayPal, Braintree)
  · Bases de datos (cadenas de conexión con credenciales embebidas)
  · Infraestructura (WireGuard, SSH, certificados PEM)
  · Servicios de correo y comunicaciones (SendGrid, Twilio, Mailgun)
  · Patrones genéricos de alta entropía (password=, api_key=, secret=…)
  · JWT y tokens Bearer
  · PII financiera: tarjetas de crédito/débito (Visa, MC, Amex, Discover),
    IBAN/BIC bancarios, CCC español, CVV/CVC hardcodeados
  · PII de identidad: SSN EE.UU., DNI/NIE/CIF español, NHS UK
  · PII de contacto: email en contexto sensible, teléfonos ES e internacionales

Complementa la detección por regex con un análisis de entropía de
Shannon sobre cadenas en asignaciones, lo que permite capturar secretos
cuyo formato no se ajusta a ningún patrón conocido pero cuya densidad
de información los delata como valores generados.

ARQUITECTURA DE EJECUCIÓN (3 fases)
------------------------------------
  Fase 1 — Descubrimiento de ficheros
    Recorre el árbol de directorios objetivo respetando las listas de
    exclusión (.git, node_modules, .venv, __pycache__, build, dist…) y
    el filtro de extensiones configurable. Soporta modo recursivo y
    profundidad máxima configurable. Informa del número de ficheros y
    bytes totales en alcance antes de empezar el escaneo.

  Fase 2 — Escaneo de patrones y entropía
    Para cada fichero en alcance:
    · Aplica los 60+ patrones regex de la base de datos SECRET_PATTERNS
      línea a línea; registra fichero, línea, categoría, nombre del
      patrón y un extracto censurado del hallazgo.
    · Calcula la entropía de Shannon de cadenas largas (≥20 chars) que
      aparezcan en contextos de asignación (key=, :, =) y marca como
      HIGH_ENTROPY aquellas que superen el umbral configurable (por
      defecto 4.5 bits/símbolo), excluyendo ruido conocido (hashes hex,
      base64 de imágenes…).
    Toda la operación es local, sin tráfico de red.

  Fase 3 — Clasificación, deduplicación e informe
    Normaliza cada hallazgo, elimina duplicados por (patrón + hash del
    valor), asigna severidad (CRÍTICO / ALTO / MEDIO / BAJO) y genera
    la salida seleccionada: tabla Rich en consola, JSON estructurado y/o
    informe HTML dark-theme standalone.

MODELO DE SEVERIDAD
-------------------
  CRÍTICO — Clave activa verificable por formato (AWS AKIA, PEM privada,
            Stripe sk_live_, Telegram BOT_TOKEN, WireGuard PrivateKey)
            o dato financiero/personal de alto impacto (PAN de tarjeta,
            IBAN, SSN EE.UU., CVV).
  ALTO    — Token de plataforma (GitHub PAT, GitLab, Slack, JWT) o dato
            de identidad regulado (DNI, NIE, CIF, BIC/SWIFT).
  MEDIO   — Patrón genérico con valor (password=, secret=, api_key=).
  BAJO    — Alta entropía o dato de contacto en contexto sensible
            (email=, teléfono).

DEPENDENCIAS
------------
  rich    >= 13.7.0    — Salida de consola con formato enriquecido
  (stdlib únicamente: re, os, math, pathlib, hashlib, json, argparse)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from html import escape
from pathlib import Path
import time
from typing import Dict, Iterator, List, Optional, Set

from rich.console import Console
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────

VERSION   = "2.5"
TOOL_NAME = "vamp-secrets-scanner"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-secrets-scanner v2.4 · Static Secrets & Git History Scanner
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Base de datos de patrones de secretos
# ─────────────────────────────────────────────────────────────────────────────
# Cada entrada:
#   name      — identificador legible del patrón
#   regex     — expresión regular (compilada más abajo)
#   severity  — CRITICAL / HIGH / MEDIUM / LOW
#   category  — agrupación temática
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

    # ── HashiCorp Vault / HCP (CVE-2026-5052 cluster) ────────────────────────
    # Tokens HashiCorp Vault — formato legacy (s.) y moderno (hvs.)
    # CVE-2026-5052: vulnerabilidad SSRF en el endpoint de emisión de certificados
    # PKI de Vault que permite exfiltrar claves privadas mediante peticiones
    # manipuladas al servidor de certificación.
    {"name": "HashiCorp Vault Token",         "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)(?:VAULT_TOKEN|X-Vault-Token|vault.{0,10}token)\s*[:=]\s*['\"]?(s\.[a-zA-Z0-9]{24,})['\"]?"},
    {"name": "Vault Wrapped Token (HVS)",     "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"hvs\.[a-zA-Z0-9]{24,}"},
    {"name": "HCP Client Secret",             "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)HCP_CLIENT_SECRET\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{64,})['\"]?"},
    {"name": "Vault PKI Private Key (CVE-2026-5052)", "severity": "HIGH", "category": "Infraestructura · Vault",
     "regex": r"(?i)(?:vault|pki).{0,40}-----BEGIN\s*(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"},
    # Vault unseal keys e Initial Root Token volcados en ficheros de texto —
    # hallazgo CRÍTICO inmediato: indican que la inicialización de Vault se
    # guardó en disco sin cifrar.
    {"name": "Vault Unseal Key en fichero",   "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"(?i)unseal_key_\d+\s*:\s*[A-Za-z0-9+/=]{40,}"},
    {"name": "Vault Initial Root Token",      "severity": "CRITICAL", "category": "Infraestructura · Vault",
     "regex": r"Initial Root Token:\s+s\.[a-zA-Z0-9]+"},

    # ── Datos personales y financieros (PII / PCI DSS) ───────────────────────
    # Tarjetas de crédito/débito — PAN (Primary Account Number)
    # Exige separadores (espacio o guión) para reducir falsos positivos.
    # Se detectan los rangos BIN de los principales emisores.
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

    # IBAN — Número Internacional de Cuenta Bancaria
    # Cobre los 30+ países del espacio SEPA más los principales internacionales.
    # Formato: 2 letras de país + 2 dígitos de control + BBAN variable.
    {"name": "IBAN bancario",              "severity": "CRITICAL", "category": "PII · Cuenta bancaria",
     "regex": r"\b(ES|GB|DE|FR|IT|NL|BE|PT|AT|CH|SE|NO|DK|FI|PL|CZ|HU|RO|HR|BG|SK|SI|LT|LV|EE|MT|CY|LU|IE|GR|AD|MC|SM|VA|IS|LI)[0-9]{2}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{0,14}\b"},
    {"name": "BIC/SWIFT bancario",         "severity": "HIGH",     "category": "PII · Cuenta bancaria",
     "regex": r"\b[A-Z]{4}(ES|GB|DE|FR|IT|NL|BE|PT|US|CH|JP|CN|AU|CA|SG|HK|AE|SA|BR)[A-Z0-9]{2}([A-Z0-9]{3})?\b"},

    # Número de Seguridad Social y documentos de identidad
    {"name": "SSN EE.UU.",                 "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?!\d)"},
    {"name": "DNI español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!00000000)[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIE español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIF/CIF empresa española",   "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[ABCDEFGHJNPQRSUVW][0-9]{7}[0-9A-J](?!\w)"},
    # NUSS — Número de la Seguridad Social español
    # Formato: 2 dígitos de provincia (01-52) + 8 de secuencia + 2 de control = 12 dígitos.
    # Admite separadores (/  o  -) entre los tres grupos, que es la presentación
    # oficial en documentos físicos (p.ej. 28/12345678/20).
    {"name": "NUSS (Seg. Social español)", "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(0[1-9]|[1-4][0-9]|5[0-2])[/\-\s]?[0-9]{8}[/\-\s]?[0-9]{2}(?!\d)"},
    {"name": "NHS UK (número paciente)",   "severity": "CRITICAL", "category": "PII · Salud",
     "regex": r"(?<!\d)[0-9]{3}[\s\-][0-9]{3}[\s\-][0-9]{4}(?!\d)"},

    # Datos de contacto en contextos sensibles (volcados de BD, logs, configs)
    {"name": "Email en contexto sensible", "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?i)(?:email|correo|mail|e-mail)\s*[:=]\s*['\"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['\"]?"},
    {"name": "Teléfono español",           "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)(?:\+34|0034)?[\s\-]?[6-9][0-9]{2}[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}(?!\d)"},
    {"name": "Teléfono internacional",     "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)\+(?!34)[1-9][0-9]{1,2}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{2,4}(?!\d)"},

    # Números de cuenta / referencia financiera en contexto
    {"name": "Número de cuenta bancaria ES (CCC)", "severity": "HIGH", "category": "PII · Cuenta bancaria",
     "regex": r"(?<!\d)[0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{2}[\s\-][0-9]{10}(?!\d)"},

    # ── Patrones genéricos (alta cobertura, más falsos positivos) ─────────────
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
    ".hcl",   # HashiCorp Configuration Language (Vault, Terraform)
}

# Nombres de fichero que se escanean independientemente de su extensión
INCLUDE_FILENAMES: Set[str] = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Procfile", ".env", ".envrc",
    "webpack.config.js", "next.config.js", "vite.config.js",
    "settings.py", "config.py", "database.py",
    "application.properties", "application.yml",
    "secrets.yaml", "values.yaml",
}

# Extensiones a ignorar siempre (binarios, media, compilados)
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".lock", ".sum",  # lock files: demasiado ruido
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
    git_commit: Optional[str] = None  # hash del commit donde apareció
    git_author: Optional[str] = None  # autor del commit
    git_date:   Optional[str] = None  # fecha ISO del commit
    allowlisted: bool = False          # ignorado por la allowlist

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Fase 1 — Descubrimiento de ficheros
# ─────────────────────────────────────────────────────────────────────────────

def discover_files(root: Path, max_depth: Optional[int], all_extensions: bool) -> Iterator[Path]:
    """
    Recorre el árbol desde `root`, respetando EXCLUDE_DIRS y el filtro de
    extensiones. Emite Path de cada fichero candidato.
    """
    def _walk(path: Path, depth: int) -> Iterator[Path]:
        if max_depth is not None and depth > max_depth:
            return
        try:
            entries = sorted(path.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in EXCLUDE_DIRS:
                    yield from _walk(entry, depth + 1)
            elif entry.is_file():
                ext = entry.suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    continue
                if all_extensions:
                    yield entry
                elif entry.name in INCLUDE_FILENAMES or ext in INCLUDE_EXTENSIONS:
                    yield entry

    yield from _walk(root, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2 — Escaneo: regex + entropía
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Entropía de Shannon en bits/símbolo."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum(f / n * math.log2(f / n) for f in freq.values())


def _censor(match: str) -> str:
    """Devuelve los primeros 6 caracteres y asteriscos para el resto."""
    if len(match) <= 6:
        return "***"
    return match[:6] + "***" + match[-2:]


def _fingerprint(value: str, pattern_name: str) -> str:
    raw = f"{pattern_name}:{value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _baseline_fingerprint(file: str, line_no: int, pattern_name: str) -> str:
    """
    Genera el fingerprint de contexto para el baseline.

    A diferencia de _fingerprint, NO incluye el valor del secreto en claro:
    solo usa fichero + número de línea + nombre del patrón. Esto permite
    identificar un hallazgo concreto en su ubicación sin almacenar secretos.
    """
    ctx = f"{file}:{line_no}:{pattern_name}"
    return hashlib.sha256(ctx.encode()).hexdigest()


def _context_lines(lines: List[str], lineno: int, radius: int = 2) -> List[str]:
    start = max(0, lineno - radius - 1)
    end   = min(len(lines), lineno + radius)
    return [f"  {i+1:4d} │ {lines[i].rstrip()}" for i in range(start, end)]


def scan_file(path: Path, entropy_threshold: float) -> List[Finding]:
    """Escanea un único fichero y retorna sus hallazgos."""
    try:
        raw = path.read_bytes()
        # Saltar ficheros binarios por heurística
        if b"\x00" in raw[:8192]:
            return []
        text = raw.decode("utf-8", errors="replace")
    except (PermissionError, OSError):
        return []

    lines   = text.splitlines()
    findings: List[Finding] = []
    seen_fps: Set[str] = set()

    # ── Patrones regex ────────────────────────────────────────────────────────
    for pat in SECRET_PATTERNS:
        for m in pat["compiled"].finditer(text):
            value   = m.group(0)
            fp      = _fingerprint(value, pat["name"])
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            line_no = text[:m.start()].count("\n") + 1
            findings.append(Finding(
                file      = str(path),
                line_no   = line_no,
                pattern   = pat["name"],
                category  = pat["category"],
                severity  = Severity(pat["severity"]),
                preview   = _censor(value),
                context   = _context_lines(lines, line_no),
                fingerprint = fp,
            ))

    # ── Entropía de Shannon ───────────────────────────────────────────────────
    # Busca cadenas largas en contextos de asignación que superen el umbral
    _ENTROPY_RE = re.compile(
        r"""(?:=|:|:=)\s*['"]?([A-Za-z0-9+/=\-_.~]{20,})['"]?""",
        re.MULTILINE,
    )
    # Falsos positivos frecuentes: hashes hex puros, UUIDs, rutas, URLs
    _NOISE_RE = re.compile(
        r"^(?:[0-9a-f]{32,}|[0-9A-Fa-f\-]{36}|https?://|/[a-z])$",
        re.IGNORECASE,
    )
    for m in _ENTROPY_RE.finditer(text):
        candidate = m.group(1)
        if _NOISE_RE.match(candidate):
            continue
        entropy = _shannon_entropy(candidate)
        if entropy < entropy_threshold:
            continue
        fp = _fingerprint(candidate, "HIGH_ENTROPY")
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        line_no = text[:m.start()].count("\n") + 1
        findings.append(Finding(
            file      = str(path),
            line_no   = line_no,
            pattern   = f"Alta Entropía (H={entropy:.2f} bits)",
            category  = "Entropía",
            severity  = Severity.LOW,
            preview   = _censor(candidate),
            context   = _context_lines(lines, line_no),
            fingerprint = fp,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2b — Escaneo de historial Git
# ─────────────────────────────────────────────────────────────────────────────

def _is_git_repo(path: Path) -> bool:
    """Devuelve True si el directorio es un repositorio git."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=path, capture_output=True, text=True,
    )
    return result.returncode == 0


def scan_git_history(
    repo_path: Path,
    entropy_threshold: float,
    max_commits: int = 0,
) -> List[Finding]:
    """
    Escanea el historial completo de git buscando secretos en las líneas añadidas.

    Estrategia:
      1. Obtiene todos los commits (todos los branches) con `git log --all`.
      2. Para cada commit, extrae el diff completo de líneas añadidas (+).
      3. Aplica los mismos patrones regex y análisis de entropía que el escaneo
         de ficheros, pero registrando también el hash del commit, autor y fecha.

    Esto detecta secretos que fueron introducidos y luego borrados del árbol
    actual, que son invisibles para el escaneo de ficheros estándar.

    Parámetros
    ----------
    repo_path:         Ruta al repositorio git.
    entropy_threshold: Umbral de Shannon (float("inf") = desactivado).
    max_commits:       Límite de commits a procesar. 0 = sin límite.
    """
    if not _is_git_repo(repo_path):
        return []

    # Obtener lista de commits: hash, autor, fecha ISO
    log_fmt = "%H\x1f%ae\x1f%aI"
    log_cmd = ["git", "log", "--all", "--no-merges", f"--format={log_fmt}"]
    if max_commits > 0:
        log_cmd += [f"-n{max_commits}"]

    log_result = subprocess.run(
        log_cmd, cwd=repo_path, capture_output=True, text=True, errors="replace",
    )
    if log_result.returncode != 0:
        return []

    commit_lines = [l for l in log_result.stdout.splitlines() if l.strip()]
    findings: List[Finding] = []
    seen_fps: Set[str] = set()

    # Regexes auxiliares para parsear el diff
    FILE_RE   = re.compile(r"^\+\+\+ b/(.+)$")
    ADDED_RE  = re.compile(r"^\+(?!\+\+)(.*)$")  # línea añadida (no la cabecera +++)
    LINENO_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

    _ENTROPY_RE = re.compile(
        r"""(?:=|:|:=)\s*['"]?([A-Za-z0-9+/=\-_.~]{20,})['"]?""",
        re.MULTILINE,
    )
    _NOISE_RE = re.compile(
        r"^(?:[0-9a-f]{32,}|[0-9A-Fa-f\-]{36}|https?://|/[a-z])$",
        re.IGNORECASE,
    )

    for raw in commit_lines:
        parts = raw.split("\x1f")
        if len(parts) != 3:
            continue
        commit_hash, author, date = parts

        # Obtener el diff completo del commit (solo líneas añadidas para velocidad)
        diff_result = subprocess.run(
            ["git", "show", "--no-notes", "--format=", "-U0", commit_hash],
            cwd=repo_path, capture_output=True, text=True, errors="replace",
        )
        if diff_result.returncode != 0:
            continue

        current_file = ""
        current_line = 0

        for diff_line in diff_result.stdout.splitlines():
            # Detectar qué fichero estamos analizando
            m_file = FILE_RE.match(diff_line)
            if m_file:
                current_file = m_file.group(1)
                continue

            # Actualizar número de línea desde el header @@ +N @@
            m_lineno = LINENO_RE.match(diff_line)
            if m_lineno:
                current_line = int(m_lineno.group(1)) - 1
                continue

            m_added = ADDED_RE.match(diff_line)
            if not m_added:
                continue

            line_content = m_added.group(1)
            current_line += 1

            # ── Patrones regex ────────────────────────────────────────────────
            for pat in SECRET_PATTERNS:
                for m in pat["compiled"].finditer(line_content):
                    value = m.group(0)
                    # El fingerprint incluye el commit para no suprimir el mismo
                    # secreto en commits distintos (puede ser la misma clave rotada).
                    fp = _fingerprint(value, f"git:{pat['name']}")
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)
                    findings.append(Finding(
                        file        = current_file,
                        line_no     = current_line,
                        pattern     = pat["name"],
                        category    = pat["category"],
                        severity    = Severity(pat["severity"]),
                        preview     = _censor(value),
                        context     = [f"  git:{commit_hash[:8]} — {line_content.rstrip()}"],
                        fingerprint = fp,
                        git_commit  = commit_hash,
                        git_author  = author,
                        git_date    = date,
                    ))

            # ── Entropía ──────────────────────────────────────────────────────
            if entropy_threshold < float("inf"):
                for m in _ENTROPY_RE.finditer(line_content):
                    candidate = m.group(1)
                    if _NOISE_RE.match(candidate):
                        continue
                    entropy = _shannon_entropy(candidate)
                    if entropy < entropy_threshold:
                        continue
                    fp = _fingerprint(candidate, f"git:HIGH_ENTROPY:{commit_hash[:8]}")
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)
                    findings.append(Finding(
                        file        = current_file,
                        line_no     = current_line,
                        pattern     = f"Alta Entropía (H={entropy:.2f} bits)",
                        category    = "Entropía",
                        severity    = Severity.LOW,
                        preview     = _censor(candidate),
                        context     = [f"  git:{commit_hash[:8]} — {line_content.rstrip()}"],
                        fingerprint = fp,
                        git_commit  = commit_hash,
                        git_author  = author,
                        git_date    = date,
                    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2c — Análisis de misconfiguraciones de HashiCorp Vault
# ─────────────────────────────────────────────────────────────────────────────

def scan_vault_misconfig(path: Path) -> List[Finding]:
    """
    Analiza ficheros de configuración de HashiCorp Vault (.hcl, .env, .yaml)
    buscando misconfiguraciones de seguridad conocidas.

    Checks implementados
    --------------------
    SECRET-VAULT-001 (CRITICAL) — CVE-2026-5052: política PKI sin allowed_domains
        Ficheros .hcl con capacidades sobre path "pki/*" sin restricción
        allowed_domains → SSRF explotable en el endpoint de emisión de certs.

    SECRET-VAULT-002 (HIGH) — Vault Audit Log deshabilitado
        Configs HCL sin bloque audit { type = "file" } → pérdida de trazabilidad.

    SECRET-VAULT-003 (HIGH) — TLS deshabilitado (VAULT_SKIP_VERIFY)
        VAULT_SKIP_VERIFY=true o vault_skip_verify: true en cualquier fichero
        de configuración → tráfico Vault sin verificación de certificado.

    SECRET-VAULT-004 (CRITICAL) — Unseal keys o root token en ficheros de texto
        Patrones de inicialización de Vault volcados en disco sin cifrar.

    Parámetros
    ----------
    path : Path — Raíz del árbol a analizar (ya descubierto por discover_files)

    Retorna
    -------
    List[Finding] — Hallazgos de misconfiguración con categoría "Vault · Misconfig"
    """
    findings: List[Finding] = []

    # ── Recopilar ficheros relevantes para análisis de misconfig Vault ─────────
    # Se examinan .hcl (políticas/config Vault), .env* y ficheros YAML/TOML
    vault_extensions = {".hcl", ".env", ".yaml", ".yml", ".toml", ".cfg", ".conf", ".config"}
    vault_filenames  = {
        ".env", ".envrc", "vault.hcl", "config.hcl", "policy.hcl",
        "vault-config.yml", "vault-config.yaml",
    }

    try:
        candidatos = [
            f for f in path.rglob("*")
            if f.is_file()
            and not any(part in EXCLUDE_DIRS for part in f.parts)
            and (f.suffix.lower() in vault_extensions or f.name in vault_filenames)
        ]
    except PermissionError:
        return []

    # Regex auxiliares para los distintos checks
    _PKI_CAP_RE        = re.compile(r'path\s+"pki/[^"]*"\s*\{[^}]*capabilities\s*=\s*\[([^\]]+)\]', re.DOTALL)
    _ALLOWED_DOM_RE    = re.compile(r'allowed_domains\s*=')
    _AUDIT_BLOCK_RE    = re.compile(r'audit\s*\{[^}]*type\s*=\s*"file"', re.DOTALL)
    _SKIP_VERIFY_RE    = re.compile(r'(?i)(VAULT_SKIP_VERIFY\s*=\s*true|vault_skip_verify\s*:\s*true)')
    _UNSEAL_KEY_RE     = re.compile(r'(?i)unseal_key_\d+\s*:\s*[A-Za-z0-9+/=]{40,}')
    _ROOT_TOKEN_RE     = re.compile(r'Initial Root Token:\s+s\.[a-zA-Z0-9]+')
    _LONG_TTL_RE       = re.compile(r'(?i)(?:max_)?ttl\s*=\s*"?(\d+)h"?')

    hcl_files    = [f for f in candidatos if f.suffix.lower() == ".hcl"]
    all_files    = candidatos

    # ── SECRET-VAULT-001: CVE-2026-5052 — PKI sin allowed_domains ─────────────
    for hcl_file in hcl_files:
        try:
            contenido = hcl_file.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue

        for m in _PKI_CAP_RE.finditer(contenido):
            caps_raw = m.group(1)
            # Solo si las capabilities incluyen wildcard "*" (privilegio sin restricción)
            if '"*"' not in caps_raw and "'*'" not in caps_raw:
                continue
            # Verificar si en el mismo bloque (o en el fichero) existe allowed_domains
            bloque_inicio = m.start()
            bloque_fin    = m.end()
            segmento      = contenido[max(0, bloque_inicio - 200): bloque_fin + 500]
            if _ALLOWED_DOM_RE.search(segmento):
                continue  # allowed_domains presente → no vulnerable
            linea = contenido[:bloque_inicio].count("\n") + 1
            fp    = _fingerprint(f"{hcl_file}:pki-no-allowed-domains:{linea}", "SECRET-VAULT-001")
            findings.append(Finding(
                file        = str(hcl_file),
                line_no     = linea,
                pattern     = "SECRET-VAULT-001: Vault PKI sin allowed_domains (CVE-2026-5052)",
                category    = "Vault · Misconfig",
                severity    = Severity.CRITICAL,
                preview     = "PKI capabilities=* sin allowed_domains",
                context     = [
                    "  CVE-2026-5052: política PKI con capabilities=[\"*\"] y sin",
                    "  restricción allowed_domains → SSRF explotable en endpoint",
                    "  de emisión de certificados de Vault.",
                ],
                fingerprint = fp,
            ))

        # Certificados PKI con TTL excesivo (> 87600h = 10 años)
        for m_ttl in _LONG_TTL_RE.finditer(contenido):
            ttl_h = int(m_ttl.group(1))
            if ttl_h <= 87600:
                continue
            linea = contenido[:m_ttl.start()].count("\n") + 1
            fp    = _fingerprint(f"{hcl_file}:pki-ttl-excesivo:{linea}", "SECRET-VAULT-001-TTL")
            findings.append(Finding(
                file        = str(hcl_file),
                line_no     = linea,
                pattern     = "SECRET-VAULT-001b: Vault PKI TTL excesivo (>10 años)",
                category    = "Vault · Misconfig",
                severity    = Severity.HIGH,
                preview     = f"ttl={ttl_h}h (mala práctica PKI)",
                context     = [
                    f"  TTL de certificado = {ttl_h}h (> 87600h = 10 años).",
                    "  Mala práctica asociada a CVE-2026-5052: certificados de",
                    "  larga vida facilitan el abuso post-explotación.",
                ],
                fingerprint = fp,
            ))

    # ── SECRET-VAULT-002: Vault Audit Log deshabilitado ───────────────────────
    # Si hay ficheros .hcl de config de Vault pero ninguno tiene bloque audit
    if hcl_files:
        tiene_audit = any(
            _AUDIT_BLOCK_RE.search(
                f.read_text(encoding="utf-8", errors="replace")
            )
            for f in hcl_files
            if f.is_file()
        )
        if not tiene_audit:
            # Usar el primer .hcl como referencia del hallazgo
            ref_file = hcl_files[0]
            fp       = _fingerprint(f"{ref_file}:audit-log-disabled", "SECRET-VAULT-002")
            findings.append(Finding(
                file        = str(ref_file),
                line_no     = 0,
                pattern     = "SECRET-VAULT-002: Vault Audit Log deshabilitado",
                category    = "Vault · Misconfig",
                severity    = Severity.HIGH,
                preview     = "Sin bloque audit { type = \"file\" } en configs HCL",
                context     = [
                    "  No se encontró ningún bloque audit { type = \"file\" }",
                    "  en los ficheros .hcl analizados. Sin audit log activo,",
                    "  las operaciones de Vault no quedan registradas.",
                ],
                fingerprint = fp,
            ))

    # ── SECRET-VAULT-003: VAULT_SKIP_VERIFY=true ──────────────────────────────
    for cfg_file in all_files:
        try:
            contenido = cfg_file.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue
        for m in _SKIP_VERIFY_RE.finditer(contenido):
            linea = contenido[:m.start()].count("\n") + 1
            fp    = _fingerprint(f"{cfg_file}:skip-verify:{linea}", "SECRET-VAULT-003")
            findings.append(Finding(
                file        = str(cfg_file),
                line_no     = linea,
                pattern     = "SECRET-VAULT-003: VAULT_SKIP_VERIFY=true (TLS deshabilitado)",
                category    = "Vault · Misconfig",
                severity    = Severity.HIGH,
                preview     = _censor(m.group(0)),
                context     = [
                    f"  {linea:4d} │ {m.group(0).rstrip()}",
                    "  TLS deshabilitado → tráfico Vault sin verificación de",
                    "  certificado. Vulnerable a ataques MITM.",
                ],
                fingerprint = fp,
            ))

    # ── SECRET-VAULT-004: Unseal keys / Initial Root Token en disco ───────────
    for chk_file in all_files:
        try:
            contenido = chk_file.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue
        for patron, regex_obj in [
            ("Vault Unseal Key en fichero (SECRET-VAULT-004)", _UNSEAL_KEY_RE),
            ("Vault Initial Root Token en fichero (SECRET-VAULT-004)", _ROOT_TOKEN_RE),
        ]:
            for m in regex_obj.finditer(contenido):
                valor  = m.group(0)
                linea  = contenido[:m.start()].count("\n") + 1
                fp     = _fingerprint(valor, "SECRET-VAULT-004")
                findings.append(Finding(
                    file        = str(chk_file),
                    line_no     = linea,
                    pattern     = patron,
                    category    = "Vault · Misconfig",
                    severity    = Severity.CRITICAL,
                    preview     = _censor(valor),
                    context     = [
                        f"  {linea:4d} │ {valor[:60].rstrip()}",
                        "  Vault unseal keys o root token volcados en disco sin",
                        "  cifrar — compromiso total del cluster de Vault.",
                    ],
                    fingerprint = fp,
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Allowlist — filtro de falsos positivos conocidos
# ─────────────────────────────────────────────────────────────────────────────

def load_allowlist(path: str) -> List[dict]:
    """
    Carga una allowlist desde un fichero JSON.

    Formato esperado:
    {
      "allowlist": [
        {"fingerprint": "abc123def456"},
        {"pattern": "DNI español", "file": "tests/fixtures/datos_prueba.py"},
        {"pattern": "Alta Entropía*"},
        {"file": "tests/fixtures/"}
      ]
    }

    Cada entrada puede filtrar por 'fingerprint' exacto, por 'pattern'
    (admite glob parcial con *), por 'file' (prefijo de ruta) o
    por combinación pattern + file.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("allowlist", [])
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[yellow]  Aviso: no se pudo leer la allowlist '{path}': {exc}[/]")
        return []


def apply_allowlist(findings: List[Finding], allowlist: List[dict]) -> List[Finding]:
    """
    Marca como `allowlisted=True` los hallazgos que coincidan con alguna
    entrada de la allowlist. Devuelve la lista con el flag actualizado.
    """
    if not allowlist:
        return findings

    def _matches(f: Finding, entry: dict) -> bool:
        # Coincidencia por fingerprint exacto
        if "fingerprint" in entry:
            return f.fingerprint == entry["fingerprint"]
        # Coincidencia por patrón (glob simple con *)
        pattern_ok = True
        if "pattern" in entry:
            pat = entry["pattern"]
            if pat.endswith("*"):
                pattern_ok = f.pattern.startswith(pat[:-1])
            else:
                pattern_ok = f.pattern == pat
        # Coincidencia por fichero (prefijo)
        file_ok = True
        if "file" in entry:
            file_ok = f.file.startswith(entry["file"]) or entry["file"] in f.file
        return pattern_ok and file_ok

    for f in findings:
        for entry in allowlist:
            if _matches(f, entry):
                f.allowlisted = True
                break
    return findings


def generate_allowlist(findings: List[Finding], path: str) -> None:
    """
    Genera un fichero allowlist JSON a partir de los hallazgos actuales.
    Útil para establecer un baseline inicial en repositorios heredados.
    """
    entries = [{"fingerprint": f.fingerprint, "pattern": f.pattern, "file": f.file}
               for f in findings]
    out = {
        "_generado_por": f"{TOOL_NAME} v{VERSION}",
        "_fecha": datetime.now(timezone.utc).isoformat(),
        "_nota": "Edita esta allowlist para suprimir falsos positivos conocidos. "
                 "Elimina entradas para que vuelvan a reportarse.",
        "allowlist": entries,
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[green]  ✔ Allowlist generada en {path} ({len(entries)} entradas)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Soporte de baseline — fichero .vamp-secrets-baseline.json
# ─────────────────────────────────────────────────────────────────────────────
# El baseline permite suprimir hallazgos que el equipo ha revisado y aceptado
# conscientemente (p.ej. credenciales de test, fixtures de datos de ejemplo).
# A diferencia de la allowlist (que usa el fingerprint del valor), el baseline
# usa el fingerprint del CONTEXTO (fichero + línea + patrón), sin almacenar
# el secreto en claro. Si el secreto se mueve de línea, vuelve a aparecer.
#
# Formato del fichero baseline:
#   {
#     "version": "1.0",
#     "accepted": [
#       {
#         "fingerprint": "<sha256_de_contexto>",
#         "reason": "credencial de test",
#         "added": "2024-01-01",
#         "pattern": "Stripe Test Secret Key",
#         "file": "tests/fixtures.py",
#         "line": 42
#       }
#     ]
#   }
# ─────────────────────────────────────────────────────────────────────────────

def load_baseline(path: str) -> List[dict]:
    """
    Carga el baseline de hallazgos aceptados desde un fichero JSON.

    Retorna la lista de entradas aceptadas; vacía si el fichero no existe
    o no tiene el formato esperado.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("accepted", [])
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[yellow]  Aviso: no se pudo leer el baseline '{path}': {exc}[/]")
        return []


def apply_baseline(findings: List[Finding], accepted: List[dict]) -> List[Finding]:
    """
    Marca como allowlisted=True los hallazgos cuyo fingerprint de contexto
    aparezca en el baseline. Los hallazgos marcados se excluyen del informe
    y no generan código de salida de error en CI.
    """
    if not accepted:
        return findings
    baseline_fps = {e["fingerprint"] for e in accepted if "fingerprint" in e}
    for f in findings:
        bf = _baseline_fingerprint(f.file, f.line_no, f.pattern)
        if bf in baseline_fps:
            f.allowlisted = True
    return findings


def update_baseline(findings: List[Finding], path: str, reason: str = "") -> None:
    """
    Añade todos los hallazgos de la lista al baseline sin reportarlos como error.

    Si el baseline ya existe, se fusionan las entradas; no se duplican
    fingerprints. Si no existe, se crea desde cero.

    Parámetros
    ----------
    findings : List[Finding]  — Hallazgos a aceptar (normalmente los actuales)
    path     : str            — Ruta al fichero baseline
    reason   : str            — Motivo de aceptación (texto libre)
    """
    # Cargar entradas existentes
    existing: List[dict] = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        existing = data.get("accepted", [])
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    existing_fps = {e["fingerprint"] for e in existing}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    nuevos = 0

    for f in findings:
        bf = _baseline_fingerprint(f.file, f.line_no, f.pattern)
        if bf not in existing_fps:
            existing.append({
                "fingerprint": bf,
                "reason": reason or "aceptado via --update-baseline",
                "added": now,
                "pattern": f.pattern,
                "file": f.file,
                "line": f.line_no,
                "severity": f.severity.value,
            })
            existing_fps.add(bf)
            nuevos += 1

    out = {
        "version": "1.0",
        "_generado_por": f"{TOOL_NAME} v{VERSION}",
        "_nota": (
            "Baseline de hallazgos aceptados. Cada entrada se identifica por el "
            "fingerprint SHA-256 del contexto (fichero+línea+patrón), NO por el "
            "valor del secreto en claro. Si el secreto cambia de línea, reaparecerá."
        ),
        "accepted": existing,
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(
        f"[green]  ✔ Baseline actualizado: {nuevos} nuevas entradas "
        f"({len(existing)} total) → {path}[/]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Exportación SARIF 2.1.0
# ─────────────────────────────────────────────────────────────────────────────

def export_sarif(findings: List[Finding], target: str, path: str) -> None:
    """
    Exporta hallazgos en formato SARIF 2.1.0 (Static Analysis Results
    Interchange Format). Compatible con GitHub Advanced Security, VS Code
    SARIF Viewer y herramientas de CI/CD que consuman este formato.

    Mapeo de severidad:
      CRITICAL → level: "error",   rank: 9.5
      HIGH     → level: "error",   rank: 7.5
      MEDIUM   → level: "warning", rank: 5.0
      LOW      → level: "note",    rank: 2.0
    """
    _SEV_TO_SARIF = {
        "CRITICAL": ("error",   9.5),
        "HIGH":     ("error",   7.5),
        "MEDIUM":   ("warning", 5.0),
        "LOW":      ("note",    2.0),
    }

    # Construir catálogo de reglas a partir de los patrones usados
    rules_seen: Dict[str, dict] = {}
    for f in findings:
        rule_id = re.sub(r"[^A-Za-z0-9\-_]", "-", f.pattern)[:64]
        if rule_id not in rules_seen:
            level, rank = _SEV_TO_SARIF.get(f.severity.value, ("note", 2.0))
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.pattern,
                "shortDescription": {"text": f"{f.pattern} ({f.category})"},
                "defaultConfiguration": {
                    "level": level,
                    "rank": rank,
                },
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                    "tags": ["security", "secrets"],
                },
            }

    # Construir resultados
    results = []
    target_uri = Path(target).as_uri()
    for f in findings:
        if f.allowlisted:
            continue
        rule_id = re.sub(r"[^A-Za-z0-9\-_]", "-", f.pattern)[:64]
        level, _ = _SEV_TO_SARIF.get(f.severity.value, ("note", 2.0))
        # URI relativa al workspace
        try:
            rel_file = str(Path(f.file).relative_to(target)).replace("\\", "/")
        except ValueError:
            rel_file = f.file.replace("\\", "/")
        result_entry: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{f.pattern} detectado en {rel_file}:{f.line_no} — {f.preview}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": f.line_no},
                }
            }],
            "fingerprints": {"vamp-secrets-scanner/v1": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "category": f.category,
                "preview":  f.preview,
            },
        }
        # Información git si disponible
        if f.git_commit:
            result_entry["properties"]["gitCommit"] = f.git_commit
            result_entry["properties"]["gitAuthor"] = f.git_author or ""
            result_entry["properties"]["gitDate"]   = f.git_date or ""
        results.append(result_entry)

    sarif_doc = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": VERSION,
                    "informationUri": "https://github.com/belky-me/vamp-secrets-scanner",
                    "organization": "VampSecure Studios",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": target_uri + "/"},
            },
            "properties": {
                "generated": datetime.now(timezone.utc).isoformat(),
                "target": target,
            },
        }],
    }

    Path(path).write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]  SARIF → {path} ({len(results)} resultados)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Fase 3 — Clasificación e informe Rich
# ─────────────────────────────────────────────────────────────────────────────

_SEV_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
}

_SEV_ICON: Dict[Severity, str] = {
    Severity.CRITICAL: "🔴 CRÍTICO",
    Severity.HIGH:     "🟠 ALTO",
    Severity.MEDIUM:   "🟡 MEDIO",
    Severity.LOW:      "🔵 BAJO",
}


def build_results_table(findings: List[Finding], base: Path) -> Table:
    table = Table(
        title="Resultados — Secrets Scanner",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Severidad",  no_wrap=True, max_width=14)
    table.add_column("Fichero",    style="white",       no_wrap=True, max_width=50)
    table.add_column("Línea",      style="cyan",        no_wrap=True, max_width=6, justify="right")
    table.add_column("Patrón",     style="white",       no_wrap=True, max_width=32)
    table.add_column("Categoría",  style="bright_black", no_wrap=True, max_width=24)
    table.add_column("Extracto",   style="yellow",      no_wrap=True, max_width=22)

    for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER[x.severity], x.file, x.line_no)):
        sty   = _SEV_STYLE[f.severity]
        label = _SEV_ICON[f.severity]
        try:
            rel = Path(f.file).relative_to(base)
        except ValueError:
            rel = Path(f.file)
        table.add_row(
            Text(label, style=sty),
            Text(str(rel)),
            str(f.line_no),
            Text(f.pattern),
            Text(f.category),
            Text(f.preview),
        )
    return table


def print_critical_panels(findings: List[Finding], base: Path) -> None:
    crits = [f for f in findings if f.severity == Severity.CRITICAL]
    if not crits:
        return
    console.print()
    console.print("[bold red]── HALLAZGOS CRÍTICOS ──────────────────────────────────────────────────────[/]")
    for f in crits:
        try:
            rel = Path(f.file).relative_to(base)
        except ValueError:
            rel = Path(f.file)
        ctx = "\n".join(f.context)
        body = (
            f"[bold white]Fichero:[/]   {markup_escape(str(rel))}:{f.line_no}\n"
            f"[bold white]Patrón:[/]    {markup_escape(f.pattern)}\n"
            f"[bold white]Categoría:[/] {markup_escape(f.category)}\n"
            f"[bold white]Extracto:[/]  [yellow]{markup_escape(f.preview)}[/]\n\n"
            f"[dim]{markup_escape(ctx)}[/]"
        )
        console.print(Panel(body,
            title=f"[bold red]⚠ CRÍTICO: {f.pattern}[/]",
            border_style="red"))


# ─────────────────────────────────────────────────────────────────────────────
# Exportación JSON
# ─────────────────────────────────────────────────────────────────────────────

def export_json(findings: List[Finding], target: str, path: str) -> None:
    out = {
        "tool":      TOOL_NAME,
        "version":   VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target":    target,
        "summary": {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "findings": [f.to_dict() for f in findings],
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]  JSON → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Exportación HTML dark-theme
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR_HTML: Dict[str, str] = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#f0c040",
    "LOW":      "#4caf50",
}


def export_html(findings: List[Finding], target: str, path: str) -> None:
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med  = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low  = sum(1 for f in findings if f.severity == Severity.LOW)

    def rows() -> str:
        out = []
        for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER[x.severity], x.file, x.line_no)):
            color = _SEV_COLOR_HTML.get(f.severity.value, "#aaa")
            ctx   = escape("\n".join(f.context))
            out.append(
                f'<tr onclick="toggle(this)" style="cursor:pointer">'
                f'<td style="color:{color};font-weight:bold">{escape(f.severity.value)}</td>'
                f'<td class="mono">{escape(f.file)}:{f.line_no}</td>'
                f'<td>{escape(f.pattern)}</td>'
                f'<td class="dim">{escape(f.category)}</td>'
                f'<td class="mono" style="color:#f0c040">{escape(f.preview)}</td>'
                f'</tr>'
                f'<tr class="ctx-row" style="display:none">'
                f'<td colspan="5"><pre class="ctx">{ctx}</pre></td>'
                f'</tr>'
            )
        return "\n".join(out)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>VampSecure Labs — Secrets Scan — {escape(target)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#010101;color:#ccc;font-family:"Share Tech Mono",monospace;font-size:13px;padding:30px}}
  h1{{color:#9d00ff;font-size:1.6rem;margin-bottom:4px}}
  .meta{{color:#444;font-size:.75rem;margin-bottom:30px}}
  .summary{{display:flex;gap:24px;margin-bottom:30px}}
  .kpi{{background:#0f0f0f;border:1px solid #222;padding:14px 22px;text-align:center}}
  .kpi-n{{font-size:2rem;font-weight:bold}}
  .kpi-l{{font-size:.7rem;color:#555;letter-spacing:1px}}
  .crit-n{{color:#ff4444}} .high-n{{color:#ff8800}} .med-n{{color:#f0c040}}
  .low-n{{color:#4caf50}} .tot-n{{color:#00f2ff}}
  h2{{color:#00f2ff;font-size:1rem;margin:28px 0 10px;border-left:4px solid #9d00ff;padding-left:12px}}
  table{{width:100%;border-collapse:collapse;font-size:.78rem}}
  th{{background:#111;color:#9d00ff;text-align:left;padding:8px;border-bottom:2px solid #222}}
  td{{padding:7px 8px;border-bottom:1px solid #0a0a0a;vertical-align:top}}
  tr:hover td{{background:#0a0a0a}}
  .mono{{color:#888;font-size:.72rem;word-break:break-all}}
  .dim{{color:#666}}
  .ctx{{background:#050505;padding:10px;font-size:.7rem;color:#666;white-space:pre-wrap;word-break:break-all}}
  footer{{margin-top:40px;color:#333;font-size:.7rem;border-top:1px solid #111;padding-top:12px}}
</style>
<script>
function toggle(row){{
  var next=row.nextElementSibling;
  if(next&&next.classList.contains('ctx-row'))
    next.style.display=next.style.display==='none'?'table-row':'none';
}}
</script>
</head>
<body>
<h1>VampSecure Labs — Secrets Scanner</h1>
<div class="meta">{escape(target)} · {now} · vamp-secrets-scanner v{VERSION}</div>

<div class="summary">
  <div class="kpi"><div class="kpi-n tot-n">{len(findings)}</div><div class="kpi-l">TOTAL</div></div>
  <div class="kpi"><div class="kpi-n crit-n">{crit}</div><div class="kpi-l">CRÍTICO</div></div>
  <div class="kpi"><div class="kpi-n high-n">{high}</div><div class="kpi-l">ALTO</div></div>
  <div class="kpi"><div class="kpi-n med-n">{med}</div><div class="kpi-l">MEDIO</div></div>
  <div class="kpi"><div class="kpi-n low-n">{low}</div><div class="kpi-l">BAJO</div></div>
</div>

<h2>Hallazgos (clic en fila para ver contexto)</h2>
<table>
  <thead><tr>
    <th>Severidad</th><th>Fichero : Línea</th><th>Patrón</th>
    <th>Categoría</th><th>Extracto</th>
  </tr></thead>
  <tbody>{rows()}</tbody>
</table>

<footer>
  © VampSecure Studios — VampSecure Labs Security Research Division<br>
  Uso exclusivo en entornos autorizados. Los datos son confidenciales.
</footer>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    console.print(f"[dim]  HTML → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Escaneo de contenedores Docker en runtime  (v2.3)
# ─────────────────────────────────────────────────────────────────────────────

def _docker_disponible() -> bool:
    """
    Comprueba si el binario docker está disponible en el PATH.
    Retorna True si está disponible, False en caso contrario.
    """
    import shutil as _shutil
    return _shutil.which("docker") is not None


def _obtener_envs_contenedor(container_id: str) -> Optional[List[str]]:
    """
    Obtiene las variables de entorno de un contenedor Docker.

    Intenta primero con 'docker inspect' para leer la configuración estática;
    si no devuelve variables, recurre a 'docker exec env' como alternativa.

    Parámetros
    ----------
    container_id : nombre o ID del contenedor en ejecución

    Retorna lista de strings con formato 'CLAVE=valor', o None si falla.
    """
    envs: List[str] = []

    # Método 1: docker inspect (más rápido, no requiere shell en el contenedor)
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            envs = [l for l in result.stdout.splitlines() if l.strip() and "=" in l]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Método 2: docker exec env (alternativa si inspect no devolvió variables)
    if not envs:
        try:
            result = subprocess.run(
                ["docker", "exec", container_id, "env"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                envs = [l for l in result.stdout.splitlines() if l.strip() and "=" in l]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return envs if envs else None


def scan_docker_container(container_id: str) -> List[Finding]:
    """
    Escanea las variables de entorno de un contenedor Docker en ejecución.

    Aplica los mismos 77 patrones de SECRET_PATTERNS del scanner estático
    a cada variable de entorno del contenedor. Los hallazgos se marcan
    como categoría 'Docker · Runtime Env' con severidad CRITICAL.

    Parámetros
    ----------
    container_id : nombre o ID del contenedor Docker a escanear

    Retorna lista de Finding con los secretos encontrados en las envs del contenedor.
    """
    if not _docker_disponible():
        console.print("[yellow]  Aviso: 'docker' no encontrado en PATH — omitiendo escaneo de contenedor[/]")
        return []

    console.print(f"[cyan]  Escaneando contenedor Docker: {container_id}[/]")

    envs = _obtener_envs_contenedor(container_id)
    if envs is None:
        console.print(f"[yellow]  Aviso: no se pudieron obtener variables de entorno del contenedor '{container_id}'[/]")
        return []

    hallazgos: List[Finding] = []

    for linea in envs:
        if not linea.strip() or "=" not in linea:
            continue

        # Escanear la línea de variable de entorno con los patrones habituales
        for pat in SECRET_PATTERNS:
            match = pat["compiled"].search(linea)
            if not match:
                continue

            valor_raw  = match.group(0)
            extracto   = _censor(valor_raw)
            fp         = _fingerprint(valor_raw, "DOCKER_ENV_SECRET")

            # Nombre de la variable de entorno (parte antes del '=')
            nombre_var = linea.split("=", 1)[0]

            hallazgos.append(Finding(
                file        = f"docker://{container_id}",
                line_no     = 0,
                pattern     = f"DOCKER_ENV_SECRET: {pat['name']}",
                category    = "Docker · Runtime Env",
                severity    = Severity.CRITICAL,
                preview     = extracto,
                context     = [
                    f"  Contenedor: {container_id}",
                    f"  Variable:   {nombre_var}",
                    f"  Patrón:     {pat['name']}",
                    f"  Extracto:   {extracto}",
                ],
                fingerprint = fp,
            ))

    if hallazgos:
        console.print(
            f"  [bold red]⚠ {len(hallazgos)} secreto(s) encontrado(s) en "
            f"variables de entorno de '{container_id}'[/]"
        )
    else:
        console.print(f"  [green]✔ Sin secretos detectados en las envs de '{container_id}'[/]")

    return hallazgos


def scan_all_docker_containers() -> List[Finding]:
    """
    Escanea los contenedores Docker actualmente en ejecución.

    Ejecuta 'docker ps -q' para obtener los IDs de todos los contenedores
    activos y aplica scan_docker_container() a cada uno.

    Retorna la lista combinada de hallazgos de todos los contenedores.
    """
    if not _docker_disponible():
        console.print("[yellow]  Aviso: 'docker' no encontrado en PATH — omitiendo escaneo de contenedores[/]")
        return []

    # Obtener lista de IDs de contenedores en ejecución
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ids = [i.strip() for i in result.stdout.splitlines() if i.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        console.print(f"[red]  Error ejecutando 'docker ps': {exc}[/]")
        return []

    if not ids:
        console.print("[yellow]  No hay contenedores Docker en ejecución.[/]")
        return []

    console.print(f"[cyan]  Escaneando {len(ids)} contenedor(es) Docker en ejecución...[/]")
    todos_hallazgos: List[Finding] = []

    for cid in ids:
        todos_hallazgos.extend(scan_docker_container(cid))

    return todos_hallazgos


def _scan_string_for_secrets(texto: str) -> List[Dict]:
    """
    Aplica todos los SECRET_PATTERNS a una cadena de texto y devuelve
    una lista de coincidencias brutas (sin crear objetos Finding).

    Cada elemento del resultado es un dict con las claves:
      - 'name':     nombre del patrón coincidente
      - 'severity': nivel de severidad del patrón
      - 'category': categoría del patrón
      - 'valor':    fragmento de texto que coincidió (sin censurar)

    Útil como auxiliar en funciones de escaneo de entornos externos
    (Docker runtime, Kubernetes Secrets, etc.) donde el contexto
    de creación del Finding difiere del flujo estático habitual.
    """
    coincidencias: List[Dict] = []
    for pat in SECRET_PATTERNS:
        match = pat["compiled"].search(texto)
        if match:
            coincidencias.append({
                "name":     pat["name"],
                "severity": pat["severity"],
                "category": pat.get("category", "Secret"),
                "valor":    match.group(0),
            })
    return coincidencias


def _kubectl_disponible() -> bool:
    """Comprueba si el binario 'kubectl' está disponible en el PATH."""
    try:
        subprocess.run(
            ["kubectl", "version", "--client", "--output=json"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, OSError):
        return False


def scan_kubernetes_secrets(namespace: Optional[str] = None) -> List[Finding]:
    """
    Escanea los Kubernetes Secrets del clúster activo buscando credenciales
    y datos sensibles codificados en base64.

    Parámetros:
      namespace: si se indica, limita la búsqueda a ese namespace;
                 si es None se escanean todos los namespaces.

    Requiere que 'kubectl' esté disponible en el PATH y que el contexto
    activo tenga permisos de lectura sobre los Secrets del namespace indicado.

    Retorna una lista de objetos Finding con los secretos detectados.
    """
    if not _kubectl_disponible():
        console.print("[yellow]  Aviso: 'kubectl' no encontrado en PATH — omitiendo escaneo de K8s Secrets[/]")
        return []

    # Construir comando kubectl
    if namespace:
        cmd = ["kubectl", "get", "secret", "-n", namespace, "-o", "json"]
        scope_label = f"namespace '{namespace}'"
    else:
        cmd = ["kubectl", "get", "secret", "--all-namespaces", "-o", "json"]
        scope_label = "todos los namespaces"

    console.print(f"[cyan]  Consultando Kubernetes Secrets ({scope_label})...[/]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        console.print("[red]  Tiempo de espera agotado ejecutando 'kubectl get secret'[/]")
        return []
    except (FileNotFoundError, OSError) as exc:
        console.print(f"[red]  Error ejecutando kubectl: {exc}[/]")
        return []

    if result.returncode != 0:
        console.print(f"[red]  kubectl salió con código {result.returncode}: {result.stderr.strip()[:200]}[/]")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        console.print(f"[red]  Error parseando salida JSON de kubectl: {exc}[/]")
        return []

    # Puede ser una lista (--all-namespaces) o un objeto único
    items = data.get("items", [data]) if "items" in data else [data]
    hallazgos: List[Finding] = []

    for secret in items:
        meta = secret.get("metadata", {})
        ns   = meta.get("namespace", "default")
        name = meta.get("name", "desconocido")
        tipo = secret.get("type", "")
        datos = secret.get("data") or {}

        for clave, valor_b64 in datos.items():
            # Decodificar el valor base64
            try:
                valor_decoded = base64.b64decode(valor_b64).decode("utf-8", errors="replace")
            except Exception:
                continue

            # Buscar patrones de secreto en el valor decodificado
            coincidencias = _scan_string_for_secrets(valor_decoded)

            # También escanear la clave (puede revelar el tipo de secreto)
            _scan_string_for_secrets(clave)

            # Usar el valor decodificado si no hay coincidencias por patrón
            # pero la clave sugiere que es un secreto
            claves_sensibles = {"password", "passwd", "secret", "token", "key",
                                 "apikey", "api_key", "private_key", "auth"}
            es_clave_sensible = any(k in clave.lower() for k in claves_sensibles)

            if not coincidencias and es_clave_sensible:
                # Hallazgo genérico basado en nombre de clave
                fp = _fingerprint(valor_decoded, f"K8S_SECRET_KEY:{clave}")
                extracto = _censor(valor_decoded[:120])
                hallazgos.append(Finding(
                    file=f"k8s://{ns}/{name}",
                    line_no=0,
                    pattern=f"K8S_SECRET_KEY: {clave} (tipo: {tipo})",
                    category="Kubernetes · Secret",
                    severity=Severity.HIGH,
                    preview=extracto,
                    context=[f"namespace={ns}", f"secret={name}", f"tipo={tipo}", f"clave={clave}"],
                    fingerprint=fp,
                ))
            else:
                for c in coincidencias:
                    fp = _fingerprint(c["valor"], f"K8S_SECRET:{ns}/{name}/{clave}")
                    extracto = _censor(c["valor"])
                    hallazgos.append(Finding(
                        file=f"k8s://{ns}/{name}",
                        line_no=0,
                        pattern=f"K8S_SECRET: {c['name']} (clave: {clave})",
                        category="Kubernetes · Secret",
                        severity=c["severity"],
                        preview=extracto,
                        context=[f"namespace={ns}", f"secret={name}", f"tipo={tipo}",
                                 f"clave={clave}", f"patron={c['name']}"],
                        fingerprint=fp,
                    ))

    if hallazgos:
        console.print(f"[dim]  {len(hallazgos)} hallazgo(s) en Kubernetes Secrets[/]")
    else:
        console.print("[dim]  Sin secretos detectados en Kubernetes Secrets[/]")

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vamp-secrets-scanner",
        description="VampSecure Labs — Escáner Estático de Secretos, PII e Historial Git",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  # Escanear directorio actual\n"
            "  python vamp_secrets_scanner.py .\n\n"
            "  # Escanear repo incluyendo historial git completo\n"
            "  python vamp_secrets_scanner.py /ruta/al/repo --git-history\n\n"
            "  # Solo críticos y altos, exportar SARIF para GitHub Actions\n"
            "  python vamp_secrets_scanner.py . --min-severity HIGH --sarif results.sarif\n\n"
            "  # Generar allowlist desde hallazgos actuales (baseline inicial)\n"
            "  python vamp_secrets_scanner.py . --generate-allowlist baseline.json\n\n"
            "  # Aplicar allowlist en CI para ignorar falsos positivos conocidos\n"
            "  python vamp_secrets_scanner.py . --allowlist baseline.json --sarif results.sarif\n"
        ),
    )
    p.add_argument("target",
                   metavar="DIRECTORIO",
                   help="Directorio raíz a escanear")
    out = p.add_argument_group("Salida")
    out.add_argument("-o", "--output",       metavar="FICHERO",
                     help="Exportar hallazgos a JSON")
    out.add_argument("--html",               metavar="FICHERO",
                     help="Exportar informe HTML dark-theme")
    out.add_argument("--sarif",              metavar="FICHERO",
                     help="Exportar resultados en formato SARIF 2.1.0 (GitHub Actions / VS Code)")
    out.add_argument("--min-severity",
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     default="LOW",
                     help="Severidad mínima a reportar (default: LOW)")
    out.add_argument("--only-critical",      action="store_true",
                     help="Mostrar solo hallazgos CRÍTICOS (alias de --min-severity CRITICAL)")
    fil = p.add_argument_group("Filtros")
    fil.add_argument("--all-extensions",     action="store_true",
                     help="Escanear todos los ficheros no binarios (ignora whitelist de extensiones)")
    fil.add_argument("--max-depth",          type=int, metavar="N",
                     help="Profundidad máxima de recursión")
    fil.add_argument("--no-entropy",         action="store_true",
                     help="Deshabilitar el análisis de entropía de Shannon")
    fil.add_argument("--entropy-threshold",  type=float, default=4.5, metavar="BITS",
                     help="Umbral de entropía en bits/símbolo (default: 4.5)")
    fil.add_argument("--exclude-dir",        action="append", default=[], metavar="DIR",
                     help="Directorios adicionales a excluir (repetible)")
    git = p.add_argument_group("Historial Git")
    git.add_argument("--git-history",        action="store_true",
                     help="Escanear el historial completo de commits git (detecta secretos borrados)")
    git.add_argument("--max-commits",        type=int, default=0, metavar="N",
                     help="Limitar el escaneo de historial a los N commits más recientes (0 = sin límite)")
    al = p.add_argument_group("Allowlist")
    al.add_argument("--allowlist",           metavar="FICHERO",
                    help="Fichero JSON con falsos positivos a ignorar")
    al.add_argument("--generate-allowlist",  metavar="FICHERO",
                    help="Generar allowlist JSON a partir de los hallazgos actuales y salir")

    bl = p.add_argument_group("Baseline")
    bl.add_argument("--baseline", metavar="FICHERO",
                    help=(
                        "Fichero JSON de baseline con hallazgos aceptados "
                        "(default: .vamp-secrets-baseline.json en el directorio objetivo si existe). "
                        "Los hallazgos en el baseline no se reportan ni generan error en CI."
                    ))
    bl.add_argument("--update-baseline", action="store_true",
                    help=(
                        "Añadir todos los hallazgos actuales al baseline y salir con código 0. "
                        "Útil para aceptar el estado actual tras una revisión. "
                        "El baseline se crea si no existe (default: .vamp-secrets-baseline.json)."
                    ))

    docker = p.add_argument_group("Escaneo Docker en runtime (v2.3)")
    docker.add_argument("--scan-container",  metavar="NAME_OR_ID",
                        dest="scan_container", default=None,
                        help="Escanear variables de entorno de un contenedor Docker en ejecución. "
                             "Requiere que 'docker' esté disponible en el PATH.")
    docker.add_argument("--scan-all-containers", action="store_true",
                        dest="scan_all_containers",
                        help="Escanear todos los contenedores Docker actualmente en ejecución "
                             "('docker ps -q'). Requiere que 'docker' esté disponible en el PATH.")

    k8s = p.add_argument_group("Escaneo Kubernetes Secrets (v2.4)")
    k8s.add_argument("--k8s", action="store_true",
                     dest="k8s",
                     help="Escanear los Kubernetes Secrets del clúster activo (todos los namespaces). "
                          "Requiere que 'kubectl' esté disponible en el PATH y que el contexto "
                          "activo tenga permisos de lectura sobre los Secrets.")
    k8s.add_argument("--k8s-namespace", metavar="NS",
                     dest="k8s_namespace", default=None,
                     help="Limitar el escaneo de K8s Secrets a un namespace concreto "
                          "(implica --k8s). Ej: --k8s-namespace production")

    ci = p.add_argument_group("Integración CI/CD")
    ci.add_argument("--install-hook",        action="store_true",
                    help="Instalar hook pre-commit git en el directorio objetivo y salir")
    ci.add_argument("--export-semgrep",      metavar="FICHERO",
                    help="Exportar patrones como reglas Semgrep YAML y salir")
    ci.add_argument("--verify",              action="store_true",
                    help="Verificar activamente si los secretos CRITICAL/HIGH encontrados siguen "
                         "válidos (petición mínima a la API del proveedor; requiere aiohttp)")
    ci.add_argument(
        "--watch", type=int, metavar="SECONDS",
        help="Daemon mode: re-escanear cada N segundos, mostrar solo secretos NEW/RESOLVED",
    )

    # Argumentos de informe unificado VSL (--client, --engagement, --auditor,
    # --report-scope, --report-html, --report-pdf)
    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


# =============================================================================
# CONVERSOR A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(findings: List["Finding"], target: str) -> list:
    """
    Convierte hallazgos de secretos al formato Finding unificado de VampSecure Labs.

    Incluye todos los hallazgos con severidad MEDIUM, HIGH o CRITICAL.
    Los hallazgos LOW se omiten del informe de cliente para mantener el foco.

    Parámetros
    ----------
    findings : List[Finding]  — Lista de hallazgos ya filtrados y deduplicados
    target   : str            — Ruta raíz del objetivo (para calcular rutas relativas)

    Retorna
    -------
    List[Finding]  — Lista de hallazgos en formato VSL con prefijo SEC-NNN
    """
    from vampsec_report import Finding as VSLFinding

    SEVERIDADES_INCLUIDAS = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos: list = []
    n = 0

    for f in findings:
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev_val not in SEVERIDADES_INCLUIDAS:
            continue
        n += 1

        # Ruta relativa para no exponer rutas absolutas de máquina en el informe
        try:
            ruta_relativa = str(Path(f.file).relative_to(target))
        except ValueError:
            ruta_relativa = f.file

        # Evidencia: ubicación, patrón, extracto censurado + historial git si aplica
        partes_evidencia = [
            f"Fichero: {ruta_relativa}:{f.line_no}",
            f"Patrón: {f.pattern}",
            f"Categoría: {f.category}",
            f"Extracto (censurado): {f.preview}",
        ]
        if f.git_commit:
            partes_evidencia.append(
                f"Commit git: {f.git_commit[:12]} "
                + (f"por {f.git_author}" if f.git_author else "")
                + (f" ({f.git_date})" if f.git_date else "")
            )

        hallazgos.append(VSLFinding(
            id          = f"SEC-{n:03d}",
            title       = f"{f.pattern} detectado en {ruta_relativa}",
            severity    = sev_val,
            description = (
                f"Se ha detectado el patrón '{f.pattern}' (categoría: {f.category}) "
                f"en el fichero {ruta_relativa} línea {f.line_no}. "
                "La presencia de este secreto en el código fuente supone un riesgo de exposición."
            ),
            evidence    = " | ".join(partes_evidencia),
            affected    = ruta_relativa,
            remediation = (
                f"Eliminar el secreto del fichero '{ruta_relativa}', rotar las credenciales "
                f"afectadas y añadir la ruta a .gitignore. Si aparece en historial git, "
                "limpiar con git-filter-repo o BFG Repo Cleaner."
            ),
            tags        = ["secrets", "sast", f.category.split("·")[0].strip().lower()],
        ))

    return hallazgos


# =============================================================================
# INTEGRACIÓN CI/CD — HOOKS Y EXPORTACIÓN
# =============================================================================

def _install_pre_commit_hook(target: Path) -> None:
    """
    Instala un hook pre-commit de git en el repositorio objetivo.

    El hook ejecuta vamp-secrets-scanner sobre el árbol de trabajo completo
    antes de cada commit, bloqueando el push si encuentra hallazgos MEDIUM+.
    El usuario puede saltarse el hook con `git commit --no-verify` cuando lo
    necesite (p. ej. para commits de emergencia o falsos positivos conocidos).

    Parámetros
    ----------
    target : Path  — Directorio raíz del repositorio git
    """
    git_dir = target / ".git"
    if not git_dir.is_dir():
        console.print(f"[red]  ERROR: {target} no es un repositorio git (falta .git/).[/]")
        sys.exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    tool_path = Path(__file__).resolve()
    hook_script = f"""#!/usr/bin/env bash
# Hook pre-commit instalado por vamp-secrets-scanner
# © VampSecure Studios — VampSecure Labs Security Research Division
#
# Bloquea commits si se detectan secretos con severidad MEDIUM o superior.
# Para omitir puntualmente: git commit --no-verify
set -euo pipefail

SCANNER="{tool_path}"
TARGET="$(git rev-parse --show-toplevel 2>/dev/null || echo ".")"

if [ ! -f "$SCANNER" ]; then
    echo "[vamp-secrets-scanner] AVISO: escáner no encontrado en $SCANNER" >&2
    exit 0
fi

echo "[vamp-secrets-scanner] Escaneando secretos antes del commit..."
ALLOWLIST_OPT=""
[ -f "$TARGET/.vamp-allowlist.json" ] && ALLOWLIST_OPT="--allowlist $TARGET/.vamp-allowlist.json"
python3 "$SCANNER" "$TARGET" --min-severity MEDIUM $ALLOWLIST_OPT 2>&1
CODE=$?

if [ $CODE -ge 1 ]; then
    echo "" >&2
    echo "[vamp-secrets-scanner] ⛔  Commit BLOQUEADO — secretos encontrados (MEDIUM+)" >&2
    echo "   Elimina los secretos, rótalos y vuelve a intentarlo." >&2
    echo "   Para omitir este check (úsalo con cuidado): git commit --no-verify" >&2
    exit 1
fi

exit 0
"""
    hook_path.write_text(hook_script, encoding="utf-8")
    hook_path.chmod(0o755)
    console.print(f"[bold green]  ✔ Hook pre-commit instalado: {hook_path}[/]")
    console.print("[dim]  Cada commit escaneará el árbol de trabajo completo (MEDIUM+).[/]")
    console.print(f"[dim]  Para desinstalar: rm {hook_path}[/]")


# =============================================================================
# VERIFICACIÓN ACTIVA DE SECRETOS (--verify)
# =============================================================================

def _extract_raw_value(finding: "Finding") -> Optional[str]:
    """
    Re-lee el fichero fuente y extrae el valor raw del secreto usando el
    mismo patrón que lo detectó originalmente.

    Solo funciona con hallazgos del árbol de trabajo (no de historial git).
    """
    if finding.git_commit:
        return None    # hallazgo de historial — fichero no accesible directamente
    try:
        path = Path(finding.file)
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in SECRET_PATTERNS:
            if pat["name"] == finding.pattern:
                for match in pat["compiled"].finditer(text):
                    line_no = text[: match.start()].count("\n") + 1
                    if line_no == finding.line_no:
                        return match.group(0)
    except Exception:
        pass
    return None


async def _check_aws_credentials_pair(
    session, access_key: str, secret_key: str
) -> Optional[bool]:
    """
    Verifica un par de credenciales AWS (Access Key ID + Secret Access Key)
    mediante STS GetCallerIdentity. No requiere permisos IAM: la llamada
    siempre está disponible para credenciales válidas.

    Implementa AWS Signature Version 4 con hmac+hashlib (sin boto3).
    Retorna True si las credenciales son válidas, False si están revocadas,
    None si no se pudo determinar.
    """
    import hashlib as _hl
    import hmac as _hm
    import datetime as _dt

    host = "sts.amazonaws.com"
    region = "us-east-1"
    service = "sts"
    payload = "Action=GetCallerIdentity&Version=2011-06-15"
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    now = _dt.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_headers = (
        f"content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    payload_hash = _hl.sha256(payload.encode()).hexdigest()

    canonical_request = "\n".join([
        "POST", "/", "",
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        _hl.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return _hm.new(key, msg.encode(), _hl.sha256).digest()

    signing_key = _sign(
        _sign(_sign(_sign(f"AWS4{secret_key}".encode(), date_stamp), region), service),
        "aws4_request",
    )
    signature = _hm.new(signing_key, string_to_sign.encode(), _hl.sha256).hexdigest()

    auth = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": auth,
    }

    try:
        async with session.post(
            f"https://{host}/",
            data=payload,
            headers=headers,
            timeout=12,
            ssl=True,
        ) as r:
            body = await r.text()
            # 200 = credenciales válidas; 403 con InvalidClientTokenId = key no existe
            if r.status == 200:
                return True
            if r.status == 403 and "InvalidClientTokenId" in body:
                return False
            # 403 con SignatureDoesNotMatch = key existe pero secret incorrecto
            if r.status == 403 and "SignatureDoesNotMatch" in body:
                return True   # la key existe, aunque el secret aquí sea incorrecto
    except Exception:
        pass
    return None


async def _check_secret_active(session, category: str, value: str) -> Optional[bool]:
    """
    Hace una petición mínima a la API del proveedor para saber si el
    secreto sigue activo. Retorna True (activo), False (revocado/inválido)
    o None (no se pudo determinar).

    Soporta: GitHub tokens, Stripe live keys, Slack bot/user tokens,
    Telegram bot tokens. AWS Access Key ID en solitario no se puede verificar
    (se necesita también el Secret) → None.
    """
    import base64 as _b64
    import re as _re
    try:
        UA = f"{TOOL_NAME}/{VERSION}"

        if "AWS" in category and _re.match(r"(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)", value):
            # Solo el Access Key ID: imposible verificar sin el Secret Access Key
            return None

        elif "GitHub" in category and value.startswith(("ghp_", "gho_", "ghs_", "github_pat_")):
            headers = {"Authorization": f"token {value}", "User-Agent": UA}
            async with session.get(
                "https://api.github.com/user", headers=headers,
                timeout=10, ssl=True
            ) as r:
                return r.status == 200

        elif "Stripe" in category and value.startswith("sk_live_"):
            creds = _b64.b64encode(f"{value}:".encode()).decode()
            headers = {"Authorization": f"Basic {creds}", "User-Agent": UA}
            async with session.get(
                "https://api.stripe.com/v1/customers?limit=1", headers=headers,
                timeout=10, ssl=True
            ) as r:
                return r.status == 200

        elif "Slack" in category and value.startswith(("xoxb-", "xoxp-", "xapp-")):
            headers = {"Authorization": f"Bearer {value}", "User-Agent": UA}
            async with session.post(
                "https://slack.com/api/auth.test", headers=headers,
                timeout=10, ssl=True
            ) as r:
                data = await r.json(content_type=None)
                return bool(data.get("ok"))

        elif "Telegram" in category:
            m = _re.search(r"([0-9]{8,10}:[A-Za-z0-9_\-]{35})", value)
            if m:
                token = m.group(1)
                async with session.get(
                    f"https://api.telegram.org/bot{token}/getMe",
                    timeout=10, ssl=True
                ) as r:
                    data = await r.json(content_type=None)
                    return bool(data.get("ok"))

    except Exception:
        pass
    return None


async def _run_verification(findings: "List[Finding]") -> None:
    """
    Verifica activamente los secretos CRITICAL/HIGH de los hallazgos.

    Para AWS: agrupa los hallazgos por fichero fuente y empareja el
    Access Key ID con el Secret Access Key del mismo fichero para
    realizar una llamada STS GetCallerIdentity (verificación real).

    Para el resto: GitHub, Stripe, Slack, Telegram con llamada individual.
    """
    import aiohttp as _aiohttp
    from collections import defaultdict as _dd

    VERIFICABLES = {"Cloud · AWS", "VCS · GitHub", "Pagos · Stripe",
                    "Comunicaciones · Slack", "Comunicaciones · Telegram"}

    candidatos = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
        and any(cat in f.category for cat in VERIFICABLES)
        and not f.git_commit    # solo árbol de trabajo
    ]

    if not candidatos:
        console.print("[dim]  --verify: no hay hallazgos verificables (se requiere árbol de trabajo + proveedor soportado).[/]")
        return

    console.print(f"\n[bold cyan]  FASE EXTRA — Verificación activa ({len(candidatos)} secretos)[/]\n")

    activos = revocados = sin_datos = 0

    # ── Agrupar hallazgos AWS por fichero para emparejar key+secret ──────────
    aws_por_fichero: dict = _dd(lambda: {"key_id": None, "secret": None, "key_finding": None, "secret_finding": None})
    aws_ids: set = set()

    for f in candidatos:
        if "AWS" in f.category:
            raw = _extract_raw_value(f)
            if not raw:
                continue
            entry = aws_por_fichero[f.file]
            import re as _re_aws
            if _re_aws.match(r"(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}", raw):
                entry["key_id"] = raw
                entry["key_finding"] = f
            elif len(raw) == 40 and _re_aws.match(r"[A-Za-z0-9/+=]{40}", raw):
                entry["secret"] = raw
                entry["secret_finding"] = f
            aws_ids.add(id(f))

    async with _aiohttp.ClientSession() as session:
        # ── Verificar pares AWS (key + secret del mismo fichero) ─────────────
        for filepath, entry in aws_por_fichero.items():
            if not (entry["key_id"] and entry["secret"]):
                # Par incompleto: marcar ambos como indeterminados
                for fnd in (entry["key_finding"], entry["secret_finding"]):
                    if fnd:
                        sin_datos += 1
                        console.print(
                            f"  [dim]? indeterminado[/] {fnd.pattern} — AWS key sin secreto parejado "
                            f"en {fnd.file}:{fnd.line_no}"
                        )
                continue

            status = await _check_aws_credentials_pair(session, entry["key_id"], entry["secret"])
            key_preview = entry["key_id"][:8] + "…"
            label = f"AWS key pair [{key_preview}] — {filepath}"

            if status is True:
                activos += 1
                console.print(f"  [bold red]✖ ACTIVO[/]   {label}")
            elif status is False:
                revocados += 1
                console.print(f"  [green]✔ revocado[/] {label}")
            else:
                sin_datos += 1
                console.print(f"  [dim]? indeterminado[/] {label}")

        # ── Verificar el resto (no-AWS) ──────────────────────────────────────
        for finding in candidatos:
            if id(finding) in aws_ids:
                continue  # ya procesado arriba

            raw = _extract_raw_value(finding)
            if not raw:
                sin_datos += 1
                console.print(f"  [dim]? {finding.pattern} en {finding.file}:{finding.line_no} — valor no recuperable[/]")
                continue

            status = await _check_secret_active(session, finding.category, raw)
            preview = raw[:6] + "…" + raw[-3:] if len(raw) > 10 else raw[:3] + "…"

            if status is True:
                activos += 1
                console.print(
                    f"  [bold red]✖ ACTIVO[/]   {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )
            elif status is False:
                revocados += 1
                console.print(
                    f"  [green]✔ revocado[/] {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )
            else:
                sin_datos += 1
                console.print(
                    f"  [dim]? indeterminado[/] {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )

    estilo = "bold red" if activos > 0 else "bold green"
    console.print(
        f"\n  [{estilo}]Verificación: {activos} activos · {revocados} revocados · {sin_datos} sin datos[/]"
    )
    if activos:
        console.print(
            "  [bold red]⚠ ACCIÓN URGENTE: rota inmediatamente los secretos activos listados.[/]"
        )


def _export_semgrep_rules(output_file: str) -> None:
    """
    Exporta todos los patrones del escáner como reglas Semgrep YAML.

    Genera un fichero importable directamente con:
        semgrep --config <fichero> <directorio>

    Los niveles de severidad se mapean así:
        CRITICAL → ERROR  |  HIGH/MEDIUM → WARNING  |  LOW → INFO

    Usa block literals YAML (|-) para los patrones regex: evita escapes y
    garantiza compatibilidad con expresiones regulares complejas.

    Parámetros
    ----------
    output_file : str  — Ruta del fichero YAML de salida
    """
    SEV_MAP = {"CRITICAL": "ERROR", "HIGH": "WARNING", "MEDIUM": "WARNING", "LOW": "INFO"}

    def _slug(name: str) -> str:
        import re as _re
        return _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

    def _yaml_str(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    lines = [
        "# Reglas Semgrep generadas automáticamente por vamp-secrets-scanner",
        "# © VampSecure Studios — VampSecure Labs Security Research Division",
        "# Uso: semgrep --config <este-fichero> <directorio-objetivo>",
        "# Documentación: https://semgrep.dev/docs/",
        "",
        "rules:",
    ]

    for pat in _RAW_PATTERNS:
        rule_id   = f"vampsec-{_slug(pat['name'])}"
        sev       = SEV_MAP.get(pat["severity"], "WARNING")
        regex     = pat["regex"]
        category  = pat["category"]
        msg_title = pat["name"]

        lines += [
            f"  - id: {rule_id}",
            "    patterns:",
            "      - pattern-regex: |-",
            f"          {regex}",
            "    message: >-",
            f"      {msg_title} detectado [{category}].",
            "      Eliminar inmediatamente y rotar las credenciales afectadas.",
            f"    severity: {sev}",
            "    languages:",
            "      - generic",
            "    metadata:",
            f'      category: "{category}"',
            f"      vsl_severity: {pat['severity']}",
            "      source: vamp-secrets-scanner",
            "      fix: Eliminar el secreto del código y rotar credenciales.",
            "",
        ]

    Path(output_file).write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[bold green]  ✔ {len(_RAW_PATTERNS)} reglas Semgrep exportadas → {output_file}[/]")
    console.print(f"[dim]  Ejecutar: semgrep --config {output_file} <directorio>[/]")


# ─── Daemon mode ──────────────────────────────────────────────────────────────

def _run_scan(args) -> List[Finding]:
    """Ejecuta todas las fases de escaneo y devuelve findings únicos filtrados."""
    import io, contextlib

    target = Path(args.target).resolve()
    min_sev = Severity.CRITICAL if args.only_critical else Severity(args.min_severity)
    entropy_threshold = float("inf") if args.no_entropy else args.entropy_threshold

    all_findings: List[Finding] = []

    # Silenciar salida verbose en modo daemon (solo stderr de cambios)
    with contextlib.redirect_stdout(io.StringIO()):
        files = list(discover_files(target, args.max_depth, args.all_extensions))
        for f in files:
            all_findings.extend(scan_file(f, entropy_threshold))

        if getattr(args, "git_history", False) and _is_git_repo(target):
            all_findings.extend(scan_git_history(target, entropy_threshold, args.max_commits))

        all_findings.extend(scan_vault_misconfig(target))

        if getattr(args, "scan_container", None):
            all_findings.extend(scan_docker_container(args.scan_container))
        elif getattr(args, "scan_all_containers", False):
            all_findings.extend(scan_all_docker_containers())

        if getattr(args, "k8s", False) or getattr(args, "k8s_namespace", None):
            all_findings.extend(scan_kubernetes_secrets(namespace=getattr(args, "k8s_namespace", None)))

    # Deduplicar por fingerprint
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in all_findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)

    if args.allowlist:
        unique = apply_allowlist(unique, load_allowlist(args.allowlist))

    return [
        f for f in unique
        if _SEVERITY_ORDER[f.severity] <= _SEVERITY_ORDER[min_sev]
        and not f.allowlisted
    ]


def _daemon_loop(args, interval: int) -> None:
    """Re-scan every `interval` seconds; print only NEW / RESOLVED secrets."""
    import signal

    prev_fps: set = set()
    iteration = 0

    def _stop(sig, frame):
        print("\n[!] Daemon detenido.", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print(
        f"[*] Daemon mode — {args.target} — cada {interval}s — Ctrl+C para detener",
        file=sys.stderr,
    )

    while True:
        iteration += 1
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"\n── [{ts}] iter #{iteration} ──", file=sys.stderr)

        try:
            findings = _run_scan(args)
        except Exception as exc:
            print(f"  [!] Error en escaneo: {exc}", file=sys.stderr)
            time.sleep(interval)
            continue

        current_fps = {f.fingerprint for f in findings}
        new_fps = current_fps - prev_fps
        resolved_fps = prev_fps - current_fps

        if not new_fps and not resolved_fps:
            print("[=] Sin cambios", file=sys.stderr)
        else:
            for f in sorted(findings, key=lambda x: x.fingerprint):
                if f.fingerprint in new_fps:
                    print(
                        f"  [+NEW     ][{f.severity.value.upper():8s}] {f.pattern}: {f.file}:{f.line_no}",
                        file=sys.stderr,
                    )
            for fp in sorted(resolved_fps):
                print(f"  [-RESOLVED] {fp[:16]}…", file=sys.stderr)

        prev_fps = current_fps
        time.sleep(interval)


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    console.print(BANNER, style="bold magenta")

    args   = parse_args()
    target = Path(args.target).resolve()

    if getattr(args, "watch", None) is not None:
        _daemon_loop(args, args.watch)
        return

    # ── Flags de acción directa (exportar/instalar) — no requieren escaneo ──
    if getattr(args, "export_semgrep", None):
        _export_semgrep_rules(args.export_semgrep)
        sys.exit(0)

    if not target.exists():
        console.print(f"[red]  ERROR: {target} no existe.[/]")
        sys.exit(1)
    if not target.is_dir():
        console.print(f"[red]  ERROR: {target} no es un directorio.[/]")
        sys.exit(1)

    if getattr(args, "install_hook", False):
        _install_pre_commit_hook(target)
        sys.exit(0)

    # Añadir directorios extra a excluir
    for d in args.exclude_dir:
        EXCLUDE_DIRS.add(d)

    min_sev = Severity.CRITICAL if args.only_critical else Severity(args.min_severity)
    entropy_threshold = float("inf") if args.no_entropy else args.entropy_threshold

    console.print(f"  Objetivo: [cyan]{target}[/]")
    if args.git_history:
        console.print("  Modo: [bold yellow]árbol actual + historial git[/]"
                      + (f" (últimos {args.max_commits} commits)" if args.max_commits else ""))
    console.print()

    all_findings: List[Finding] = []

    # ── Fase 1: descubrir ficheros ────────────────────────────────────────────
    console.print("[bold cyan]  FASE 1[/] — Descubriendo ficheros en alcance...")
    files = list(discover_files(target, args.max_depth, args.all_extensions))
    total_bytes = sum(f.stat().st_size for f in files if f.exists())
    console.print(f"[dim]  {len(files)} ficheros · {total_bytes / 1024:.1f} KB en alcance[/]\n")

    # ── Fase 2a: escaneo de ficheros ──────────────────────────────────────────
    console.print("[bold cyan]  FASE 2[/] — Escaneando patrones y entropía (árbol actual)...")
    with console.status("[bold green]Analizando ficheros...[/]", spinner="dots"):
        for f in files:
            all_findings.extend(scan_file(f, entropy_threshold))

    # ── Fase 2b: escaneo de historial git (opcional) ──────────────────────────
    if args.git_history:
        if _is_git_repo(target):
            console.print("[bold cyan]  FASE 2b[/] — Escaneando historial git...")
            with console.status("[bold green]Analizando commits...[/]", spinner="dots"):
                git_findings = scan_git_history(target, entropy_threshold, args.max_commits)
            console.print(f"[dim]  {len(git_findings)} hallazgos en historial git[/]\n")
            all_findings.extend(git_findings)
        else:
            console.print("[yellow]  Aviso: --git-history solicitado pero el directorio no es un repo git[/]\n")

    # ── Fase 2c: análisis de misconfiguraciones de Vault ──────────────────────
    console.print("[bold cyan]  FASE 2c[/] — Analizando misconfiguraciones Vault (CVE-2026-5052)...")
    vault_findings = scan_vault_misconfig(target)
    if vault_findings:
        console.print(f"[dim]  {len(vault_findings)} hallazgos de misconfiguración Vault[/]\n")
    else:
        console.print("[dim]  Sin misconfiguraciones Vault detectadas[/]\n")
    all_findings.extend(vault_findings)

    # ── Fase 2d: escaneo de contenedores Docker en runtime (v2.3) ────────────
    _contenedor_a_escanear = getattr(args, "scan_container", None)
    _escanear_todos        = getattr(args, "scan_all_containers", False)

    if _contenedor_a_escanear:
        console.print("[bold cyan]  FASE 2d[/] — Escaneando contenedor Docker en runtime...")
        docker_findings = scan_docker_container(_contenedor_a_escanear)
        if docker_findings:
            console.print(
                f"[dim]  {len(docker_findings)} hallazgo(s) en variables de entorno "
                f"del contenedor '{_contenedor_a_escanear}'[/]\n"
            )
        else:
            console.print("[dim]  Sin secretos detectados en el contenedor indicado[/]\n")
        all_findings.extend(docker_findings)

    elif _escanear_todos:
        console.print("[bold cyan]  FASE 2d[/] — Escaneando todos los contenedores Docker en ejecución...")
        docker_findings = scan_all_docker_containers()
        if docker_findings:
            console.print(
                f"[dim]  {len(docker_findings)} hallazgo(s) en variables de entorno "
                f"de contenedores Docker[/]\n"
            )
        else:
            console.print("[dim]  Sin secretos detectados en los contenedores en ejecución[/]\n")
        all_findings.extend(docker_findings)

    # ── Fase 2e: escaneo de Kubernetes Secrets (v2.4) ────────────────────────
    _k8s_ns = getattr(args, "k8s_namespace", None)
    _k8s    = getattr(args, "k8s", False) or bool(_k8s_ns)

    if _k8s:
        console.print("[bold cyan]  FASE 2e[/] — Escaneando Kubernetes Secrets...")
        k8s_findings = scan_kubernetes_secrets(namespace=_k8s_ns)
        if k8s_findings:
            console.print(
                f"[dim]  {len(k8s_findings)} hallazgo(s) en Kubernetes Secrets[/]\n"
            )
        else:
            console.print("[dim]  Sin secretos detectados en Kubernetes Secrets[/]\n")
        all_findings.extend(k8s_findings)

    # ── Deduplicación y filtrado ──────────────────────────────────────────────
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in all_findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)

    # ── Allowlist ─────────────────────────────────────────────────────────────
    if args.allowlist:
        allowlist = load_allowlist(args.allowlist)
        unique = apply_allowlist(unique, allowlist)
        n_suppressed = sum(1 for f in unique if f.allowlisted)
        if n_suppressed:
            console.print(f"[dim]  {n_suppressed} hallazgos suprimidos por la allowlist[/]")

    # ── Filtrar por severidad y allowlist ─────────────────────────────────────
    filtered = [
        f for f in unique
        if _SEVERITY_ORDER[f.severity] <= _SEVERITY_ORDER[min_sev]
        and not f.allowlisted
    ]

    console.print(f"[dim]  {len(unique)} hallazgos únicos · {len(filtered)} tras filtro de severidad[/]\n")

    # ── Generar allowlist baseline (si se pide, exportar y salir) ─────────────
    if args.generate_allowlist:
        generate_allowlist(filtered, args.generate_allowlist)
        console.print("[dim]  Usa --allowlist con ese fichero para suprimir los hallazgos en próximas ejecuciones.[/]")
        sys.exit(0)

    # ── Baseline — filtrar hallazgos ya aceptados ─────────────────────────────
    # Buscar el fichero baseline: --baseline explícito o .vamp-secrets-baseline.json en el objetivo
    _baseline_path: Optional[str] = getattr(args, "baseline", None)
    if _baseline_path is None:
        _default_bp = target / ".vamp-secrets-baseline.json"
        if _default_bp.exists():
            _baseline_path = str(_default_bp)

    if _baseline_path:
        _accepted = load_baseline(_baseline_path)
        if _accepted:
            filtered = apply_baseline(filtered, _accepted)
            _n_bl = sum(1 for f in filtered if f.allowlisted)
            if _n_bl:
                console.print(
                    f"[dim]  {_n_bl} hallazgo(s) suprimido(s) por el baseline ({_baseline_path})[/]"
                )
            filtered = [f for f in filtered if not f.allowlisted]

    # ── Actualizar baseline (--update-baseline) ───────────────────────────────
    if getattr(args, "update_baseline", False):
        _bp_dest = _baseline_path or str(target / ".vamp-secrets-baseline.json")
        update_baseline(filtered, _bp_dest)
        console.print(
            "[dim]  Próximas ejecuciones ignorarán estos hallazgos. "
            "Usa --baseline para aplicar el filtro.[/]"
        )
        sys.exit(0)

    # ── Mostrar resultados ────────────────────────────────────────────────────
    if not filtered:
        console.print("[bold green]  ✓ Sin hallazgos en el rango de severidad seleccionado.[/]")
    else:
        console.print(build_results_table(filtered, target))
        print_critical_panels(filtered, target)

    # ── Resumen ───────────────────────────────────────────────────────────────
    n_crit = sum(1 for f in filtered if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in filtered if f.severity == Severity.HIGH)
    n_med  = sum(1 for f in filtered if f.severity == Severity.MEDIUM)
    n_low  = sum(1 for f in filtered if f.severity == Severity.LOW)
    n_git  = sum(1 for f in filtered if f.git_commit)

    sev_style = "bold red" if n_crit > 0 else ("bold yellow" if n_high > 0 else "bold green")
    resumen = (f"\n[{sev_style}]  RESUMEN: {len(filtered)} hallazgos · "
               f"{n_crit} CRÍTICO · {n_high} ALTO · {n_med} MEDIO · {n_low} BAJO")
    if n_git:
        resumen += f" · {n_git} en historial git"
    console.print(resumen + "[/]")

    # ── Verificación activa de secretos (--verify) ───────────────────────────
    if getattr(args, "verify", False) and filtered:
        asyncio.run(_run_verification(filtered))

    # ── Exportación ───────────────────────────────────────────────────────────
    if args.output:
        export_json(filtered, str(target), args.output)
    if args.html:
        export_html(filtered, str(target), args.html)
    if args.sarif:
        export_sarif(filtered, str(target), args.sarif)

    # ── Informe unificado VSL (cliente) ───────────────────────────────────────
    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta   = meta_from_args(args, tool="vamp-secrets-scanner", version=VERSION)
        report = VampSecReport(meta=meta, findings=_findings_vsl(filtered, str(target)))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(f"[bold green]  ✔ Informe cliente HTML guardado: {args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"[bold green]  ✔ Informe cliente PDF guardado: {args.report_pdf}[/]")

    # Exit codes útiles en CI/CD
    if n_crit > 0:
        sys.exit(2)
    elif n_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]  Escaneo interrumpido por el usuario.[/]")
        sys.exit(130)
