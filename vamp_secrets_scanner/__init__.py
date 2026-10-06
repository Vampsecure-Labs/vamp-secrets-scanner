# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_secrets_scanner — Escáner Estático de Secretos y Credenciales
===================================================================
VampSecure Labs · VampSecure Studios

Paquete importable con API pública backward-compatible.

Uso como librería:
    from vamp_secrets_scanner import scan_file, discover_files, Severity, export_json

Uso como CLI:
    python -m vamp_secrets_scanner <directorio>
    vamp-secrets-scanner <directorio>
"""

from ._models import (
    VERSION,
    TOOL_NAME,
    _RAW_PATTERNS,
    SECRET_PATTERNS,
    EXCLUDE_DIRS,
    INCLUDE_EXTENSIONS,
    INCLUDE_FILENAMES,
    BINARY_EXTENSIONS,
    Severity,
    _SEVERITY_ORDER,
    Finding,
)

from ._core import (
    discover_files,
    scan_file,
    scan_git_history,
    scan_vault_misconfig,
    load_allowlist,
    apply_allowlist,
    generate_allowlist,
    load_baseline,
    apply_baseline,
    update_baseline,
    scan_docker_container,
    scan_all_docker_containers,
    scan_kubernetes_secrets,
    apply_delta_scan,
    _shannon_entropy,
    _censor,
    _fingerprint,
    _baseline_fingerprint,
    _context_lines,
    _check_aws_credentials_pair,
    _check_secret_active,
    _run_verification,
    _is_git_repo,
    _run_scan,
)

from .cli import main, parse_args

from ._report import (
    export_json,
    export_html,
    export_sarif,
    _findings_vsl,
)

__all__ = [
    # Versión y nombre
    "VERSION",
    "TOOL_NAME",
    # Constantes
    "_RAW_PATTERNS",
    "SECRET_PATTERNS",
    "EXCLUDE_DIRS",
    "INCLUDE_EXTENSIONS",
    "INCLUDE_FILENAMES",
    "BINARY_EXTENSIONS",
    # Tipos
    "Severity",
    "_SEVERITY_ORDER",
    "Finding",
    # Core — descubrimiento y escaneo
    "discover_files",
    "scan_file",
    "scan_git_history",
    "scan_vault_misconfig",
    # Core — allowlist y baseline
    "load_allowlist",
    "apply_allowlist",
    "generate_allowlist",
    "load_baseline",
    "apply_baseline",
    "update_baseline",
    # Core — runtime scanning
    "scan_docker_container",
    "scan_all_docker_containers",
    "scan_kubernetes_secrets",
    # Core — utilidades
    "apply_delta_scan",
    "_shannon_entropy",
    "_censor",
    "_fingerprint",
    "_baseline_fingerprint",
    "_context_lines",
    "_check_aws_credentials_pair",
    "_check_secret_active",
    "_run_verification",
    "_is_git_repo",
    # Report
    "export_json",
    "export_html",
    "export_sarif",
    "_findings_vsl",
    # CLI
    "main",
    "parse_args",
    "_run_scan",
]
