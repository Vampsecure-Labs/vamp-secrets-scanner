# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Lógica de escaneo y funciones auxiliares
====================================================
VampSecure Labs · vamp-secrets-scanner
Contiene las funciones de escaneo, allowlist, baseline y herramientas CI.
Sin main(), parse_args() ni funciones de display Rich.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

from rich.console import Console

from ._models import (
    VERSION, TOOL_NAME,
    SECRET_PATTERNS, _RAW_PATTERNS,
    EXCLUDE_DIRS, INCLUDE_EXTENSIONS, INCLUDE_FILENAMES, BINARY_EXTENSIONS,
    Severity, _SEVERITY_ORDER, Finding,
)

_console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Motor de reglas YAML — carga patrones adicionales desde rules/*.yaml
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml_rules() -> list:
    """
    Carga reglas de detección adicionales desde el directorio rules/ del paquete.
    Requiere pyyaml (ya incluido en las dependencias).
    Falla silenciosamente si yaml no está disponible o un fichero es inválido.
    """
    try:
        import yaml  # noqa: F401 — comprobamos disponibilidad
    except ImportError:
        return []
    import yaml as _yaml
    rules_dir = Path(__file__).parent / "rules"
    if not rules_dir.exists():
        return []
    loaded: list = []
    for yf in sorted(rules_dir.glob("*.yaml")):
        try:
            data = _yaml.safe_load(yf.read_text(encoding="utf-8")) or {}
            for r in data.get("rules", []):
                if not r.get("regex") or not r.get("name"):
                    continue
                try:
                    loaded.append({
                        "name":     r["name"],
                        "severity": r.get("severity", "MEDIUM"),
                        "category": r.get("category", "Externo"),
                        "regex":    r["regex"],
                        "compiled": re.compile(r["regex"], re.MULTILINE),
                    })
                except re.error:
                    pass
        except Exception:
            pass
    return loaded


_YAML_PATTERNS: list = _load_yaml_rules()
ALL_PATTERNS: list = SECRET_PATTERNS + _YAML_PATTERNS
_ALL_RAW: list = _RAW_PATTERNS + [
    {k: v for k, v in p.items() if k != "compiled"} for p in _YAML_PATTERNS
]

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
        if b"\x00" in raw[:8192]:
            return []
        text = raw.decode("utf-8", errors="replace")
    except (PermissionError, OSError):
        return []

    lines   = text.splitlines()
    findings: List[Finding] = []
    seen_fps: Set[str] = set()

    for pat in ALL_PATTERNS:
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

    _ENTROPY_RE = re.compile(
        r"""(?:=|:|:=)\s*['"]?([A-Za-z0-9+/=\-_.~]{20,})['"]?""",
        re.MULTILINE,
    )
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
    """Escanea el historial completo de git buscando secretos en las líneas añadidas."""
    if not _is_git_repo(repo_path):
        return []

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

    FILE_RE   = re.compile(r"^\+\+\+ b/(.+)$")
    ADDED_RE  = re.compile(r"^\+(?!\+\+)(.*)$")
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

        diff_result = subprocess.run(
            ["git", "show", "--no-notes", "--format=", "-U0", commit_hash],
            cwd=repo_path, capture_output=True, text=True, errors="replace",
        )
        if diff_result.returncode != 0:
            continue

        current_file = ""
        current_line = 0

        for diff_line in diff_result.stdout.splitlines():
            m_file = FILE_RE.match(diff_line)
            if m_file:
                current_file = m_file.group(1)
                continue

            m_lineno = LINENO_RE.match(diff_line)
            if m_lineno:
                current_line = int(m_lineno.group(1)) - 1
                continue

            m_added = ADDED_RE.match(diff_line)
            if not m_added:
                continue

            line_content = m_added.group(1)
            current_line += 1

            for pat in ALL_PATTERNS:
                for m in pat["compiled"].finditer(line_content):
                    value = m.group(0)
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
    """Analiza ficheros de configuración de HashiCorp Vault buscando misconfiguraciones."""
    findings: List[Finding] = []

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

    _PKI_CAP_RE        = re.compile(r'path\s+"pki/[^"]*"\s*\{[^}]*capabilities\s*=\s*\[([^\]]+)\]', re.DOTALL)
    _ALLOWED_DOM_RE    = re.compile(r'allowed_domains\s*=')
    _AUDIT_BLOCK_RE    = re.compile(r'audit\s*\{[^}]*type\s*=\s*"file"', re.DOTALL)
    _SKIP_VERIFY_RE    = re.compile(r'(?i)(VAULT_SKIP_VERIFY\s*=\s*true|vault_skip_verify\s*:\s*true)')
    _UNSEAL_KEY_RE     = re.compile(r'(?i)unseal_key_\d+\s*:\s*[A-Za-z0-9+/=]{40,}')
    _ROOT_TOKEN_RE     = re.compile(r'Initial Root Token:\s+s\.[a-zA-Z0-9]+')
    _LONG_TTL_RE       = re.compile(r'(?i)(?:max_)?ttl\s*=\s*"?(\d+)h"?')

    hcl_files    = [f for f in candidatos if f.suffix.lower() == ".hcl"]
    all_files    = candidatos

    for hcl_file in hcl_files:
        try:
            contenido = hcl_file.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue

        for m in _PKI_CAP_RE.finditer(contenido):
            caps_raw = m.group(1)
            if '"*"' not in caps_raw and "'*'" not in caps_raw:
                continue
            bloque_inicio = m.start()
            bloque_fin    = m.end()
            segmento      = contenido[max(0, bloque_inicio - 200): bloque_fin + 500]
            if _ALLOWED_DOM_RE.search(segmento):
                continue
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

    if hcl_files:
        tiene_audit = any(
            _AUDIT_BLOCK_RE.search(
                f.read_text(encoding="utf-8", errors="replace")
            )
            for f in hcl_files
            if f.is_file()
        )
        if not tiene_audit:
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
# Allowlist
# ─────────────────────────────────────────────────────────────────────────────

def load_allowlist(path: str) -> List[dict]:
    """Carga una allowlist desde un fichero JSON."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("allowlist", [])
    except (OSError, json.JSONDecodeError) as exc:
        _console.print(f"[yellow]  Aviso: no se pudo leer la allowlist '{path}': {exc}[/]")
        return []


def apply_allowlist(findings: List[Finding], allowlist: List[dict]) -> List[Finding]:
    """Marca como allowlisted=True los hallazgos que coincidan con alguna entrada."""
    if not allowlist:
        return findings

    def _matches(f: Finding, entry: dict) -> bool:
        if "fingerprint" in entry:
            return f.fingerprint == entry["fingerprint"]
        pattern_ok = True
        if "pattern" in entry:
            pat = entry["pattern"]
            if pat.endswith("*"):
                pattern_ok = f.pattern.startswith(pat[:-1])
            else:
                pattern_ok = f.pattern == pat
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
    """Genera un fichero allowlist JSON a partir de los hallazgos actuales."""
    entries = [{"fingerprint": f.fingerprint, "pattern": f.pattern, "file": f.file}
               for f in findings]
    out = {
        "_generado_por": f"{TOOL_NAME} v{VERSION}",
        "_fecha": datetime.now(timezone.utc).isoformat(),
        "_nota": "Edita esta allowlist para suprimir falsos positivos conocidos.",
        "allowlist": entries,
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    _console.print(f"[green]  ✔ Allowlist generada en {path} ({len(entries)} entradas)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Baseline
# ─────────────────────────────────────────────────────────────────────────────

def load_baseline(path: str) -> List[dict]:
    """Carga el baseline de hallazgos aceptados desde un fichero JSON."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("accepted", [])
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as exc:
        _console.print(f"[yellow]  Aviso: no se pudo leer el baseline '{path}': {exc}[/]")
        return []


def apply_baseline(findings: List[Finding], accepted: List[dict]) -> List[Finding]:
    """Marca como allowlisted=True los hallazgos cuyo fingerprint de contexto aparezca en el baseline."""
    if not accepted:
        return findings
    baseline_fps = {e["fingerprint"] for e in accepted if "fingerprint" in e}
    for f in findings:
        bf = _baseline_fingerprint(f.file, f.line_no, f.pattern)
        if bf in baseline_fps:
            f.allowlisted = True
    return findings


def update_baseline(findings: List[Finding], path: str, reason: str = "") -> None:
    """Añade todos los hallazgos de la lista al baseline."""
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
            "fingerprint SHA-256 del contexto (fichero+línea+patrón)."
        ),
        "accepted": existing,
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    _console.print(
        f"[green]  ✔ Baseline actualizado: {nuevos} nuevas entradas "
        f"({len(existing)} total) → {path}[/]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Docker runtime scanning
# ─────────────────────────────────────────────────────────────────────────────

def _docker_disponible() -> bool:
    import shutil as _shutil
    return _shutil.which("docker") is not None


def _obtener_envs_contenedor(container_id: str) -> Optional[List[str]]:
    envs: List[str] = []
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_id],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            envs = [l for l in result.stdout.splitlines() if l.strip() and "=" in l]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    if not envs:
        try:
            result = subprocess.run(
                ["docker", "exec", container_id, "env"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                envs = [l for l in result.stdout.splitlines() if l.strip() and "=" in l]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return envs if envs else None


def scan_docker_container(container_id: str) -> List[Finding]:
    """Escanea las variables de entorno de un contenedor Docker en ejecución."""
    if not _docker_disponible():
        _console.print("[yellow]  Aviso: 'docker' no encontrado en PATH — omitiendo escaneo de contenedor[/]")
        return []

    _console.print(f"[cyan]  Escaneando contenedor Docker: {container_id}[/]")

    envs = _obtener_envs_contenedor(container_id)
    if envs is None:
        _console.print(f"[yellow]  Aviso: no se pudieron obtener variables de entorno del contenedor '{container_id}'[/]")
        return []

    hallazgos: List[Finding] = []

    for linea in envs:
        if not linea.strip() or "=" not in linea:
            continue
        for pat in ALL_PATTERNS:
            match = pat["compiled"].search(linea)
            if not match:
                continue
            valor_raw  = match.group(0)
            extracto   = _censor(valor_raw)
            fp         = _fingerprint(valor_raw, "DOCKER_ENV_SECRET")
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
        _console.print(
            f"  [bold red]⚠ {len(hallazgos)} secreto(s) encontrado(s) en "
            f"variables de entorno de '{container_id}'[/]"
        )
    else:
        _console.print(f"  [green]✔ Sin secretos detectados en las envs de '{container_id}'[/]")

    return hallazgos


def scan_all_docker_containers() -> List[Finding]:
    """Escanea los contenedores Docker actualmente en ejecución."""
    if not _docker_disponible():
        _console.print("[yellow]  Aviso: 'docker' no encontrado en PATH — omitiendo escaneo de contenedores[/]")
        return []

    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True, text=True, timeout=10,
        )
        ids = [i.strip() for i in result.stdout.splitlines() if i.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        _console.print(f"[red]  Error ejecutando 'docker ps': {exc}[/]")
        return []

    if not ids:
        _console.print("[yellow]  No hay contenedores Docker en ejecución.[/]")
        return []

    _console.print(f"[cyan]  Escaneando {len(ids)} contenedor(es) Docker en ejecución...[/]")
    todos_hallazgos: List[Finding] = []

    for cid in ids:
        todos_hallazgos.extend(scan_docker_container(cid))

    return todos_hallazgos


def _scan_string_for_secrets(texto: str) -> List[Dict]:
    """Aplica todos los SECRET_PATTERNS a una cadena y devuelve coincidencias brutas."""
    coincidencias: List[Dict] = []
    for pat in ALL_PATTERNS:
        match = pat["compiled"].search(texto)
        if match:
            coincidencias.append({
                "name":     pat["name"],
                "severity": pat["severity"],
                "category": pat.get("category", "Secret"),
                "valor":    match.group(0),
            })
    return coincidencias


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes Secrets scanning
# ─────────────────────────────────────────────────────────────────────────────

def _kubectl_disponible() -> bool:
    try:
        subprocess.run(
            ["kubectl", "version", "--client", "--output=json"],
            capture_output=True, timeout=5,
        )
        return True
    except (FileNotFoundError, OSError):
        return False


def scan_kubernetes_secrets(namespace: Optional[str] = None) -> List[Finding]:
    """Escanea los Kubernetes Secrets del clúster activo."""
    if not _kubectl_disponible():
        _console.print("[yellow]  Aviso: 'kubectl' no encontrado en PATH — omitiendo escaneo de K8s Secrets[/]")
        return []

    if namespace:
        cmd = ["kubectl", "get", "secret", "-n", namespace, "-o", "json"]
        scope_label = f"namespace '{namespace}'"
    else:
        cmd = ["kubectl", "get", "secret", "--all-namespaces", "-o", "json"]
        scope_label = "todos los namespaces"

    _console.print(f"[cyan]  Consultando Kubernetes Secrets ({scope_label})...[/]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        _console.print("[red]  Tiempo de espera agotado ejecutando 'kubectl get secret'[/]")
        return []
    except (FileNotFoundError, OSError) as exc:
        _console.print(f"[red]  Error ejecutando kubectl: {exc}[/]")
        return []

    if result.returncode != 0:
        _console.print(f"[red]  kubectl salió con código {result.returncode}: {result.stderr.strip()[:200]}[/]")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _console.print(f"[red]  Error parseando salida JSON de kubectl: {exc}[/]")
        return []

    items = data.get("items", [data]) if "items" in data else [data]
    hallazgos: List[Finding] = []

    for secret in items:
        meta = secret.get("metadata", {})
        ns   = meta.get("namespace", "default")
        name = meta.get("name", "desconocido")
        tipo = secret.get("type", "")
        datos = secret.get("data") or {}

        for clave, valor_b64 in datos.items():
            try:
                valor_decoded = base64.b64decode(valor_b64).decode("utf-8", errors="replace")
            except Exception:
                continue

            coincidencias = _scan_string_for_secrets(valor_decoded)
            _scan_string_for_secrets(clave)

            claves_sensibles = {"password", "passwd", "secret", "token", "key",
                                 "apikey", "api_key", "private_key", "auth"}
            es_clave_sensible = any(k in clave.lower() for k in claves_sensibles)

            if not coincidencias and es_clave_sensible:
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
        _console.print(f"[dim]  {len(hallazgos)} hallazgo(s) en Kubernetes Secrets[/]")
    else:
        _console.print("[dim]  Sin secretos detectados en Kubernetes Secrets[/]")

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Hook pre-commit
# ─────────────────────────────────────────────────────────────────────────────

def _install_pre_commit_hook(target: Path) -> None:
    """Instala un hook pre-commit de git en el repositorio objetivo."""
    git_dir = target / ".git"
    if not git_dir.is_dir():
        _console.print(f"[red]  ERROR: {target} no es un repositorio git (falta .git/).[/]")
        sys.exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    hook_script = """#!/usr/bin/env bash
# Hook pre-commit instalado por vamp-secrets-scanner
# © VampSecure Studios — VampSecure Labs Security Research Division
set -euo pipefail

TARGET="$(git rev-parse --show-toplevel 2>/dev/null || echo ".")"

echo "[vamp-secrets-scanner] Escaneando secretos antes del commit..."
ALLOWLIST_OPT=""
[ -f "$TARGET/.vamp-allowlist.json" ] && ALLOWLIST_OPT="--allowlist $TARGET/.vamp-allowlist.json"
python3 -m vamp_secrets_scanner "$TARGET" --min-severity MEDIUM $ALLOWLIST_OPT 2>&1
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
    _console.print(f"[bold green]  ✔ Hook pre-commit instalado: {hook_path}[/]")
    _console.print("[dim]  Cada commit escaneará el árbol de trabajo completo (MEDIUM+).[/]")
    _console.print(f"[dim]  Para desinstalar: rm {hook_path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Verificación activa de secretos (--verify)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_raw_value(finding: Finding) -> Optional[str]:
    """Re-lee el fichero fuente y extrae el valor raw del secreto."""
    if finding.git_commit:
        return None
    try:
        path = Path(finding.file)
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in ALL_PATTERNS:
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
    """Verifica un par de credenciales AWS mediante STS GetCallerIdentity."""
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
            if r.status == 200:
                return True
            if r.status == 403 and "InvalidClientTokenId" in body:
                return False
            if r.status == 403 and "SignatureDoesNotMatch" in body:
                return True
    except Exception:
        pass
    return None


async def _check_secret_active(session, category: str, value: str) -> Optional[bool]:
    """Verifica si un secreto sigue activo mediante una petición mínima al proveedor."""
    import base64 as _b64
    import re as _re
    try:
        UA = f"{TOOL_NAME}/{VERSION}"

        if "AWS" in category and _re.match(r"(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)", value):
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


async def _run_verification(findings: List[Finding]) -> None:
    """Verifica activamente los secretos CRITICAL/HIGH de los hallazgos."""
    import aiohttp as _aiohttp
    from collections import defaultdict as _dd

    VERIFICABLES = {"Cloud · AWS", "VCS · GitHub", "Pagos · Stripe",
                    "Comunicaciones · Slack", "Comunicaciones · Telegram"}

    candidatos = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
        and any(cat in f.category for cat in VERIFICABLES)
        and not f.git_commit
    ]

    if not candidatos:
        _console.print("[dim]  --verify: no hay hallazgos verificables.[/]")
        return

    _console.print(f"\n[bold cyan]  FASE EXTRA — Verificación activa ({len(candidatos)} secretos)[/]\n")

    activos = revocados = sin_datos = 0

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
        for filepath, entry in aws_por_fichero.items():
            if not (entry["key_id"] and entry["secret"]):
                for fnd in (entry["key_finding"], entry["secret_finding"]):
                    if fnd:
                        sin_datos += 1
                        _console.print(
                            f"  [dim]? indeterminado[/] {fnd.pattern} — AWS key sin secreto parejado "
                            f"en {fnd.file}:{fnd.line_no}"
                        )
                continue

            status = await _check_aws_credentials_pair(session, entry["key_id"], entry["secret"])
            key_preview = entry["key_id"][:8] + "…"
            label = f"AWS key pair [{key_preview}] — {filepath}"

            if status is True:
                activos += 1
                _console.print(f"  [bold red]✖ ACTIVO[/]   {label}")
            elif status is False:
                revocados += 1
                _console.print(f"  [green]✔ revocado[/] {label}")
            else:
                sin_datos += 1
                _console.print(f"  [dim]? indeterminado[/] {label}")

        for finding in candidatos:
            if id(finding) in aws_ids:
                continue
            raw = _extract_raw_value(finding)
            if not raw:
                sin_datos += 1
                _console.print(f"  [dim]? {finding.pattern} en {finding.file}:{finding.line_no} — valor no recuperable[/]")
                continue

            status = await _check_secret_active(session, finding.category, raw)
            preview = raw[:6] + "…" + raw[-3:] if len(raw) > 10 else raw[:3] + "…"

            if status is True:
                activos += 1
                _console.print(
                    f"  [bold red]✖ ACTIVO[/]   {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )
            elif status is False:
                revocados += 1
                _console.print(
                    f"  [green]✔ revocado[/] {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )
            else:
                sin_datos += 1
                _console.print(
                    f"  [dim]? indeterminado[/] {finding.pattern} [{preview}] "
                    f"— {finding.file}:{finding.line_no}"
                )

    estilo = "bold red" if activos > 0 else "bold green"
    _console.print(
        f"\n  [{estilo}]Verificación: {activos} activos · {revocados} revocados · {sin_datos} sin datos[/]"
    )
    if activos:
        _console.print(
            "  [bold red]⚠ ACCIÓN URGENTE: rota inmediatamente los secretos activos listados.[/]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Exportación Semgrep
# ─────────────────────────────────────────────────────────────────────────────

def _export_semgrep_rules(output_file: str) -> None:
    """Exporta todos los patrones del escáner como reglas Semgrep YAML."""
    SEV_MAP = {"CRITICAL": "ERROR", "HIGH": "WARNING", "MEDIUM": "WARNING", "LOW": "INFO"}

    def _slug(name: str) -> str:
        import re as _re
        return _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

    lines = [
        "# Reglas Semgrep generadas automáticamente por vamp-secrets-scanner",
        "# © VampSecure Studios — VampSecure Labs Security Research Division",
        "# Uso: semgrep --config <este-fichero> <directorio-objetivo>",
        "",
        "rules:",
    ]

    for pat in _ALL_RAW:
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
    _console.print(f"[bold green]  ✔ {len(_ALL_RAW)} reglas Semgrep exportadas → {output_file}[/]")
    _console.print(f"[dim]  Ejecutar: semgrep --config {output_file} <directorio>[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Daemon mode y scan helper
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(args) -> List[Finding]:
    """Ejecuta todas las fases de escaneo y devuelve findings únicos filtrados."""
    import io
    import contextlib

    target = Path(args.target).resolve()
    min_sev = Severity.CRITICAL if args.only_critical else Severity(args.min_severity)
    entropy_threshold = float("inf") if args.no_entropy else args.entropy_threshold

    all_findings: List[Finding] = []

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


def apply_delta_scan(
    findings: List[Finding], delta_path: str
) -> "tuple[List[Finding], List[dict]]":
    """Compara hallazgos actuales con un informe JSON previo."""
    try:
        baseline_data = json.loads(Path(delta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se puede leer el delta baseline '{delta_path}': {exc}") from exc
    baseline_fps = {f["fingerprint"] for f in baseline_data.get("findings", []) if "fingerprint" in f}
    for f in findings:
        f.delta_state = "recurring" if f.fingerprint in baseline_fps else "new"
    current_fps = {f.fingerprint for f in findings}
    resolved = [
        f for f in baseline_data.get("findings", [])
        if f.get("fingerprint") not in current_fps
    ]
    return findings, resolved


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
