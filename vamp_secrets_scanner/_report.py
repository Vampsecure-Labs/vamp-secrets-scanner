# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Serialización y exportación de informes
=====================================================
VampSecure Labs · vamp-secrets-scanner
Contiene export_json, export_html, export_sarif y _findings_vsl.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Dict, List

from rich.console import Console

from ._models import VERSION, TOOL_NAME, Severity, _SEVERITY_ORDER, Finding

_console = Console()

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
    _console.print(f"[dim]  JSON → {path}[/]")


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
    _console.print(f"[dim]  HTML → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Exportación SARIF 2.1.0
# ─────────────────────────────────────────────────────────────────────────────

def export_sarif(findings: List[Finding], target: str, path: str) -> None:
    """Exporta hallazgos en formato SARIF 2.1.0."""
    _SEV_TO_SARIF = {
        "CRITICAL": ("error",   9.5),
        "HIGH":     ("error",   7.5),
        "MEDIUM":   ("warning", 5.0),
        "LOW":      ("note",    2.0),
    }

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

    results = []
    target_uri = Path(target).as_uri()
    for f in findings:
        if f.allowlisted:
            continue
        rule_id = re.sub(r"[^A-Za-z0-9\-_]", "-", f.pattern)[:64]
        level, _ = _SEV_TO_SARIF.get(f.severity.value, ("note", 2.0))
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
                    "informationUri": "https://github.com/Vampsecure-Labs/vamp-secrets-scanner",
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
    _console.print(f"[dim]  SARIF → {path} ({len(results)} resultados)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Conversor al formato de informe unificado VSL
# ─────────────────────────────────────────────────────────────────────────────

def _findings_vsl(findings: List[Finding], target: str) -> list:
    """Convierte hallazgos de secretos al formato Finding unificado de VampSecure Labs."""
    from vampsec_report import Finding as VSLFinding

    SEVERIDADES_INCLUIDAS = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos: list = []
    n = 0

    for f in findings:
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev_val not in SEVERIDADES_INCLUIDAS:
            continue
        n += 1

        try:
            ruta_relativa = str(Path(f.file).relative_to(target))
        except ValueError:
            ruta_relativa = f.file

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
