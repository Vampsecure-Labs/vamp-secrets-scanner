# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Interfaz de línea de comandos y display Rich
======================================================
VampSecure Labs · vamp-secrets-scanner
Contiene parse_args(), main(), display functions y BANNER.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._models import VERSION, Severity, _SEVERITY_ORDER, Finding, t
import vamp_secrets_scanner._models as _models
from ._core import (
    discover_files, scan_file, _is_git_repo, scan_git_history,
    scan_vault_misconfig, load_allowlist, apply_allowlist, generate_allowlist,
    load_baseline, apply_baseline, update_baseline,
    scan_docker_container, scan_all_docker_containers,
    scan_kubernetes_secrets,
    _install_pre_commit_hook, _export_semgrep_rules,
    _run_verification, apply_delta_scan, _daemon_loop,
    EXCLUDE_DIRS,
)
from ._report import export_json, export_html, export_sarif, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-secrets-scanner v3.2.0 · Static Secrets & Git History Scanner
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

SEVERITY_COLOR: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
}

_SEV_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
}

def _sev_icon(sev: Severity) -> str:
    return {
        Severity.CRITICAL: t("🔴 CRITICAL", "🔴 CRÍTICO"),
        Severity.HIGH:     t("🟠 HIGH",     "🟠 ALTO"),
        Severity.MEDIUM:   t("🟡 MEDIUM",   "🟡 MEDIO"),
        Severity.LOW:      t("🔵 LOW",      "🔵 BAJO"),
    }[sev]


def build_results_table(findings: List[Finding], base: Path) -> Table:
    table = Table(
        title=t("Results — Secrets Scanner", "Resultados — Secrets Scanner"),
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
    )
    table.add_column(t("Severity",  "Severidad"),  no_wrap=True, max_width=14)
    table.add_column(t("File",      "Fichero"),    style="white",       no_wrap=True, max_width=50)
    table.add_column(t("Line",      "Línea"),      style="cyan",        no_wrap=True, max_width=6, justify="right")
    table.add_column(t("Pattern",   "Patrón"),     style="white",       no_wrap=True, max_width=32)
    table.add_column(t("Category",  "Categoría"),  style="bright_black", no_wrap=True, max_width=24)
    table.add_column(t("Excerpt",   "Extracto"),   style="yellow",      no_wrap=True, max_width=22)

    for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER[x.severity], x.file, x.line_no)):
        sty   = _SEV_STYLE[f.severity]
        label = _sev_icon(f.severity)
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
    console.print(t(
        "[bold red]── CRITICAL FINDINGS ──────────────────────────────────────────────────────[/]",
        "[bold red]── HALLAZGOS CRÍTICOS ──────────────────────────────────────────────────────[/]",
    ))
    for f in crits:
        try:
            rel = Path(f.file).relative_to(base)
        except ValueError:
            rel = Path(f.file)
        ctx = "\n".join(f.context)
        body = (
            f"[bold white]{t('File:', 'Fichero:')}[/]   {markup_escape(str(rel))}:{f.line_no}\n"
            f"[bold white]{t('Pattern:', 'Patrón:')}[/]    {markup_escape(f.pattern)}\n"
            f"[bold white]{t('Category:', 'Categoría:')}[/] {markup_escape(f.category)}\n"
            f"[bold white]{t('Excerpt:', 'Extracto:')}[/]  [yellow]{markup_escape(f.preview)}[/]\n\n"
            f"[dim]{markup_escape(ctx)}[/]"
        )
        console.print(Panel(body,
            title=f"[bold red]⚠ {t('CRITICAL', 'CRÍTICO')}: {f.pattern}[/]",
            border_style="red"))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vamp-secrets-scanner",
        description="VampSecure Labs — Static Secrets, PII & Git History Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Scan current directory\n"
            "  python -m vamp_secrets_scanner .\n\n"
            "  # Scan repo including full git history\n"
            "  python -m vamp_secrets_scanner /path/to/repo --git-history\n\n"
            "  # Only criticals and highs, export SARIF for GitHub Actions\n"
            "  python -m vamp_secrets_scanner . --min-severity HIGH --sarif results.sarif\n"
        ),
    )
    p.add_argument("target",
                   metavar="DIRECTORY",
                   help="Root directory to scan")
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",       metavar="FILE",
                     help="Export findings to JSON")
    out.add_argument("--html",               metavar="FILE",
                     help="Export dark-theme HTML report")
    out.add_argument("--sarif",              metavar="FILE",
                     help="Export results in SARIF 2.1.0 format")
    out.add_argument("--min-severity",
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     default="LOW",
                     help="Minimum severity to report (default: LOW)")
    out.add_argument("--only-critical",      action="store_true",
                     help="Show only CRITICAL findings")
    out.add_argument("--lang",               choices=["en", "es"], default="en",
                     help="Output language (default: en)")
    fil = p.add_argument_group("Filters")
    fil.add_argument("--all-extensions",     action="store_true",
                     help="Scan all non-binary files")
    fil.add_argument("--max-depth",          type=int, metavar="N",
                     help="Maximum recursion depth")
    fil.add_argument("--no-entropy",         action="store_true",
                     help="Disable Shannon entropy analysis")
    fil.add_argument("--entropy-threshold",  type=float, default=4.5, metavar="BITS",
                     help="Entropy threshold in bits/symbol (default: 4.5)")
    fil.add_argument("--exclude-dir",        action="append", default=[], metavar="DIR",
                     help="Additional directories to exclude (repeatable)")
    git = p.add_argument_group("Git History")
    git.add_argument("--git-history",        action="store_true",
                     help="Scan full git commit history")
    git.add_argument("--max-commits",        type=int, default=0, metavar="N",
                     help="Limit history scan to the N most recent commits")
    al = p.add_argument_group("Allowlist")
    al.add_argument("--allowlist",           metavar="FILE",
                    help="JSON file with false positives to ignore")
    al.add_argument("--generate-allowlist",  metavar="FILE",
                    help="Generate allowlist JSON from current findings and exit")

    bl = p.add_argument_group("Baseline")
    bl.add_argument("--baseline", metavar="FILE",
                    help="JSON baseline file with accepted findings")
    bl.add_argument("--update-baseline", action="store_true",
                    help="Add all current findings to the baseline and exit with code 0")

    docker = p.add_argument_group("Docker Runtime Scan")
    docker.add_argument("--scan-container",  metavar="NAME_OR_ID",
                        dest="scan_container", default=None,
                        help="Scan environment variables of a running Docker container")
    docker.add_argument("--scan-all-containers", action="store_true",
                        dest="scan_all_containers",
                        help="Scan all currently running Docker containers")

    k8s = p.add_argument_group("Kubernetes Secrets Scan")
    k8s.add_argument("--k8s", action="store_true",
                     dest="k8s",
                     help="Scan Kubernetes Secrets from the active cluster")
    k8s.add_argument("--k8s-namespace", metavar="NS",
                     dest="k8s_namespace", default=None,
                     help="Limit K8s Secrets scan to a specific namespace")

    ci = p.add_argument_group("CI/CD Integration")
    ci.add_argument("--install-hook",        action="store_true",
                    help="Install git pre-commit hook in the target directory and exit")
    ci.add_argument("--export-semgrep",      metavar="FILE",
                    help="Export patterns as Semgrep YAML rules and exit")
    ci.add_argument("--verify",              action="store_true",
                    help="Actively verify whether found CRITICAL/HIGH secrets are still valid")
    ci.add_argument(
        "--watch", type=int, metavar="SECONDS",
        help="Daemon mode: re-scan every N seconds",
    )
    ci.add_argument(
        "--delta", metavar="FILE",
        help="Delta scan: compare against a previous JSON report",
    )

    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


def main() -> None:
    console.print(BANNER, style="bold magenta")

    args   = parse_args()
    _models.LANG = getattr(args, "lang", "en")
    target = Path(args.target).resolve()

    if getattr(args, "watch", None) is not None:
        _daemon_loop(args, args.watch)
        return

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

    for d in args.exclude_dir:
        EXCLUDE_DIRS.add(d)

    min_sev = Severity.CRITICAL if args.only_critical else Severity(args.min_severity)
    entropy_threshold = float("inf") if args.no_entropy else args.entropy_threshold

    console.print(f"  {t('Target:', 'Objetivo:')} [cyan]{target}[/]")
    if args.git_history:
        console.print(t(
            "  Mode: [bold yellow]current tree + git history[/]"
            + (f" (last {args.max_commits} commits)" if args.max_commits else ""),
            "  Modo: [bold yellow]árbol actual + historial git[/]"
            + (f" (últimos {args.max_commits} commits)" if args.max_commits else ""),
        ))
    console.print()

    all_findings: List[Finding] = []

    # ── Phase 1: discover files ───────────────────────────────────────────────
    console.print(t(
        "[bold cyan]  PHASE 1[/] — Discovering in-scope files...",
        "[bold cyan]  FASE 1[/] — Descubriendo ficheros en alcance...",
    ))
    files = list(discover_files(target, args.max_depth, args.all_extensions))
    total_bytes = sum(f.stat().st_size for f in files if f.exists())
    console.print(t(
        f"[dim]  {len(files)} files · {total_bytes / 1024:.1f} KB in scope[/]\n",
        f"[dim]  {len(files)} ficheros · {total_bytes / 1024:.1f} KB en alcance[/]\n",
    ))

    # ── Phase 2a: file scanning ───────────────────────────────────────────────
    console.print(t(
        "[bold cyan]  PHASE 2[/] — Scanning patterns and entropy (current tree)...",
        "[bold cyan]  FASE 2[/] — Escaneando patrones y entropía (árbol actual)...",
    ))
    with console.status(t("[bold green]Analysing files...[/]", "[bold green]Analizando ficheros...[/]"), spinner="dots"):
        for f in files:
            all_findings.extend(scan_file(f, entropy_threshold))

    # ── Phase 2b: git history scan (optional) ────────────────────────────────
    if args.git_history:
        if _is_git_repo(target):
            console.print(t(
                "[bold cyan]  PHASE 2b[/] — Scanning git history...",
                "[bold cyan]  FASE 2b[/] — Escaneando historial git...",
            ))
            with console.status(t("[bold green]Analysing commits...[/]", "[bold green]Analizando commits...[/]"), spinner="dots"):
                git_findings = scan_git_history(target, entropy_threshold, args.max_commits)
            console.print(t(
                f"[dim]  {len(git_findings)} findings in git history[/]\n",
                f"[dim]  {len(git_findings)} hallazgos en historial git[/]\n",
            ))
            all_findings.extend(git_findings)
        else:
            console.print(t(
                "[yellow]  Warning: --git-history requested but directory is not a git repo[/]\n",
                "[yellow]  Aviso: --git-history solicitado pero el directorio no es un repo git[/]\n",
            ))

    # ── Phase 2c: Vault misconfiguration analysis ─────────────────────────────
    console.print(t(
        "[bold cyan]  PHASE 2c[/] — Analysing Vault misconfigurations (CVE-2026-5052)...",
        "[bold cyan]  FASE 2c[/] — Analizando misconfiguraciones Vault (CVE-2026-5052)...",
    ))
    vault_findings = scan_vault_misconfig(target)
    if vault_findings:
        console.print(t(
            f"[dim]  {len(vault_findings)} Vault misconfiguration finding(s)[/]\n",
            f"[dim]  {len(vault_findings)} hallazgos de misconfiguración Vault[/]\n",
        ))
    else:
        console.print(t(
            "[dim]  No Vault misconfigurations detected[/]\n",
            "[dim]  Sin misconfiguraciones Vault detectadas[/]\n",
        ))
    all_findings.extend(vault_findings)

    # ── Phase 2d: Docker runtime container scan ───────────────────────────────
    _contenedor_a_escanear = getattr(args, "scan_container", None)
    _escanear_todos        = getattr(args, "scan_all_containers", False)

    if _contenedor_a_escanear:
        console.print(t(
            "[bold cyan]  PHASE 2d[/] — Scanning Docker container at runtime...",
            "[bold cyan]  FASE 2d[/] — Escaneando contenedor Docker en runtime...",
        ))
        docker_findings = scan_docker_container(_contenedor_a_escanear)
        if docker_findings:
            console.print(t(
                f"[dim]  {len(docker_findings)} finding(s) in environment variables "
                f"of container '{_contenedor_a_escanear}'[/]\n",
                f"[dim]  {len(docker_findings)} hallazgo(s) en variables de entorno "
                f"del contenedor '{_contenedor_a_escanear}'[/]\n",
            ))
        else:
            console.print(t(
                "[dim]  No secrets detected in the specified container[/]\n",
                "[dim]  Sin secretos detectados en el contenedor indicado[/]\n",
            ))
        all_findings.extend(docker_findings)

    elif _escanear_todos:
        console.print(t(
            "[bold cyan]  PHASE 2d[/] — Scanning all running Docker containers...",
            "[bold cyan]  FASE 2d[/] — Escaneando todos los contenedores Docker en ejecución...",
        ))
        docker_findings = scan_all_docker_containers()
        if docker_findings:
            console.print(t(
                f"[dim]  {len(docker_findings)} finding(s) in Docker container environment variables[/]\n",
                f"[dim]  {len(docker_findings)} hallazgo(s) en variables de entorno de contenedores Docker[/]\n",
            ))
        else:
            console.print(t(
                "[dim]  No secrets detected in running containers[/]\n",
                "[dim]  Sin secretos detectados en los contenedores en ejecución[/]\n",
            ))
        all_findings.extend(docker_findings)

    # ── Phase 2e: Kubernetes Secrets scan ────────────────────────────────────
    _k8s_ns = getattr(args, "k8s_namespace", None)
    _k8s    = getattr(args, "k8s", False) or bool(_k8s_ns)

    if _k8s:
        console.print(t(
            "[bold cyan]  PHASE 2e[/] — Scanning Kubernetes Secrets...",
            "[bold cyan]  FASE 2e[/] — Escaneando Kubernetes Secrets...",
        ))
        k8s_findings = scan_kubernetes_secrets(namespace=_k8s_ns)
        if k8s_findings:
            console.print(t(
                f"[dim]  {len(k8s_findings)} finding(s) in Kubernetes Secrets[/]\n",
                f"[dim]  {len(k8s_findings)} hallazgo(s) en Kubernetes Secrets[/]\n",
            ))
        else:
            console.print(t(
                "[dim]  No secrets detected in Kubernetes Secrets[/]\n",
                "[dim]  Sin secretos detectados en Kubernetes Secrets[/]\n",
            ))
        all_findings.extend(k8s_findings)

    # ── Deduplicación y filtrado ──────────────────────────────────────────────
    from typing import Set
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
            console.print(t(
                f"[dim]  {n_suppressed} finding(s) suppressed by allowlist[/]",
                f"[dim]  {n_suppressed} hallazgos suprimidos por la allowlist[/]",
            ))

    # ── Filtrar por severidad y allowlist ─────────────────────────────────────
    filtered = [
        f for f in unique
        if _SEVERITY_ORDER[f.severity] <= _SEVERITY_ORDER[min_sev]
        and not f.allowlisted
    ]

    console.print(t(
        f"[dim]  {len(unique)} unique findings · {len(filtered)} after severity filter[/]\n",
        f"[dim]  {len(unique)} hallazgos únicos · {len(filtered)} tras filtro de severidad[/]\n",
    ))

    # ── Generar allowlist baseline ────────────────────────────────────────────
    if args.generate_allowlist:
        generate_allowlist(filtered, args.generate_allowlist)
        console.print(t(
            "[dim]  Use --allowlist with that file to suppress findings in future runs.[/]",
            "[dim]  Usa --allowlist con ese fichero para suprimir los hallazgos en próximas ejecuciones.[/]",
        ))
        sys.exit(0)

    # ── Baseline — filtrar hallazgos ya aceptados ─────────────────────────────
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
                console.print(t(
                    f"[dim]  {_n_bl} finding(s) suppressed by baseline ({_baseline_path})[/]",
                    f"[dim]  {_n_bl} hallazgo(s) suprimido(s) por el baseline ({_baseline_path})[/]",
                ))
            filtered = [f for f in filtered if not f.allowlisted]

    # ── Actualizar baseline (--update-baseline) ───────────────────────────────
    if getattr(args, "update_baseline", False):
        _bp_dest = _baseline_path or str(target / ".vamp-secrets-baseline.json")
        update_baseline(filtered, _bp_dest)
        console.print(t(
            "[dim]  Future runs will ignore these findings. Use --baseline to apply the filter.[/]",
            "[dim]  Próximas ejecuciones ignorarán estos hallazgos. Usa --baseline para aplicar el filtro.[/]",
        ))
        sys.exit(0)

    # ── Delta scan (--delta) ─────────────────────────────────────────────────
    delta_resolved: List[dict] = []
    if getattr(args, "delta", None):
        try:
            filtered, delta_resolved = apply_delta_scan(filtered, args.delta)
            n_new = sum(1 for f in filtered if f.delta_state == "new")
            n_rec = sum(1 for f in filtered if f.delta_state == "recurring")
            console.print(
                f"[bold cyan]  DELTA vs {args.delta}:[/] "
                f"[bold green]{n_new} NEW[/] · [yellow]{n_rec} RECURRING[/] · "
                f"[dim]{len(delta_resolved)} RESOLVED[/]"
            )
        except ValueError as exc:
            console.print(f"[bold red]  [!] Delta error: {exc}[/]")

    # ── Mostrar resultados ────────────────────────────────────────────────────
    if not filtered:
        console.print(t(
            "[bold green]  ✓ No findings in the selected severity range.[/]",
            "[bold green]  ✓ Sin hallazgos en el rango de severidad seleccionado.[/]",
        ))
    else:
        console.print(build_results_table(filtered, target))
        print_critical_panels(filtered, target)

    # ── Mostrar RESOLVED si hay delta ─────────────────────────────────────────
    if delta_resolved:
        console.print("\n[bold green]  ✅ RESUELTOS desde el baseline:[/]")
        for r in delta_resolved:
            sev = r.get("severity", "").upper()
            pat = r.get("pattern", "?")
            loc = f"{r.get('file', '?')}:{r.get('line_no', '?')}"
            console.print(f"[dim]    [-RESOLVED] [{sev:8s}] {pat}: {loc}[/]")

    # ── Resumen ───────────────────────────────────────────────────────────────
    n_crit = sum(1 for f in filtered if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in filtered if f.severity == Severity.HIGH)
    n_med  = sum(1 for f in filtered if f.severity == Severity.MEDIUM)
    n_low  = sum(1 for f in filtered if f.severity == Severity.LOW)
    n_git  = sum(1 for f in filtered if f.git_commit)

    sev_style = "bold red" if n_crit > 0 else ("bold yellow" if n_high > 0 else "bold green")
    resumen = (
        f"\n[{sev_style}]  {t('SUMMARY', 'RESUMEN')}: {len(filtered)} {t('findings', 'hallazgos')} · "
        f"{n_crit} {t('CRITICAL', 'CRÍTICO')} · {n_high} {t('HIGH', 'ALTO')} · "
        f"{n_med} {t('MEDIUM', 'MEDIO')} · {n_low} {t('LOW', 'BAJO')}"
    )
    if n_git:
        resumen += f" · {n_git} {t('in git history', 'en historial git')}"
    if getattr(args, "delta", None) and delta_resolved is not None:
        resumen += f" · {len(delta_resolved)} RESOLVED"
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
            console.print(t(
                f"[bold green]  ✔ Client HTML report saved: {args.report_html}[/]",
                f"[bold green]  ✔ Informe cliente HTML guardado: {args.report_html}[/]",
            ))
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(t(
                f"[bold green]  ✔ Client PDF report saved: {args.report_pdf}[/]",
                f"[bold green]  ✔ Informe cliente PDF guardado: {args.report_pdf}[/]",
            ))

    # Exit codes útiles en CI/CD
    if n_crit > 0:
        sys.exit(2)
    elif n_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(t(
            "\n[dim]  Scan interrupted by user.[/]",
            "\n[dim]  Escaneo interrumpido por el usuario.[/]",
        ))
        sys.exit(130)
