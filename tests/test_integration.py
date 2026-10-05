# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_secrets_scanner
=====================================================================
Ejercita el scanner completo contra ficheros temporales con secretos reales
de formato conocido y verifica que los hallazgos generados son correctos.
"""

import json


from vamp_secrets_scanner import (
    scan_file,
    discover_files,
    Severity,
    export_json,
)


# ---------------------------------------------------------------------------
# Tests de integración (5 mínimos)
# ---------------------------------------------------------------------------

class TestIntegracionScanner:
    """Integración end-to-end del scanner contra ficheros reales."""

    def test_detecta_aws_key_en_fichero_real(self, tmp_path):
        """
        Crea fichero con AWS key falsa y verifica que scan_file retorna
        un hallazgo CRITICAL con el patrón correcto.
        """
        f = tmp_path / "config.py"
        f.write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
            encoding="utf-8",
        )
        hallazgos = scan_file(f, entropy_threshold=4.5)

        ids_criticos = [h for h in hallazgos if h.severity == Severity.CRITICAL]
        assert len(ids_criticos) >= 1, "Se esperaba al menos un hallazgo CRITICAL"

        patrones_encontrados = {h.pattern for h in hallazgos}
        assert "AWS Access Key ID" in patrones_encontrados, (
            "No se detectó el patrón 'AWS Access Key ID'"
        )

    def test_detecta_github_token_en_fichero(self, tmp_path):
        """GitHub PAT real en fichero debe generar hallazgo HIGH."""
        f = tmp_path / "deploy.sh"
        # Token con formato correcto: ghp_ + 36 alfanuméricos
        token = "ghp_" + "A" * 36
        f.write_text(f'export GITHUB_TOKEN="{token}"\n', encoding="utf-8")
        hallazgos = scan_file(f, entropy_threshold=4.5)
        patrones = {h.pattern for h in hallazgos}
        assert "GitHub PAT (classic)" in patrones, "No detectó GitHub PAT"

    def test_detecta_rsa_private_key(self, tmp_path):
        """BEGIN RSA PRIVATE KEY en fichero debe generar hallazgo CRITICAL."""
        f = tmp_path / "id_rsa"
        f.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA2a2rwplBQL+AAAAAAAAA\n"
            "-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        hallazgos = scan_file(f, entropy_threshold=4.5)
        criticos = [h for h in hallazgos if h.severity == Severity.CRITICAL]
        assert len(criticos) >= 1, "Se esperaba hallazgo CRITICAL para RSA key"

    def test_fichero_limpio_sin_hallazgos(self, tmp_path):
        """Fichero sin secretos no debe generar ningún hallazgo."""
        f = tmp_path / "utils.py"
        f.write_text(
            "import os\n"
            "API_KEY = os.environ.get('API_KEY', '')\n"
            "SECRET = os.environ.get('MY_SECRET', '')\n",
            encoding="utf-8",
        )
        hallazgos = scan_file(f, entropy_threshold=4.5)
        # Solo puede haber hallazgos de entropía baja
        criticos_o_altos = [
            h for h in hallazgos
            if h.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(criticos_o_altos) == 0, (
            f"Hallazgos inesperados en fichero limpio: {[h.pattern for h in criticos_o_altos]}"
        )

    def test_export_json_estructura_correcta(self, tmp_path):
        """Export JSON debe contener resumen y lista de hallazgos bien formada."""
        f = tmp_path / "config.py"
        f.write_text(
            'TOKEN = "sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc"\n',
            encoding="utf-8",
        )
        hallazgos = scan_file(f, entropy_threshold=4.5)
        assert len(hallazgos) >= 1, "Se esperaba al menos un hallazgo"

        salida_json = tmp_path / "resultado.json"
        export_json(hallazgos, str(tmp_path), str(salida_json))
        data = json.loads(salida_json.read_text())
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total"] == len(hallazgos)
        assert isinstance(data["findings"], list)

    def test_discover_files_excluye_node_modules(self, tmp_path):
        """discover_files no debe entrar en node_modules ni otros dirs excluidos."""
        # Crear estructura con secreto dentro de node_modules
        nm = tmp_path / "node_modules" / "paquete"
        nm.mkdir(parents=True)
        (nm / "config.py").write_text('SK = "sk_" + "live_nodemodulefake123456789"\n')
        # Y un fichero legítimo
        (tmp_path / "app.py").write_text('x = 1\n')

        ficheros = list(discover_files(tmp_path, max_depth=None, all_extensions=False))
        rutas_str = [str(f) for f in ficheros]
        assert not any("node_modules" in r for r in rutas_str), (
            "discover_files no debería entrar en node_modules"
        )
        assert any("app.py" in r for r in rutas_str), (
            "discover_files debería encontrar app.py"
        )
