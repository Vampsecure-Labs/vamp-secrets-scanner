# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_secrets_scanner
=========================================================
Cubre: patrones de detección, entropía de Shannon, allowlist,
       SARIF output, fingerprinting, lógica auxiliar y verificación live AWS.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock


from vamp_secrets_scanner import (
    SECRET_PATTERNS,
    Severity,
    Finding,
    _shannon_entropy,
    _censor,
    _fingerprint,
    _context_lines,
    apply_allowlist,
    export_sarif,
    _check_aws_credentials_pair,
)


# ---------------------------------------------------------------------------
# Tests de detección de patrones (12 tests unitarios)
# ---------------------------------------------------------------------------

class TestPatronesRegex:
    """Verifica que cada patrón detecta correctamente su tipo de secreto."""

    def test_detecta_aws_access_key_akia(self):
        """AWS Access Key ID con prefijo AKIA debe ser detectado como CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "AWS Access Key ID")
        match = patron["compiled"].search("clave = AKIAIOSFODNN7EXAMPLE aqui")
        assert match is not None, "No detectó AWS Access Key ID con prefijo AKIA"

    def test_aws_key_severidad_critica(self):
        """El patrón de AWS Access Key ID debe tener severidad CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "AWS Access Key ID")
        assert patron["severity"] == "CRITICAL"

    def test_detecta_github_pat_ghp(self):
        """GitHub PAT con prefijo ghp_ debe ser detectado."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "GitHub PAT (classic)")
        # 36 caracteres alfanuméricos tras ghp_
        valor = "ghp_" + "A" * 36
        match = patron["compiled"].search(valor)
        assert match is not None, "No detectó GitHub PAT (ghp_)"

    def test_github_pat_severidad_high(self):
        """GitHub PAT debe tener severidad HIGH."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "GitHub PAT (classic)")
        assert patron["severity"] == "HIGH"

    def test_detecta_slack_webhook_url(self):
        """URL de Slack webhook hooks.slack.com debe ser detectada como HIGH."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "Slack Webhook URL")
        url = "https://hooks.slack.com/services/" + "TXXXXXXXX/BXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXXXXX"
        match = patron["compiled"].search(url)
        assert match is not None, "No detectó Slack Webhook URL"

    def test_slack_webhook_severidad_high(self):
        """Slack Webhook URL debe tener severidad HIGH."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "Slack Webhook URL")
        assert patron["severity"] == "HIGH"

    def test_detecta_rsa_private_key_pem(self):
        """Cabecera BEGIN RSA PRIVATE KEY debe ser detectada como CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "RSA Private Key (PEM)")
        texto = "-----BEGIN RSA PRIVATE KEY-----"
        match = patron["compiled"].search(texto)
        assert match is not None, "No detectó RSA Private Key (PEM)"

    def test_rsa_private_key_severidad_critica(self):
        """RSA Private Key debe tener severidad CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "RSA Private Key (PEM)")
        assert patron["severity"] == "CRITICAL"

    def test_detecta_jwt_token(self):
        """JWT con formato eyJ...eyJ...sig debe ser detectado."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "JSON Web Token (JWT)")
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ"
               ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        match = patron["compiled"].search(jwt)
        assert match is not None, "No detectó JWT token"

    def test_jwt_severidad_high(self):
        """JWT token debe tener severidad HIGH."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "JSON Web Token (JWT)")
        assert patron["severity"] == "HIGH"

    def test_detecta_stripe_live_key(self):
        """Stripe Live Secret Key debe ser detectada como CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "Stripe Live Secret Key")
        match = patron["compiled"].search("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc")
        assert match is not None, "No detectó Stripe Live Secret Key"

    def test_stripe_live_key_severidad_critica(self):
        """Stripe Live Secret Key debe tener severidad CRITICAL."""
        patron = next(p for p in SECRET_PATTERNS if p["name"] == "Stripe Live Secret Key")
        assert patron["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests de entropía de Shannon
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    """Verifica el cálculo de entropía de Shannon."""

    def test_entropia_cadena_vacia(self):
        """Cadena vacía debe retornar entropía 0."""
        assert _shannon_entropy("") == 0.0

    def test_entropia_cadena_uniforme(self):
        """Cadena con un solo carácter repetido tiene entropía 0."""
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_entropia_cadena_alta(self):
        """Token aleatorio tipo base64 debe superar umbral de 4.5 bits."""
        token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert _shannon_entropy(token) > 4.5

    def test_entropia_cadena_baja(self):
        """Cadena simple como 'password' tiene entropía menor que 4.5."""
        assert _shannon_entropy("password") < 4.5

    def test_entropia_formula_correcta(self):
        """Verifica que la entropía de dos caracteres equiprobables es 1.0 bit."""
        # "ab" → dos símbolos con prob 0.5 cada uno → H = 1.0
        resultado = _shannon_entropy("ab")
        assert abs(resultado - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Tests de lógica auxiliar
# ---------------------------------------------------------------------------

class TestAuxiliares:
    """Tests de funciones utilitarias del scanner."""

    def test_censor_cadena_corta(self):
        """Cadena de 6 o menos caracteres devuelve '***'."""
        assert _censor("abc") == "***"
        assert _censor("abcdef") == "***"

    def test_censor_cadena_larga(self):
        """Cadena larga muestra primeros 6 chars + *** + últimos 2."""
        resultado = _censor("AKIAIOSFODNN7EXAMPLE")
        assert resultado.startswith("AKIA")
        assert "***" in resultado

    def test_fingerprint_deterministico(self):
        """El mismo valor y patrón siempre producen el mismo fingerprint."""
        fp1 = _fingerprint("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID")
        fp2 = _fingerprint("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID")
        assert fp1 == fp2

    def test_fingerprint_diferente_por_patron(self):
        """Misma cadena con patrones distintos produce fingerprints distintos."""
        fp1 = _fingerprint("misecret", "patron_a")
        fp2 = _fingerprint("misecret", "patron_b")
        assert fp1 != fp2

    def test_context_lines_linea_central(self):
        """Las líneas de contexto deben incluir la línea objetivo."""
        lineas = [f"linea_{i}" for i in range(20)]
        ctx = _context_lines(lineas, 10)
        # Debe haber líneas de contexto alrededor
        assert len(ctx) > 0
        assert any("10" in c for c in ctx)

    def test_context_lines_no_index_error(self):
        """Las líneas de contexto no deben lanzar IndexError en bordes."""
        lineas = ["unica_linea"]
        ctx = _context_lines(lineas, 1)
        assert isinstance(ctx, list)


# ---------------------------------------------------------------------------
# Tests de allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    """Tests de la lógica de allowlist y filtrado de hallazgos."""

    def _hallazgo(self, fp="abc123", pattern="AWS Access Key ID", file="test.py"):
        return Finding(
            file=file,
            line_no=1,
            pattern=pattern,
            category="Cloud · AWS",
            severity=Severity.CRITICAL,
            preview="AKIA***",
            context=[],
            fingerprint=fp,
        )

    def test_allowlist_por_fingerprint_exacto(self):
        """Hallazgo con fingerprint en allowlist debe marcarse como allowlisted."""
        hallazgo = self._hallazgo(fp="deadbeef1234")
        allowlist = [{"fingerprint": "deadbeef1234"}]
        resultado = apply_allowlist([hallazgo], allowlist)
        assert resultado[0].allowlisted is True

    def test_allowlist_fingerprint_incorrecto_no_filtra(self):
        """Hallazgo con fingerprint diferente NO debe filtrarse."""
        hallazgo = self._hallazgo(fp="deadbeef1234")
        allowlist = [{"fingerprint": "ffffffff9999"}]
        resultado = apply_allowlist([hallazgo], allowlist)
        assert resultado[0].allowlisted is False

    def test_allowlist_por_patron_glob(self):
        """Patrón con wildcard * debe filtrar todos los hallazgos que empiecen igual."""
        hallazgo = self._hallazgo(pattern="Alta Entropía (H=4.80 bits)")
        allowlist = [{"pattern": "Alta Entropía*"}]
        resultado = apply_allowlist([hallazgo], allowlist)
        assert resultado[0].allowlisted is True

    def test_allowlist_patron_exacto(self):
        """Patrón sin wildcard solo filtra si coincide exactamente."""
        hallazgo = self._hallazgo(pattern="AWS Access Key ID")
        allowlist = [{"pattern": "AWS Access Key ID"}]
        resultado = apply_allowlist([hallazgo], allowlist)
        assert resultado[0].allowlisted is True

    def test_allowlist_por_fichero_prefijo(self):
        """Hallazgo en fichero que empieza por el prefijo de la allowlist debe filtrarse."""
        hallazgo = self._hallazgo(file="tests/fixtures/datos.py")
        allowlist = [{"file": "tests/fixtures/"}]
        resultado = apply_allowlist([hallazgo], allowlist)
        assert resultado[0].allowlisted is True

    def test_allowlist_vacia_no_filtra(self):
        """Allowlist vacía no debe marcar ningún hallazgo."""
        hallazgo = self._hallazgo()
        resultado = apply_allowlist([hallazgo], [])
        assert resultado[0].allowlisted is False


# ---------------------------------------------------------------------------
# Test de formato SARIF
# ---------------------------------------------------------------------------

class TestSarifOutput:
    """Verifica la estructura del output SARIF generado."""

    def test_sarif_estructura_basica(self, tmp_path):
        """El SARIF generado debe tener claves $schema, version y runs."""
        hallazgo = Finding(
            file=str(tmp_path / "config.py"),
            line_no=5,
            pattern="AWS Access Key ID",
            category="Cloud · AWS",
            severity=Severity.CRITICAL,
            preview="AKIA***",
            context=[],
            fingerprint="abc123def456",
        )
        salida = tmp_path / "resultado.sarif"
        export_sarif([hallazgo], str(tmp_path), str(salida))
        data = json.loads(salida.read_text())
        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_contiene_resultados(self, tmp_path):
        """El SARIF debe incluir los hallazgos en runs[0].results."""
        hallazgo = Finding(
            file=str(tmp_path / "config.py"),
            line_no=5,
            pattern="Stripe Live Secret Key",
            category="Pagos · Stripe",
            severity=Severity.CRITICAL,
            preview="sk_li***",
            context=[],
            fingerprint="stripe001",
        )
        salida = tmp_path / "resultado.sarif"
        export_sarif([hallazgo], str(tmp_path), str(salida))
        data = json.loads(salida.read_text())
        resultados = data["runs"][0]["results"]
        assert len(resultados) == 1
        assert resultados[0]["level"] == "error"

    def test_sarif_omite_allowlisted(self, tmp_path):
        """Hallazgos marcados como allowlisted NO deben aparecer en el SARIF."""
        hallazgo = Finding(
            file=str(tmp_path / "config.py"),
            line_no=5,
            pattern="AWS Access Key ID",
            category="Cloud · AWS",
            severity=Severity.CRITICAL,
            preview="AKIA***",
            context=[],
            fingerprint="abc999",
            allowlisted=True,
        )
        salida = tmp_path / "resultado.sarif"
        export_sarif([hallazgo], str(tmp_path), str(salida))
        data = json.loads(salida.read_text())
        assert len(data["runs"][0]["results"]) == 0


# ---------------------------------------------------------------------------
# Tests de verificación activa AWS con SigV4 (6 tests)
# ---------------------------------------------------------------------------

class TestCheckAwsCredentialsPair:
    """Verifica la lógica de verificación live de credenciales AWS mediante STS."""

    def test_retorna_true_si_status_200(self):
        """Credenciales válidas: STS devuelve 200 → True."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_response.text = AsyncMock(return_value="<GetCallerIdentityResponse/>")

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        resultado = asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAIOSFODNN7EXAMPLE", "A" * 40)
        )
        assert resultado is True

    def test_retorna_false_si_403_invalid_token(self):
        """Key ID inexistente: 403 con InvalidClientTokenId → False."""
        mock_response = MagicMock()
        mock_response.status = 403
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_response.text = AsyncMock(return_value="<Error><Code>InvalidClientTokenId</Code></Error>")

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        resultado = asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAINVALIDKEYXXXXXXX", "B" * 40)
        )
        assert resultado is False

    def test_retorna_true_si_403_signature_mismatch(self):
        """Key existe pero secret incorrecto: 403 SignatureDoesNotMatch → True (key activa)."""
        mock_response = MagicMock()
        mock_response.status = 403
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_response.text = AsyncMock(return_value="<Error><Code>SignatureDoesNotMatch</Code></Error>")

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        resultado = asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAIOSFODNN7EXAMPLE", "C" * 40)
        )
        assert resultado is True

    def test_retorna_none_si_excepcion_de_red(self):
        """Si la red falla (timeout, DNS), retorna None (indeterminado)."""
        mock_session = MagicMock()
        mock_session.post = MagicMock(side_effect=Exception("connection error"))

        resultado = asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAIOSFODNN7EXAMPLE", "D" * 40)
        )
        assert resultado is None

    def test_genera_cabeceras_sigv4_validas(self):
        """La función debe llamar a session.post con cabeceras de autorización AWS4-HMAC-SHA256."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_response.text = AsyncMock(return_value="<ok/>")

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAIOSFODNN7EXAMPLE", "E" * 40)
        )
        call_kwargs = mock_session.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        assert "X-Amz-Date" in headers

    def test_url_apunta_a_sts(self):
        """La petición debe ir a sts.amazonaws.com."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_response.text = AsyncMock(return_value="<ok/>")

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        asyncio.run(
            _check_aws_credentials_pair(mock_session, "AKIAIOSFODNN7EXAMPLE", "F" * 40)
        )
        url = mock_session.post.call_args.args[0]
        assert "sts.amazonaws.com" in url


# ---------------------------------------------------------------------------
# Tests de daemon mode (--watch) — v2.5
# ---------------------------------------------------------------------------

class TestDaemonMode:
    """Tests del modo daemon (_run_scan, _daemon_loop)."""

    def test_run_scan_retorna_lista(self, tmp_path):
        """_run_scan sobre un directorio vacío retorna lista (puede ser vacía)."""
        import argparse
        from vamp_secrets_scanner import _run_scan

        args = argparse.Namespace(
            target=str(tmp_path),
            only_critical=False,
            min_severity="MEDIUM",
            no_entropy=True,
            entropy_threshold=4.5,
            max_depth=None,
            all_extensions=False,
            git_history=False,
            max_commits=None,
            scan_container=None,
            scan_all_containers=False,
            k8s=False,
            k8s_namespace=None,
            allowlist=None,
        )
        findings = _run_scan(args)
        assert isinstance(findings, list)

    def test_run_scan_detecta_secret_en_fichero(self, tmp_path):
        """_run_scan detecta un token AWS hardcodeado."""
        import argparse
        from vamp_secrets_scanner import _run_scan

        (tmp_path / "config.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        )
        args = argparse.Namespace(
            target=str(tmp_path),
            only_critical=False,
            min_severity="LOW",
            no_entropy=False,
            entropy_threshold=3.5,
            max_depth=None,
            all_extensions=False,
            git_history=False,
            max_commits=None,
            scan_container=None,
            scan_all_containers=False,
            k8s=False,
            k8s_namespace=None,
            allowlist=None,
        )
        findings = _run_scan(args)
        assert any("AKIA" in f.preview or "AWS" in f.pattern for f in findings)

    def test_daemon_loop_argparser_acepta_watch(self):
        """El parser acepta --watch como entero."""
        import argparse
        from vamp_secrets_scanner import parse_args as _parse
        import sys

        old_argv = sys.argv
        sys.argv = ["vamp-secrets-scanner", ".", "--watch", "30"]
        try:
            args = _parse()
            assert args.watch == 30
        finally:
            sys.argv = old_argv

    def test_version_es_25(self):
        from vamp_secrets_scanner import VERSION
        assert VERSION == "2.5"
