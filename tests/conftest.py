# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-secrets-scanner
"""

import sys
from pathlib import Path

import pytest

# Añadir el directorio raíz de la herramienta al path de importación
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures de ficheros temporales con secretos conocidos
# ---------------------------------------------------------------------------

@pytest.fixture
def archivo_con_secretos(tmp_path):
    """Fichero con secretos conocidos para tests de detección básica."""
    contenido = (
        '# Configuración de prueba\n'
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        'GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"\n'
    )
    f = tmp_path / "config_prueba.py"
    f.write_text(contenido, encoding="utf-8")
    return f


@pytest.fixture
def archivo_con_rsa_key(tmp_path):
    """Fichero que contiene la cabecera de una clave privada RSA."""
    contenido = (
        "# fichero de clave\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJTP8BAAAAAAAAAAAAAAAA\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    f = tmp_path / "id_rsa"
    f.write_text(contenido, encoding="utf-8")
    return f


@pytest.fixture
def archivo_con_slack_webhook(tmp_path):
    """Fichero con una URL de webhook de Slack."""
    contenido = (
        'WEBHOOK_URL = "https://hooks.slack.com/services/" + "TXXXXXXXX/BXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX"\n'
    )
    f = tmp_path / "notificaciones.py"
    f.write_text(contenido, encoding="utf-8")
    return f


@pytest.fixture
def archivo_con_jwt(tmp_path):
    """Fichero con un JWT hardcodeado."""
    contenido = (
        'TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ'
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n'
    )
    f = tmp_path / "auth_helper.py"
    f.write_text(contenido, encoding="utf-8")
    return f


@pytest.fixture
def archivo_limpio(tmp_path):
    """Fichero sin secretos para comprobar que no hay falsos positivos."""
    contenido = (
        "# Módulo de utilidades\n"
        "import os\n"
        "API_KEY = os.environ.get('API_KEY', '')\n"
        "SECRET = os.environ.get('SECRET', '')\n"
    )
    f = tmp_path / "utils.py"
    f.write_text(contenido, encoding="utf-8")
    return f


@pytest.fixture
def allowlist_fingerprint(tmp_path):
    """Fichero de allowlist con un fingerprint de prueba."""
    import json
    data = {
        "allowlist": [
            {"fingerprint": "aabbccdd1122"},
            {"pattern": "Alta Entropía*"},
        ]
    }
    f = tmp_path / "allowlist.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    return f
