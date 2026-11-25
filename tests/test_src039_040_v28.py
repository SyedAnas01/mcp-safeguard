"""v28: SRC-039 mode-gated enforcement, SRC-040 default admin credentials -- synthetic fixtures."""
import pytest
from mcp_safeguard.scanner.source_scanner import _find_default_admin_credentials as adm, _find_mode_gated_enforcement as gate

GP = {
    "enforce_flag": "enforce_allowlist = not local_single_user_enabled()\nallowed_handlers = load()\n",
    "if_not_local": "if not is_local_mode():\n    verify_signature(token)\n",
    "js_not_dev": "if (!isDevMode()) {\n  verifyAuth(req);\n}\n",
}
GN = {
    "no_security_word": "if not is_local_mode():\n    start_background_job()\n",
    "plain_positive": "if is_local_mode():\n    verify_signature(token)\n",
}
AP = {
    "django": 'User.objects.create_superuser("admin", "a@b.c", password="admin123")',
    "const": 'DEFAULT_ADMIN_PASSWORD = "Sup3rSecret"',
    "kw": 'u = make(username="a", password="changeme")\n',
}
AN = {
    "env": 'password = os.environ["ADMIN_PASSWORD"]',
    "random": 'create_superuser("admin", "a@b.c", password=secrets.token_hex(16))',
    "placeholder_empty": 'DEFAULT_ADMIN_PASSWORD = ""',
}


@pytest.mark.parametrize("k", GP)
def test_gate_fires(k): assert gate(GP[k]), k
@pytest.mark.parametrize("k", GN)
def test_gate_silent(k): assert not gate(GN[k]), k
@pytest.mark.parametrize("k", AP)
def test_admin_fires(k): assert adm(AP[k]), k
@pytest.mark.parametrize("k", AN)
def test_admin_silent(k): assert not adm(AN[k]), k


def test_check_for_updates_not_a_security_gate():
    assert not gate("if (!isDev()) {\n  checkForUpdates();\n}\n")
