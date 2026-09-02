"""Version consistency check between mcp_safeguard.__version__ and pyproject.toml."""

import re
import tomllib
from pathlib import Path

import mcp_safeguard


def test_package_version_matches_pyproject():
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text())
    pyproject_version = data["project"]["version"]

    assert re.match(r"^\d+\.\d+\.\d+$", mcp_safeguard.__version__), (
        f"__version__ '{mcp_safeguard.__version__}' is not a valid semver string"
    )
    assert mcp_safeguard.__version__ == pyproject_version
