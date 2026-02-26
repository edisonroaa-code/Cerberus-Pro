import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), "backend"))

from backend.core.engine_adapters import SqlmapAdapter, get_engine_adapter_registry


from unittest.mock import patch

def test_sqlmap_adapter_builds_non_interactive_command():
    with patch("backend.core.engine_adapters.shutil.which", return_value="/usr/bin/sqlmap"):
        adapter = SqlmapAdapter()
        cmd = adapter.build_command(
            technique="enum",
            command_template="sqlmap --schema",
            endpoint="https://example.org/item?id=1",
            parameter="id",
        )
    assert cmd is not None
    assert cmd.engine == "sqlmap"
    assert "--batch" in cmd.command
    assert "-u" in cmd.command
    assert "https://example.org/item?id=1" in cmd.command
    assert "-p" in cmd.command
    assert "id" in cmd.command


def test_registry_picks_sqlmap_for_sqli_chain():
    registry = get_engine_adapter_registry()
    adapter = registry.find_adapter(
        technique="enum",
        command_template="sqlmap --dbs",
        vuln_type="sql_injection",
    )
    assert adapter is not None
    assert adapter.name == "sqlmap"

