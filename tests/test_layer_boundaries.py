"""Static check that the layers only import downwards.

The thesis architecture relies on information hiding: each layer may
depend only on the layers below it (views -> explanation -> abstraction
-> models, with ingestion depending only on models and the shared
config module). This test parses the source of each module and fails
if a forbidden import appears, so the dependency direction is enforced
mechanically rather than by convention.

`app.py` is the composition root and is allowed to import any layer.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

EXPLAINER_DIR = Path(__file__).resolve().parent.parent / "explainer"

ALLOWED_IMPORTS = {
    "models": set(),
    "config": set(),
    "ingestion": {"models", "config"},
    "abstraction": {"models", "config"},
    "explanation": {"models", "config"},
    "views": {"models"},
}


def _explainer_imports(module_path: Path) -> set[str]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imports = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            if parts[0] == "explainer" and len(parts) > 1:
                imports.add(parts[1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "explainer" and len(parts) > 1:
                    imports.add(parts[1])

    return imports


@pytest.mark.parametrize("module_name, allowed", ALLOWED_IMPORTS.items())
def test_module_only_imports_allowed_layers(module_name, allowed):
    module_path = EXPLAINER_DIR / f"{module_name}.py"

    actual = _explainer_imports(module_path)
    forbidden = actual - allowed

    assert not forbidden, f"{module_name}.py imports forbidden modules: {forbidden}"
