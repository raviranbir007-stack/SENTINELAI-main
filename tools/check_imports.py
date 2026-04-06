"""Validate Python syntax and imports for server/client modules.

This checker avoids writing bytecode files so it can run in read-only or mixed-ownership
workspaces without false failures.
"""
import ast
import importlib
import pkgutil
import sys
import traceback
from pathlib import Path


def syntax_check_dir(root: Path, dirs=("server", "client")) -> bool:
    """Parse all Python files under target dirs without generating .pyc files."""
    ok = True
    for d in dirs:
        target = root / d
        if not target.exists():
            continue
        print(f"Syntax-checking Python files under {target}...")
        for py_file in target.rglob("*.py"):
            # Skip virtual environments and cache folders if present inside the tree.
            if any(part in {"venv", ".venv", "__pycache__"} for part in py_file.parts):
                continue
            try:
                source = py_file.read_text(encoding="utf-8")
                ast.parse(source, filename=str(py_file))
            except Exception:
                ok = False
                print(f"SYNTAX ERROR: {py_file}")
                print(traceback.format_exc())
    return ok


def iter_modules(package_root: Path, root_package: str):
    """Walk importable modules under a package root and yield full import paths."""
    for _, name, _ in pkgutil.walk_packages([str(package_root)]):
        yield f"{root_package}.{name}"


def iter_client_modules(client_root: Path):
    """Yield importable modules from the client tree."""
    for _, name, _ in pkgutil.walk_packages([str(client_root)]):
        yield name


def try_import(name: str):
    # Provide stubs for heavy or environment-specific third-party packages
    stub_pkgs = [
        "sqlalchemy",
        "reportlab",
        "google",
        "google.generativeai",
        "torch",
        "tensorflow",
    ]

    inserted = []
    try:
        for pkg in stub_pkgs:
            try:
                if importlib.util.find_spec(pkg) is None:
                    # insert a simple module stub
                    import types

                    mod = types.ModuleType(pkg)
                    if pkg == "torch":
                        # SciPy probes torch.Tensor via getattr(); provide a minimal placeholder.
                        mod.Tensor = type("Tensor", (), {})
                    sys.modules[pkg] = mod
                    inserted.append(pkg)
            except Exception:
                continue

        importlib.import_module(name)
        return None
    except Exception:
        return traceback.format_exc()
    finally:
        # remove inserted stubs
        for pkg in inserted:
            sys.modules.pop(pkg, None)


def main():
    repo = Path(__file__).resolve().parents[1]
    syntax_ok = syntax_check_dir(repo)

    failures = {}

    # Server imports use the top-level 'app' package when /server is on sys.path.
    server_root = repo / "server"
    server_app = server_root / "app"
    if server_app.exists():
        sys.path.insert(0, str(server_root))
        print(f"Scanning server modules under: {server_app}")
        for mod in iter_modules(server_app, "app"):
            err = try_import(mod)
            if err:
                failures[mod] = err

    # Client imports resolve from /client (e.g., scanner.*, sentinel_client_v3).
    client_root = repo / "client"
    if client_root.exists():
        sys.path.insert(0, str(client_root))
        print(f"Scanning client modules under: {client_root}")
        for mod in iter_client_modules(client_root):
            err = try_import(mod)
            if err:
                failures[mod] = err

    if failures:
        print("\nIMPORT FAILURES:\n")
        for mod, tb in failures.items():
            print("MODULE:", mod)
            print(tb)
            print("-" * 80)
        sys.exit(2)
    else:
        print("All imports succeeded.")

    if not syntax_ok:
        sys.exit(3)


if __name__ == "__main__":
    main()
