"""Compile all .py files and attempt to import every top-level module under the repo.
Prints failures to stdout for easy debugging.
"""
import compileall
import importlib
import pkgutil
import sys
import traceback
from pathlib import Path


def compile_repo_dirs(root: Path, dirs=('server', 'client')) -> None:
    """Compile only the specified directories under the repo (avoid .venv)."""
    for d in dirs:
        target = root / d
        if target.exists():
            print(f"Compiling Python files under {target}...")
            ok = compileall.compile_dir(str(target), force=True, quiet=1)
            print(f"compileall {d} result:", ok)


def iter_modules(package_root: Path):
    sys.path.insert(0, str(package_root.parent.parent))
    prefix = f"{package_root.parent.name}.{package_root.name}"
    # Walk packages under package_root
    for finder, name, ispkg in pkgutil.walk_packages([str(package_root)]):
        # Build full module name, e.g. server.app.api -> 'server.app.' + name
        yield f"{prefix}.{name}"


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
    # Compile server and client directories only
    compile_repo_dirs(repo)

    failures = {}
    # Check server and client packages (if present)
    for pkg_dir in (repo / "server" / "app", repo / "client"):
        if pkg_dir.exists():
            print(f"Scanning modules under: {pkg_dir}")
            for mod in iter_modules(pkg_dir):
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


if __name__ == "__main__":
    main()
