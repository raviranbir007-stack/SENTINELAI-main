import subprocess
import sys
from pathlib import Path


SCRIPTS = [
    Path(__file__).parent / "test_api_all.py",
    Path(__file__).parent / "test_cors.py",
    Path(__file__).parent / "test_threat_detection.py",
]


def run_script(path: Path) -> None:
    res = subprocess.run([sys.executable, str(path)], capture_output=True, text=True)
    print(res.stdout)
    print(res.stderr, file=sys.stderr)
    assert res.returncode == 0, f"Script {path} failed with code {res.returncode}"


def test_run_all_scripts():
    for s in SCRIPTS:
        run_script(s)
