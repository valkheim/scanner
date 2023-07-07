import subprocess
import sys


def test_unittest() -> None:
    completed = subprocess.run(
        ["python", "-u", "-m", "unittest", "discover", "-v"]
    )
    sys.exit(completed.returncode)


def test_coverage() -> None:
    completed = subprocess.run(
        ["python", "-m", "coverage", "run", "--branch", "-m", "unittest", "-v"]
    )
    subprocess.run(["python", "-m", "coverage", "html"])
    sys.exit(completed.returncode)
