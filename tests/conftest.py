import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

pytest_plugins = [
    "root",
    "command",
    "ports",
    "sshd",
]
