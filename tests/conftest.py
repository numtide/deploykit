import sys
import os

sys.path.append(os.path.dirname(__file__))

pytest_plugins = [
    "sshd",
    "root",
]
