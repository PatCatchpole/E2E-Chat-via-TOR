from __future__ import annotations

import os
import sys

# The client imports its crypto package as `crypto.*`, so `client/` must be on
# the path for the tests to exercise exactly what the CLI runs.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(ROOT, "client")
if CLIENT_DIR not in sys.path:
    sys.path.insert(0, CLIENT_DIR)

# The relay refuses to start without a token, and reads it at import time, so
# it has to be in the environment before `import app` anywhere in the suite.
os.environ.setdefault("SPECTRE_INTERNAL_TOKEN", "test-token-not-a-real-secret")
SERVER_DIR = os.path.join(ROOT, "server")
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)
