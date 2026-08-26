from __future__ import annotations

import os
import sys

# The client imports its crypto package as `crypto.*`, so `client/` must be on
# the path for the tests to exercise exactly what the CLI runs.
CLIENT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
if CLIENT_DIR not in sys.path:
    sys.path.insert(0, CLIENT_DIR)
