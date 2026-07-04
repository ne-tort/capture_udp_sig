#!/usr/bin/env python3
"""Backward-compatible wrapper — use scripts/live_capture.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.live_capture import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.extend(["--profile", "quic_browser"])
    elif "--profile" not in sys.argv:
        # legacy: positional profile [timeout]
        args = [a for a in sys.argv[1:] if not a.startswith("-")]
        if args:
            sys.argv = [sys.argv[0], "--profile", args[0]] + sys.argv[1:]
    sys.exit(main())
