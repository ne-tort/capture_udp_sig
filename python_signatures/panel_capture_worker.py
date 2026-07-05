"""
Detached capture worker for wg-easy panel (spawned from Node, does not block HTTP).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _write_status(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: panel_capture_worker.py '<json-payload>'", file=sys.stderr)
        return 2

    payload = json.loads(sys.argv[1])
    action = str(payload.get("action", "")).strip()
    kwargs: Dict[str, Any] = dict(payload.get("kwargs") or {})
    status_path = Path(str(payload.get("status_path", ""))).resolve()
    if not action or not status_path:
        print("missing action or status_path", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc).isoformat()
    base: Dict[str, Any] = {
        "state": "running",
        "action": action,
        "started_at": started,
        "profiles_done": 0,
        "profiles_total": 0,
        "current_profile": None,
    }
    _write_status(status_path, base)

    try:
        from python_signatures.library_api import invoke

        if action == "capture_all_profiles":
            kwargs["status_path"] = str(status_path)
            result = invoke(action, **kwargs)
        else:
            kwargs["status_path"] = str(status_path)
            result = invoke(action, **kwargs)

        _write_status(status_path, {
            **base,
            "state": "done",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        })
        return 0
    except Exception as exc:
        _write_status(status_path, {
            **base,
            "state": "error",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        })
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
