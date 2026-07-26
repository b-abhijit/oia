from __future__ import annotations

import os
from pathlib import Path
import orjson
from .models import StoredRun

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


def run_path(run_id: str) -> Path:
    return DATA_DIR / f"{run_id}.json"


def load_run(run_id: str) -> StoredRun | None:
    path = run_path(run_id)
    if not path.exists():
        return None
    return StoredRun.model_validate(orjson.loads(path.read_bytes()))


def save_run(run: StoredRun) -> None:
    path = run_path(run.state.runId)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(orjson.dumps(run.model_dump(mode="json"), option=orjson.OPT_INDENT_2))
    os.replace(tmp, path)