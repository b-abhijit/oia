from __future__ import annotations

import orjson
import psycopg
from psycopg.rows import dict_row
from .config import DATABASE_URL
from .models import StoredRun


def get_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                create table if not exists incident_runs (
                    run_id text primary key,
                    payload jsonb not null
                )
            """)
        conn.commit()


def load_run(run_id: str) -> StoredRun | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select payload from incident_runs where run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return StoredRun.model_validate(row["payload"])


def save_run(run: StoredRun) -> None:
    payload = run.model_dump(mode="json")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into incident_runs (run_id, payload)
                values (%s, %s::jsonb)
                on conflict (run_id)
                do update set payload = excluded.payload
                """,
                (run.state.runId, orjson.dumps(payload).decode("utf-8")),
            )
        conn.commit()