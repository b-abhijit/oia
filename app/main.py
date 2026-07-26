from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Response
import orjson
from .models import IncidentRequest, ReceiptRequest
from .state_machine import handle_receipt, init_run
from .store import init_db, load_run, save_run
from .utils import digest_json
from .store import init_db, load_run, save_run

@app.on_event("startup")
def startup():
    init_db()

app = FastAPI(title="Observable Incident Agent")


@app.on_event("startup")
def startup():
    init_db()


def json_response(data, status_code=200):
    return Response(
        content=orjson.dumps(data),
        media_type="application/json",
        status_code=status_code,
    )


@app.post("/v2/incidents")
def create_incident(
    req: IncidentRequest,
    traceparent: str | None = Header(default=None),
    tracestate: str | None = Header(default=None),
):
    existing = load_run(req.runId)
    request_hash = digest_json(req.model_dump(mode="json"))

    if existing:
        if existing.requestHash != request_hash:
            raise HTTPException(status_code=409, detail="run conflict")
        return json_response(existing.state.model_dump(mode="json"))

    run = init_run(req, traceparent, tracestate)
    save_run(run)
    return json_response(run.state.model_dump(mode="json"))


@app.post("/v2/incidents/{run_id}/receipts")
def post_receipt(run_id: str, receipt: ReceiptRequest):
    run = load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    updated = handle_receipt(run, receipt)
    save_run(updated)
    return json_response(updated.state.model_dump(mode="json"))


@app.get("/v2/incidents/{run_id}")
def get_run(run_id: str):
    run = load_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return json_response(run.state.model_dump(mode="json"))