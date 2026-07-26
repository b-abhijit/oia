from __future__ import annotations

from typing import Any
from .models import Dispatch, RunState
from .utils import new_span_id

SPAN_KIND_INTERNAL = 1
SPAN_KIND_SERVER = 2
SPAN_KIND_CLIENT = 3


def make_span(span_id: str, trace_id: str, name: str, kind: int, parent_span_id: str | None, attributes: dict[str, Any], status_code: int | None = None, links: list[dict] | None = None):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "attributes": [{"key": k, "value": {"stringValue": str(v)}} if not isinstance(v, int) else {"key": k, "value": {"intValue": v}} for k, v in attributes.items()],
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if status_code is not None:
        span["status"] = {"code": status_code}
    if links:
        span["links"] = links
    return span


def build_otlp(state: RunState, trace_ctx: dict[str, str]) -> dict[str, Any]:
    trace_id = trace_ctx["trace_id"]
    server_span_id = trace_ctx["server_span_id"]
    agent_span_id = trace_ctx["agent_span_id"]
    plan_span_id = trace_ctx["plan_span_id"]

    spans = []
    common = {
        "ga5.run.id": state.runId,
        "ga5.public.marker": trace_ctx["public_marker"],
    }

    spans.append(make_span(server_span_id, trace_id, "POST /v2/incidents", SPAN_KIND_SERVER, trace_ctx.get("incoming_parent_span_id"), common))
    spans.append(make_span(agent_span_id, trace_id, "invoke_agent incident-response", SPAN_KIND_INTERNAL, server_span_id, common))
    spans.append(make_span(plan_span_id, trace_id, "chat incident-plan", SPAN_KIND_CLIENT, agent_span_id, {
        **common,
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": trace_ctx.get("model_name", "dummy-local-model"),
    }))

    logical_span_ids = {}
    for dispatch in state.actionLog:
        logical_span_ids.setdefault(dispatch.actionId, new_span_id())

    for dispatch in state.actionLog:
        exec_span_id = logical_span_ids[dispatch.actionId]
        spans.append(make_span(exec_span_id, trace_id, f"execute_tool {dispatch.toolName}", SPAN_KIND_INTERNAL, agent_span_id, {
            **common,
            "ga5.action.id": dispatch.actionId,
            "gen_ai.tool.name": dispatch.toolName,
            "gen_ai.tool.call.id": dispatch.callId,
            "gen_ai.operation.name": "execute_tool",
        }))
        client_span_id = dispatch.traceparent.split("-")[2]
        receipt = next((r for r in state.receiptLog if getattr(r, "actionId", None) == dispatch.actionId and getattr(r, "attempt", None) == dispatch.attempt), None)
        attrs = {
            **common,
            "ga5.action.id": dispatch.actionId,
            "ga5.attempt": dispatch.attempt,
            "http.request.method": "POST",
            "http.request.resend_count": dispatch.attempt - 1,
        }
        status_code = None
        if receipt:
            if getattr(receipt, "receiptId", None):
                attrs["ga5.receipt.id"] = receipt.receiptId
            if getattr(receipt, "nonce", None):
                attrs["ga5.receipt.nonce"] = receipt.nonce
            if getattr(receipt, "status", None) is not None:
                attrs["http.response.status_code"] = int(receipt.status)
                if int(receipt.status) == 503:
                    status_code = 2
                    attrs["error.type"] = "503"
            if getattr(receipt, "errorType", None):
                attrs["error.type"] = receipt.errorType
                status_code = 2
        spans.append(make_span(client_span_id, trace_id, f"POST tool/{dispatch.toolName}", SPAN_KIND_CLIENT, exec_span_id, attrs, status_code=status_code))

    diagnostic_execs = []
    for dispatch in state.actionLog:
        if dispatch.phase == "diagnostic":
            diagnostic_execs.append(logical_span_ids[dispatch.actionId])
    if len(set(diagnostic_execs)) > 1:
        join_span_id = trace_ctx.get("join_span_id") or new_span_id()
        links = [{"traceId": trace_id, "spanId": sid} for sid in sorted(set(diagnostic_execs))]
        spans.append(make_span(join_span_id, trace_id, "incident.join", SPAN_KIND_INTERNAL, agent_span_id, common, links=links))

    for receipt in state.receiptLog:
        if hasattr(receipt, "approvalId"):
            gate_span_id = trace_ctx.get("approval_gate_span_id") or new_span_id()
            spans.append(make_span(gate_span_id, trace_id, "approval_gate", SPAN_KIND_INTERNAL, agent_span_id, {
                **common,
                "ga5.approval.id": receipt.approvalId,
                "ga5.receipt.nonce": receipt.nonce,
            }))
            break

    return {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": spans
            }]
        }]
    }