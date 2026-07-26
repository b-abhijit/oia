from __future__ import annotations

from typing import Any


def _str_attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def _int_attr(key: str, value: int) -> dict[str, Any]:
    return {"key": key, "value": {"intValue": value}}


def _base_attrs(state, trace_ctx) -> list[dict[str, Any]]:
    return [
        _str_attr("ga5.run.id", state.runId),
        _str_attr("ga5.public.marker", trace_ctx["public_marker"]),
    ]


def _span(
    *,
    trace_id: str,
    span_id: str,
    name: str,
    kind: int,
    attrs: list[dict[str, Any]] | None = None,
    parent_span_id: str | None = None,
    links: list[dict[str, Any]] | None = None,
    status_code: int | None = None,
    error_message: str | None = None,
) -> dict[str, Any]:
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "attributes": attrs or [],
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if links:
        span["links"] = links
    if status_code is not None:
        status: dict[str, Any] = {"code": status_code}
        if error_message is not None:
            status["message"] = error_message
        span["status"] = status
    return span


def build_otlp(state, trace_ctx) -> dict[str, Any]:
    trace_id = trace_ctx["trace_id"]
    server_span_id = trace_ctx["server_span_id"]
    agent_span_id = trace_ctx["agent_span_id"]
    plan_span_id = trace_ctx["plan_span_id"]
    join_span_id = trace_ctx["join_span_id"]
    approval_gate_span_id = trace_ctx["approval_gate_span_id"]

    spans: list[dict[str, Any]] = []
    base = _base_attrs(state, trace_ctx)

    # SERVER span for the whole incoming request
    spans.append(_span(
        trace_id=trace_id, span_id=server_span_id, name="POST /v2/incidents",
        kind=2, attrs=base.copy(), parent_span_id=trace_ctx.get("incoming_parent_span_id"),
    ))

    # INTERNAL agent span
    spans.append(_span(
        trace_id=trace_id, span_id=agent_span_id, name="invoke_agent incident-response",
        kind=1, attrs=base.copy(), parent_span_id=server_span_id,
    ))

    # CLIENT span for the single model call — exactly one per run
    plan_attrs = base.copy() + [
        _str_attr("gen_ai.operation.name", "chat"),
        _str_attr("gen_ai.request.model", trace_ctx.get("model_name", "unknown-model")),
    ]
    spans.append(_span(
        trace_id=trace_id, span_id=plan_span_id, name="chat incident-plan",
        kind=3, attrs=plan_attrs, parent_span_id=agent_span_id,
    ))

    # Index receipts so each tool CLIENT span can be enriched with what
    # actually happened to that attempt. No separate "receipt span" exists
    # in the required topology — the data lives on the CLIENT span itself.
    receipt_by_attempt: dict[tuple[str, int], Any] = {}
    approval_receipt_by_id: dict[str, Any] = {}
    for entry in state.receiptLog:
        if hasattr(entry, "actionId"):
            receipt_by_attempt[(entry.actionId, entry.attempt)] = entry
        elif hasattr(entry, "approvalId"):
            approval_receipt_by_id[entry.approvalId] = entry

    diagnostic_exec_span_ids: list[str] = []
    exec_span_ids: dict[str, str] = trace_ctx.setdefault("exec_span_ids", {})

    for dispatch in state.actionLog:
        client_span_id = dispatch.traceparent.split("-")[2]

        exec_span_id = exec_span_ids.get(dispatch.actionId)
        if not exec_span_id:
            exec_span_id = ("e" + client_span_id[1:])[:16]
            exec_span_ids[dispatch.actionId] = exec_span_id

        if dispatch.phase == "diagnostic" and exec_span_id not in diagnostic_exec_span_ids:
            diagnostic_exec_span_ids.append(exec_span_id)

        # One execute_tool span per logical action (emit on first attempt only)
        if dispatch.attempt == 1:
            execute_attrs = base.copy() + [
                _str_attr("ga5.action.id", dispatch.actionId),
                _str_attr("gen_ai.tool.call.id", dispatch.callId),
                _str_attr("gen_ai.tool.name", dispatch.toolName),
                _str_attr("gen_ai.operation.name", "execute_tool"),
            ]
            spans.append(_span(
                trace_id=trace_id, span_id=exec_span_id,
                name=f"execute_tool {dispatch.toolName}",
                kind=1, attrs=execute_attrs, parent_span_id=agent_span_id,
            ))

        receipt = receipt_by_attempt.get((dispatch.actionId, dispatch.attempt))

        client_attrs = base.copy() + [
            _str_attr("ga5.action.id", dispatch.actionId),
            _int_attr("ga5.attempt", dispatch.attempt),
            _str_attr("gen_ai.tool.call.id", dispatch.callId),
            _str_attr("gen_ai.tool.name", dispatch.toolName),
            _str_attr("http.request.method", "POST"),
            _int_attr("http.request.resend_count", dispatch.attempt - 1),
        ]
        if dispatch.approvalId:
            client_attrs.append(_str_attr("ga5.approval.id", dispatch.approvalId))
        if dispatch.approvalNonce:
            client_attrs.append(_str_attr("ga5.approval.nonce", dispatch.approvalNonce))

        status_code = None
        error_message = None
        if receipt is not None:
            client_attrs.append(_str_attr("ga5.receipt.id", receipt.receiptId))
            if receipt.nonce:
                client_attrs.append(_str_attr("ga5.receipt.nonce", receipt.nonce))
            if receipt.errorType:
                # e.g. timeout: no HTTP status, just an error type
                client_attrs.append(_str_attr("error.type", receipt.errorType))
                status_code = 2
                error_message = receipt.errorType
            else:
                client_attrs.append(_int_attr("http.response.status_code", receipt.status))
                if receipt.status >= 400:
                    error_type = str(receipt.status)
                    client_attrs.append(_str_attr("error.type", error_type))
                    status_code = 2
                    error_message = error_type
                # else: successful attempt -> leave status as UNSET (default)

        spans.append(_span(
            trace_id=trace_id, span_id=client_span_id,
            name=f"POST tool/{dispatch.toolName}",
            kind=3, attrs=client_attrs, parent_span_id=exec_span_id,
            status_code=status_code, error_message=error_message,
        ))

    # incident.join: only when diagnostics fanned out (2+ parallel diagnostics),
    # and it links to every independent diagnostic execute_tool span.
    first_attempt_diagnostics = [d for d in state.actionLog if d.phase == "diagnostic" and d.attempt == 1]
    if len(first_attempt_diagnostics) > 1:
        links = [{"traceId": trace_id, "spanId": sid} for sid in diagnostic_exec_span_ids]
        join_attrs = base.copy() + [
            _int_attr("ga5.dispatch.count", len(state.actionLog)),
            _int_attr("ga5.receipt.count", len(state.receiptLog)),
        ]
        spans.append(_span(
            trace_id=trace_id, span_id=join_span_id, name="incident.join",
            kind=1, attrs=join_attrs, parent_span_id=agent_span_id, links=links,
        ))

    # approval_gate: persists in the trace for the whole run once an
    # approval was ever requested, even after it's been decided.
    approval_records = trace_ctx.get("approval_records", [])
    if approval_records:
        approval_attrs = base.copy()
        for record in approval_records:
            approval_attrs.append(_str_attr("ga5.approval.id", record["approvalId"]))
            approval_attrs.append(_str_attr("ga5.action.id", record["actionId"]))
            approval_attrs.append(_str_attr("gen_ai.tool.name", record["toolName"]))
            receipt = approval_receipt_by_id.get(record["approvalId"])
            if receipt is not None:
                approval_attrs.append(_str_attr("ga5.approval.decision", receipt.decision))
                if receipt.nonce:
                    approval_attrs.append(_str_attr("ga5.approval.receipt.nonce", receipt.nonce))
        spans.append(_span(
            trace_id=trace_id, span_id=approval_gate_span_id, name="approval_gate",
            kind=1, attrs=approval_attrs, parent_span_id=agent_span_id,
        ))

    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [_str_attr("service.name", "incident-agent")]},
                "scopeSpans": [{"scope": {"name": "incident-agent"}, "spans": spans}],
            }
        ]
    }