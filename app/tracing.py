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

    server_attrs = base.copy()
    spans.append(
        _span(
            trace_id=trace_id,
            span_id=server_span_id,
            name="POST /v2/incidents",
            kind=2,
            attrs=server_attrs,
            parent_span_id=trace_ctx.get("incoming_parent_span_id"),
        )
    )

    agent_attrs = base.copy()
    spans.append(
        _span(
            trace_id=trace_id,
            span_id=agent_span_id,
            name="invoke_agent incident-response",
            kind=1,
            attrs=agent_attrs,
            parent_span_id=server_span_id,
        )
    )

    plan_attrs = base.copy() + [
        _str_attr("gen_ai.operation.name", "chat"),
        _str_attr("gen_ai.request.model", trace_ctx.get("model_name", "starter-local-model")),
    ]
    spans.append(
        _span(
            trace_id=trace_id,
            span_id=plan_span_id,
            name="chat incident-plan",
            kind=3,
            attrs=plan_attrs,
            parent_span_id=agent_span_id,
        )
    )

    for dispatch in state.actionLog:
        execute_span_id = dispatch.traceparent.split("-")[2]

        execute_attrs = base.copy() + [
            _str_attr("ga5.action.id", dispatch.actionId),
            _str_attr("gen_ai.tool.name", dispatch.toolName),
            _str_attr("gen_ai.tool.call.id", dispatch.callId),
            _str_attr("gen_ai.operation.name", "execute_tool"),
            _str_attr("ga5.phase", dispatch.phase),
            _int_attr("ga5.attempt", dispatch.attempt),
        ]
        if dispatch.approvalId:
            execute_attrs.append(_str_attr("ga5.approval.id", dispatch.approvalId))

        spans.append(
            _span(
                trace_id=trace_id,
                span_id=f"{execute_span_id[:15]}e",
                name=f"execute_tool {dispatch.toolName}",
                kind=1,
                attrs=execute_attrs,
                parent_span_id=agent_span_id,
            )
        )

        client_attrs = base.copy() + [
            _str_attr("ga5.action.id", dispatch.actionId),
            _int_attr("ga5.attempt", dispatch.attempt),
            _str_attr("http.request.method", "POST"),
            _str_attr("gen_ai.tool.name", dispatch.toolName),
            _str_attr("gen_ai.tool.call.id", dispatch.callId),
        ]
        spans.append(
            _span(
                trace_id=trace_id,
                span_id=execute_span_id,
                name=f"POST tool/{dispatch.toolName}",
                kind=3,
                attrs=client_attrs,
                parent_span_id=f"{execute_span_id[:15]}e",
            )
        )

    join_attrs = base.copy() + [
        _int_attr("ga5.dispatch.count", len(state.actionLog)),
        _int_attr("ga5.receipt.count", len(state.receiptLog)),
        _int_attr("ga5.approval.count", len(state.approvals)),
    ]
    spans.append(
        _span(
            trace_id=trace_id,
            span_id=join_span_id,
            name="join tool results",
            kind=1,
            attrs=join_attrs,
            parent_span_id=agent_span_id,
        )
    )

    if state.approvals:
        approval_attrs = base.copy() + [
            _int_attr("ga5.pending.approvals", len(state.approvals)),
        ]
        spans.append(
            _span(
                trace_id=trace_id,
                span_id=approval_gate_span_id,
                name="approval gate",
                kind=1,
                attrs=approval_attrs,
                parent_span_id=join_span_id,
            )
        )

    complete_attrs = base.copy() + [
        _str_attr("ga5.status", state.status),
    ]
    if state.chosenEffect:
        complete_attrs.append(_str_attr("ga5.chosen.effect", state.chosenEffect))
    if state.suppressed:
        complete_attrs.append(_int_attr("ga5.suppressed.count", len(state.suppressed)))

    spans.append(
        _span(
            trace_id=trace_id,
            span_id="f" + join_span_id[1:],
            name="complete run",
            kind=1,
            attrs=complete_attrs,
            parent_span_id=approval_gate_span_id if state.approvals else join_span_id,
        )
    )

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _str_attr("service.name", "incident-agent"),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "incident-agent"},
                        "spans": spans,
                    }
                ],
            }
        ]
    }