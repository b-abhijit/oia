from __future__ import annotations

from fastapi import HTTPException
from .models import ApprovalReceiptLog, ApprovalRequest, Dispatch, IncidentRequest, ReceiptRequest, RunState, StoredRun, ToolReceiptLog
from .planner import plan_incident
from .tracing import build_otlp
from .utils import digest_json, make_id, new_span_id, parse_traceparent


def init_run(req: IncidentRequest, incoming_traceparent: str | None, incoming_tracestate: str | None) -> StoredRun:
    diagnosis, diagnostics, effect_plan = plan_incident(req)
    parent = parse_traceparent(incoming_traceparent)
    trace_id = parent["trace_id"] if parent else __import__("app.utils", fromlist=["new_trace_id"]).new_trace_id()
    trace_ctx = {
        "trace_id": trace_id,
        "public_marker": req.publicMarker,
        "server_span_id": new_span_id(),
        "agent_span_id": new_span_id(),
        "plan_span_id": new_span_id(),
        "join_span_id": new_span_id(),
        "approval_gate_span_id": new_span_id(),
        "model_name": "starter-local-model",
    }
    if parent:
        trace_ctx["incoming_parent_span_id"] = parent["parent_id"]
    if incoming_tracestate:
        trace_ctx["tracestate"] = incoming_tracestate
    
    action_log = []
    pending = {}
    for d in diagnostics:
        action_id = make_id("act")
        call_id = make_id("call")
        client_span_id = new_span_id()
        traceparent = f"00-{trace_id}-{client_span_id}-01"
        dispatch = Dispatch(
            actionId=action_id,
            callId=call_id,
            phase="diagnostic",
            toolName=d["toolName"],
            arguments=d["arguments"],
            evidence=d["evidence"],
            attempt=1,
            traceparent=traceparent,
        )
        action_log.append(dispatch)
        pending[action_id] = dispatch
    state = RunState(
        runId=req.runId,
        status="waiting",
        diagnosis=diagnosis,
        actionLog=action_log.copy(),
        dispatches=action_log.copy(),
        approvals=[],
        otlp={},
    )
    state.otlp = build_otlp(state, trace_ctx)
    return StoredRun(
        requestHash=digest_json(req.model_dump(mode="json")),
        requestBody=req.model_dump(mode="json"),
        state=state,
        pendingActions=pending,
        pendingApprovals={},
        effectPlan=effect_plan,
        traceContext=trace_ctx,
        plannerUsed=True,
    )


def handle_receipt(run: StoredRun, receipt: ReceiptRequest) -> StoredRun:
    body_hash = digest_json(receipt.model_dump(mode="json"))
    if receipt.receiptId in run.receipts and run.receipts[receipt.receiptId] != body_hash:
        raise HTTPException(status_code=409, detail="receipt conflict")
    if receipt.receiptId in run.receipts:
        return run
    run.receipts[receipt.receiptId] = body_hash
    run.state.dispatches = []
    run.state.approvals = []

    for out in receipt.outcomes:
        pending = run.pendingActions.get(out.actionId)
        if not pending or pending.attempt != out.attempt:
            raise HTTPException(status_code=422, detail="unknown or non-pending action outcome")
        run.state.receiptLog.append(ToolReceiptLog(
            receiptId=receipt.receiptId,
            actionId=out.actionId,
            callId=out.callId,
            attempt=out.attempt,
            status=out.status,
            resultClass=out.resultClass,
            nonce=out.nonce,
            errorType=out.errorType,
        ))
        del run.pendingActions[out.actionId]
        if out.status == 503 and out.attempt == 1:
            retry = pending.model_copy(update={
                "attempt": 2,
                "traceparent": f"00-{run.traceContext['trace_id']}-{new_span_id()}-01",
            })
            run.pendingActions[retry.actionId] = retry
            run.state.actionLog.append(retry)
            run.state.dispatches.append(retry)
        elif out.status == 0 and out.errorType == "timeout":
            run.state.suppressed.append(out.actionId)

    for approval in receipt.approvals:
        pending = run.pendingApprovals.get(approval.approvalId)
        if not pending:
            raise HTTPException(status_code=422, detail="unknown approval")
        run.state.receiptLog.append(ApprovalReceiptLog(
            receiptId=receipt.receiptId,
            approvalId=approval.approvalId,
            decision=approval.decision,
            nonce=approval.nonce,
        ))
        del run.pendingApprovals[approval.approvalId]
        if approval.decision == "approved":
            effect = run.effectPlan
            if effect:
                client_span_id = new_span_id()
                dispatch = Dispatch(
                    actionId=pending.actionId,
                    callId=make_id("call"),
                    phase="effect",
                    toolName=pending.toolName,
                    arguments=effect["arguments"],
                    evidence=run.state.diagnosis.evidence,
                    attempt=1,
                    traceparent=f"00-{run.traceContext['trace_id']}-{client_span_id}-01",
                    approvalId=approval.approvalId,
                    approvalNonce=approval.nonce,
                )
                run.pendingActions[dispatch.actionId] = dispatch
                run.state.actionLog.append(dispatch)
                run.state.dispatches.append(dispatch)
                run.state.chosenEffect = dispatch.toolName

    if not run.pendingActions and not run.pendingApprovals and run.effectPlan and not run.state.chosenEffect and not run.state.suppressed:
        tool = run.effectPlan["toolName"]
        if tool in run.requestBody["policy"]["approvalRequiredFor"]:
            approval_req = ApprovalRequest(
                approvalId=make_id("approval"),
                actionId=make_id("act"),
                toolName=tool,
                argumentsDigest=digest_json(run.effectPlan["arguments"]),
            )
            run.pendingApprovals[approval_req.approvalId] = approval_req
            run.state.approvals.append(approval_req)
        else:
            client_span_id = new_span_id()
            dispatch = Dispatch(
                actionId=make_id("act"),
                callId=make_id("call"),
                phase="effect",
                toolName=tool,
                arguments=run.effectPlan["arguments"],
                evidence=run.state.diagnosis.evidence,
                attempt=1,
                traceparent=f"00-{run.traceContext['trace_id']}-{client_span_id}-01",
            )
            run.pendingActions[dispatch.actionId] = dispatch
            run.state.actionLog.append(dispatch)
            run.state.dispatches.append(dispatch)
            run.state.chosenEffect = dispatch.toolName

    effect_done = any(d.phase == "effect" for d in run.state.actionLog) and not run.pendingActions and not run.pendingApprovals
    if effect_done or (not run.effectPlan and not run.pendingActions and not run.pendingApprovals):
        run.state.status = "completed"
    run.state.otlp = build_otlp(run.state, run.traceContext)
    return run