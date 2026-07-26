from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict, model_validator


class ToolSpec(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None


class Policy(BaseModel):
    effectTools: list[str] = Field(default_factory=list)
    approvalRequiredFor: list[str] = Field(default_factory=list)
    maximumDiagnostics: int = Field(default=1, ge=0, le=10)
    doNotExport: list[str] = Field(default_factory=list)


class Sensitive(BaseModel):
    accessToken: str = Field(min_length=1)
    privateNote: str = Field(min_length=1)


class Incident(BaseModel):
    incidentId: str = Field(min_length=1)
    title: str = Field(min_length=1)
    service: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    transcript: str = Field(min_length=1)
    allowedRootCauses: list[str] = Field(min_length=1)


class IncidentRequest(BaseModel):
    profile: str = Field(min_length=1)
    runId: str = Field(min_length=8)
    agentName: str = Field(min_length=1)
    publicMarker: str = Field(min_length=1)
    sensitive: Sensitive
    incident: Incident
    toolCatalog: list[ToolSpec] = Field(min_length=1)
    policy: Policy

    @model_validator(mode="after")
    def validate_request(self):
        if self.policy.maximumDiagnostics > len(self.toolCatalog):
            self.policy.maximumDiagnostics = len(self.toolCatalog)
        return self


class Diagnosis(BaseModel):
    rootCause: str
    evidence: list[str]


class Dispatch(BaseModel):
    actionId: str
    callId: str
    phase: Literal["diagnostic", "effect"]
    toolName: str
    arguments: dict[str, Any]
    evidence: list[str] = Field(default_factory=list)
    attempt: int = 1
    traceparent: str
    approvalId: str | None = None
    approvalNonce: str | None = None


class ApprovalRequest(BaseModel):
    approvalId: str
    actionId: str
    toolName: str
    argumentsDigest: str


class ToolOutcome(BaseModel):
    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: str
    nonce: str | None = None
    errorType: str | None = None


class ApprovalOutcome(BaseModel):
    approvalId: str
    decision: Literal["approved", "rejected"]
    nonce: str | None = None


class ReceiptRequest(BaseModel):
    receiptId: str = Field(min_length=1)
    outcomes: list[ToolOutcome] = Field(default_factory=list)
    approvals: list[ApprovalOutcome] = Field(default_factory=list)


class ToolReceiptLog(BaseModel):
    receiptId: str
    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: str
    nonce: str | None = None
    errorType: str | None = None


class ApprovalReceiptLog(BaseModel):
    receiptId: str
    approvalId: str
    decision: Literal["approved", "rejected"]
    nonce: str | None = None


class RunState(BaseModel):
    runId: str
    status: Literal["waiting", "completed"] = "waiting"
    diagnosis: Diagnosis
    chosenEffect: str | None = None
    suppressed: list[str] = Field(default_factory=list)
    actionLog: list[Dispatch] = Field(default_factory=list)
    receiptLog: list[ToolReceiptLog | ApprovalReceiptLog] = Field(default_factory=list)
    dispatches: list[Dispatch] = Field(default_factory=list)
    approvals: list[ApprovalRequest] = Field(default_factory=list)
    otlp: dict[str, Any] = Field(default_factory=dict)


class StoredRun(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    requestHash: str
    requestBody: dict[str, Any]
    state: RunState
    pendingActions: dict[str, Dispatch] = Field(default_factory=dict)
    pendingApprovals: dict[str, ApprovalRequest] = Field(default_factory=dict)
    effectPlan: dict[str, Any] | None = None
    traceContext: dict[str, Any] = Field(default_factory=dict)
    plannerUsed: bool = True
    receipts: dict[str, str] = Field(default_factory=dict)