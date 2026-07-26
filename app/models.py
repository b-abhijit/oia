from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator

PROFILE = "ga5-incident-agent/v2"


class Sensitive(BaseModel):
    accessToken: str
    privateNote: str


class Incident(BaseModel):
    incidentId: str = Field(min_length=1)
    title: str = Field(min_length=1)
    service: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    transcript: str = Field(min_length=1)
    allowedRootCauses: list[str] = Field(min_length=1)


class ToolCatalogItem(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    maximumDiagnostics: int = Field(ge=1, le=3)
    effectTools: list[str] = Field(default_factory=list)
    approvalRequiredFor: list[str] = Field(default_factory=list)
    doNotExport: list[str] = Field(default_factory=list)


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str
    runId: str = Field(min_length=8)
    agentName: str = Field(min_length=1)
    publicMarker: str = Field(min_length=1)
    sensitive: Sensitive
    incident: Incident
    toolCatalog: list[ToolCatalogItem]
    policy: Policy

    @model_validator(mode="after")
    def validate_profile(self):
        if self.profile != PROFILE:
            raise ValueError("unsupported profile")
        return self


class Outcome(BaseModel):
    actionId: str
    callId: str
    attempt: int = Field(ge=1)
    status: int | None = None
    resultClass: str | None = None
    nonce: str | None = None
    errorType: str | None = None


class ApprovalDecision(BaseModel):
    approvalId: str
    decision: Literal["approved", "denied"]
    nonce: str


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receiptId: str = Field(min_length=8)
    outcomes: list[Outcome] = Field(default_factory=list)
    approvals: list[ApprovalDecision] = Field(default_factory=list)


class Dispatch(BaseModel):
    actionId: str
    callId: str
    phase: Literal["diagnostic", "effect"]
    toolName: str
    arguments: dict[str, Any]
    evidence: list[str] = Field(default_factory=list)
    attempt: int
    traceparent: str
    approvalId: str | None = None
    approvalNonce: str | None = None


class ApprovalRequest(BaseModel):
    approvalId: str
    actionId: str
    toolName: str
    argumentsDigest: str


class Diagnosis(BaseModel):
    rootCause: str
    evidence: list[str] = Field(min_length=2, max_length=4)


class ToolReceiptLog(BaseModel):
    receiptId: str
    actionId: str
    callId: str
    attempt: int
    status: int | None = None
    resultClass: str | None = None
    nonce: str | None = None
    errorType: str | None = None


class ApprovalReceiptLog(BaseModel):
    receiptId: str
    approvalId: str
    decision: str
    nonce: str


class RunState(BaseModel):
    runId: str
    status: Literal["waiting", "completed", "failed"]
    diagnosis: Diagnosis
    chosenEffect: str | None = None
    suppressed: list[str] = Field(default_factory=list)
    actionLog: list[Dispatch] = Field(default_factory=list)
    receiptLog: list[ToolReceiptLog | ApprovalReceiptLog] = Field(default_factory=list)
    dispatches: list[Dispatch] = Field(default_factory=list)
    approvals: list[ApprovalRequest] = Field(default_factory=list)
    otlp: dict[str, Any] = Field(default_factory=dict)


class StoredRun(BaseModel):
    requestHash: str
    requestBody: dict[str, Any]
    state: RunState
    pendingActions: dict[str, Dispatch] = Field(default_factory=dict)
    pendingApprovals: dict[str, ApprovalRequest] = Field(default_factory=dict)
    effectPlan: dict[str, Any] | None = None
    traceContext: dict[str, str | None]
    plannerUsed: bool = False
    receipts: dict[str, str] = Field(default_factory=dict)