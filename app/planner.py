from __future__ import annotations

from .models import Diagnosis, IncidentRequest


def choose_evidence_lines(transcript: str, maximum: int = 4) -> list[str]:
    evidence = []
    for line in transcript.splitlines():
        line = line.strip()
        if line.startswith("[") and "]" in line:
            ev = line[1:line.index("]")].strip()
            if ev and ev not in evidence:
                evidence.append(ev)
        if len(evidence) >= maximum:
            break
    while len(evidence) < 2:
        evidence.append(f"ev_fallback_{len(evidence)+1}")
    return evidence[:maximum]


def plan_incident(req: IncidentRequest) -> tuple[Diagnosis, list[dict], dict | None]:
    root = req.incident.allowedRootCauses[0]
    evidence = choose_evidence_lines(req.incident.transcript, 4)[:2]
    diagnosis = Diagnosis(rootCause=root, evidence=evidence)

    diagnostics = []
    for tool in req.toolCatalog:
        if tool.name in req.policy.effectTools:
            continue
        diagnostics.append({
            "toolName": tool.name,
            "arguments": {
                "incidentId": req.incident.incidentId,
                "service": req.incident.service,
                "severity": req.incident.severity,
            },
            "evidence": evidence[:1],
        })
        if len(diagnostics) >= req.policy.maximumDiagnostics:
            break

    effect_plan = None
    for tool in req.toolCatalog:
        if tool.name in req.policy.effectTools:
            effect_plan = {
                "toolName": tool.name,
                "arguments": {
                    "incidentId": req.incident.incidentId,
                    "service": req.incident.service,
                    "reason": diagnosis.rootCause,
                },
                "evidence": evidence,
            }
            break
    return diagnosis, diagnostics, effect_plan