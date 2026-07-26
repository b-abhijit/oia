from __future__ import annotations

from .models import Diagnosis, IncidentRequest


SAFE_EFFECT_HINTS = {
    "rollback": {"bad_deploy", "config_change", "release_regression"},
    "disable": {"feature_flag", "bad_deploy", "traffic_spike"},
    "drain": {"traffic_spike", "capacity_issue"},
    "restart": {"stuck_worker", "memory_leak"},
    "scale": {"traffic_spike", "capacity_issue"},
}


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


def normalize(text: str) -> str:
    return text.strip().lower().replace("-", "_").replace(" ", "_")


def choose_root_cause(req: IncidentRequest) -> str:
    transcript = normalize(req.incident.transcript)
    allowed = [normalize(x) for x in req.incident.allowedRootCauses]

    heuristics = [
        ("bad_deploy", ["deploy", "release", "rollback", "new version"]),
        ("feature_flag", ["feature flag", "flag", "toggle"]),
        ("traffic_spike", ["traffic spike", "surge", "throttle", "load"]),
        ("capacity_issue", ["capacity", "overload", "saturation"]),
        ("db_issue", ["database", "db", "query", "replica"]),
        ("memory_leak", ["memory", "oom"]),
        ("stuck_worker", ["worker", "stuck", "queue"]),
        ("config_change", ["config", "configuration", "misconfig"]),
    ]

    for cause, keywords in heuristics:
        if cause in allowed and any(k.replace(" ", "_") in transcript for k in keywords):
            return cause

    return allowed[0] if allowed else "unknown"


def choose_diagnostics(req: IncidentRequest, evidence: list[str]) -> list[dict]:
    diagnostics = []
    for tool in req.toolCatalog:
        if tool.name in req.policy.effectTools:
            continue
        diagnostics.append(
            {
                "toolName": tool.name,
                "arguments": {
                    "incidentId": req.incident.incidentId,
                    "service": req.incident.service,
                    "severity": req.incident.severity,
                },
                "evidence": evidence[:1],
            }
        )
        if len(diagnostics) >= req.policy.maximumDiagnostics:
            break
    return diagnostics


def choose_effect_plan(req: IncidentRequest, root_cause: str, evidence: list[str]) -> dict | None:
    root = normalize(root_cause)

    for tool in req.toolCatalog:
        if tool.name not in req.policy.effectTools:
            continue

        tool_name = normalize(tool.name)

        for hint, supported_causes in SAFE_EFFECT_HINTS.items():
            if hint in tool_name and root in supported_causes:
                return {
                    "toolName": tool.name,
                    "arguments": {
                        "incidentId": req.incident.incidentId,
                        "service": req.incident.service,
                        "reason": root_cause,
                    },
                    "evidence": evidence,
                    "safeToAutoPropose": True,
                }

    return None


def plan_incident(req: IncidentRequest) -> tuple[Diagnosis, list[dict], dict | None]:
    evidence = choose_evidence_lines(req.incident.transcript, 4)[:2]
    root = choose_root_cause(req)
    diagnosis = Diagnosis(rootCause=root, evidence=evidence)

    diagnostics = choose_diagnostics(req, evidence)
    effect_plan = choose_effect_plan(req, root, evidence)

    return diagnosis, diagnostics, effect_plan