"""Keyword-based ATT&CK worksheets for lab investigation."""
from __future__ import annotations
from dataclasses import dataclass
from .models import ThreatRecord


@dataclass(frozen=True)
class Hypothesis:
    trigger: str
    technique: str
    tactic: str
    telemetry: str
    analyst_question: str
    lab_exercise: str


RULES = (
    Hypothesis("ransomware", "T1486 – Data Encrypted for Impact", "Impact",
               "Windows Security 4663 (if configured), EDR file events, Sysmon 1/11",
               "Do correlated file-write bursts and process activity suggest encryption?",
               "Generate harmless bulk file-renaming events inside an isolated test folder, then inspect logs."),
    Hypothesis("phishing", "T1566 – Phishing", "Initial Access",
               "Email gateway headers, reported messages, URL click telemetry",
               "Does the email contain spoofing indicators or high-risk URLs?",
               "Use a synthetic .eml sample and document header anomalies without sending mail."),
    Hypothesis("powershell", "T1059.001 – PowerShell", "Execution",
               "PowerShell operational 4104 (if enabled), Windows 4688, Sysmon 1",
               "Can encoded or unexpected PowerShell activity be explained?",
               "Run a benign local PowerShell command and verify command-line logging."),
    Hypothesis("cloud storage", "T1530 – Data from Cloud Storage Object", "Collection",
               "Cloud storage access logs and IAM audit events",
               "Are there unusual reads or broad access permissions on sensitive objects?",
               "Inspect synthetic bucket access policies and an audit-log fixture."),
    Hypothesis("authentication bypass", "T1190 – Exploit Public-Facing Application", "Initial Access",
               "Reverse proxy/WAF and application authentication logs",
               "Is there suspicious unauthenticated traffic to an exposed service?",
               "Review generated access logs and look for repeated unexpected 2xx responses."),
)


def hypotheses(threat: ThreatRecord) -> list[Hypothesis]:
    content = f"{threat.title} {threat.summary}".lower()
    return [r for r in RULES if r.trigger in content]


def playbook(threat: ThreatRecord) -> str:
    lines = [f"# Detection hypothesis | {threat.title}", "",
             "> These keyword matches suggest what to investigate. They are not observed adversary behavior or tested detection rules.",
             "", f"Evidence: {threat.url}", f"Synthetic scenario: {'YES' if threat.is_demo else 'NO'}", ""]
    relevant = hypotheses(threat)
    if not relevant:
        lines += ["No worksheet matches the keywords in this case.",
                  "Read the original advisory, then choose logs that could help test your explanation."]
    else:
        for h in relevant:
            lines += [f"## {h.technique}", f"- ATT&CK tactic: {h.tactic}",
                      f"- Logs to review: {h.telemetry}", f"- Triage question: {h.analyst_question}",
                      f"- Lab exercise: {h.lab_exercise}", ""]
    lines += ["## Validation checklist", "- [ ] Confirm product/version relevance",
              "- [ ] Verify telemetry exists and collection is permitted",
              "- [ ] Reproduce benign test event in an isolated lab",
              "- [ ] Record expected and observed results",
              "- [ ] Document false positives and coverage gaps"]
    return "\n".join(lines)
