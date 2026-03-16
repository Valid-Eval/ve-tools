# Compliance Operating System

Data files supporting Valid Eval's compliance management across FedRAMP Moderate,
IL-4/IL-5, and CMMC Level 2 frameworks.

## Structure

```
compliance/
  calendar/
    recurring.yaml        — Recurring compliance obligations (monthly/quarterly/annual)
  decisions/
    dispositions.yaml     — Vulnerability finding dispositions
    risk-acceptances.yaml — Formal risk acceptance decisions
    suppressions.yaml     — Finding suppression rules with rationale
  delegations/
    tracker.yaml          — Cross-party commitments and deliverables
```

## How This Is Used

These files are read and written by the `/compliance` Claude skill (in `valid-eval-skills`).
The skill queries live data sources (Inspector2, Dependabot, Grype, GitHub) and combines
that with the human decisions recorded here to produce status views, triage workflows,
and compliance artifacts.

**Key principle**: Scanner data stays in its source systems. Only human decisions
(dispositions, risk acceptances, suppressions) are stored here. Everything else is
queried on demand.

## Ownership

- **CTO** (Jacob Ablowitz) owns these files and approves all disposition/risk decisions
- **Rule4 / CISO** contributes to ConMon deliverable tracking
- Changes to decision files should go through PR review for audit trail
