# Compliance Operating System — Design & Vision

*Valid Evaluation, Inc.*
*Draft: 2026-03-16*

---

## The Problem

Valid Eval is a small company (<20 employees) with FedRAMP Moderate, IL-4/IL-5, and
CMMC Level 2 compliance obligations. These frameworks create an enormous surface area
of operational responsibilities — vulnerability management, continuous monitoring,
configuration management, access reviews, incident response testing, security training,
vendor management, and more — that must be actively maintained, evidenced, and reported.

Today, compliance management is distributed across multiple systems with no unified view:
- Vulnerability scanners (AWS Inspector2, Grype, Dependabot) each report independently
- ConMon deliverables are coordinated between VE and Rule4 without centralized tracking
- POA&M management relies on periodic document exchanges
- Recurring obligations (monthly scans, quarterly access reviews, annual testing) live in
  policy documents but have no operational tracking or reminders
- The SSP and its supporting documents are maintained by Rule4 but there is no systematic
  way to verify that stated commitments are being met in practice

The result: **the CTO often doesn't have a clear, current picture of what's going on
with compliance without actively pulling information from every source.** Things that
matter can fall through cracks, and when auditors, the FedRAMP PMO, or DoD stakeholders
ask questions, answering takes days of data gathering rather than minutes.

## The Goal

Build an operating system — a combination of tooling, process, and data — that makes
managing this broad set of responsibilities as tractable as possible for a small team.

**Specifically:**
- Surface what needs attention, organized by time horizon (today / this week / this
  month / longer term)
- Track that work is getting done by the right people (VE team, Rule4, InfusionPoints,
  3PAO) on the right timeline
- Maintain the audit trail of human decisions (dispositions, risk acceptances) that
  auditors need to see
- Generate compliance artifacts (ConMon reports, POA&M, scan summaries) from live data
  rather than manual compilation
- Proactively identify gaps before they become audit findings

**Equally important — what this is NOT:**
- Not a replacement for Rule4's CISO/InfoSec role or their SSP authoring work
- Not a replacement for InfusionPoints' SOC/ConMon monitoring (once operational)
- Not a vulnerability scanner (Inspector2, Grype, Dependabot handle that)
- Not a project management tool (Jira handles feature/dev work)
- Not an enterprise GRC platform — it must be operable by one person

## Design Principles

**1. Documents align to requirements. Operations account for reality.**
The SSP, policies, and procedures must match FedRAMP/CMMC requirements exactly. But
day-to-day operations must make practical judgment calls about where limited resources
go. Not all commitments carry equal weight — the system helps identify which ones matter
most to assessors and which have more flexibility.

**2. Lens, not warehouse.**
Scanner data stays in its source systems (AWS Console, GitHub, CI artifacts). The system
queries it on demand and synthesizes a prioritized view. No data replication, no ingestion
pipelines, no normalization infrastructure.

**3. Store only human decisions.**
The only new persistent data is what a human decided: vulnerability dispositions, risk
acceptances, suppression rationale, architecture choices. These are the audit artifacts
a 3PAO wants to see. Everything else is derived at query time.

**4. Assessor impact drives priority.**
Items are categorized by assessor scrutiny and real-world flexibility:
- **Must be excellent**: Monthly ConMon deliverables, vuln remediation timelines for
  critical/high/KEV, annual CP/IR testing, access reviews, training records
- **Must be competent**: Medium/low findings triaged, processes documented, reference
  docs current
- **Must exist**: Policies reviewed annually, plans on file, low-priority items acknowledged

**5. One person can run this.**
Steady-state operating time target: ~5 min/day (check for urgent items), ~30-60 min/week
(triage session), ~2-4 hours/month (ConMon deliverables), plus heavier quarterly and
annual activities. AI assistance handles the data gathering and synthesis.

## Architecture: Seven Pieces

### 1. Compliance Picture
A current, honest view of status across all compliance domains — generated on demand,
not maintained as a static document. Shows what's on track, what's at risk, what's
overdue. Could be handed to an auditor, AO, or CEO for a snapshot of "how are we doing?"

### 2. Attention Engine
The AI layer that answers "what needs my attention right now?" — implemented as a Claude
Code skill (`/compliance`) with subcommands organized by time horizon:

| Command | What it does |
|---------|-------------|
| `/compliance status` | Generate the full Compliance Picture |
| `/compliance today` | SLA breaches, KEV CVEs, broken builds, overdue items |
| `/compliance week` | Untriaged findings, Renovate PRs to merge, approaching SLAs |
| `/compliance month` | ConMon deliverable checklist, monthly deadlines |
| `/compliance triage` | Interactive vulnerability disposition workflow |
| `/compliance report <type>` | Generate specific compliance artifacts |

The skill queries live data sources (Inspector2 via AWS CLI, Dependabot via GitHub API,
Grype from CI artifacts, CISA KEV catalog, GitHub PR status) and combines that with the
decision record to produce prioritized output.

### 3. Decision Record
Git-tracked YAML files recording human judgments:
- **Dispositions**: What was decided about each vulnerability finding
- **Risk acceptances**: Formal risk acceptance with rationale and review dates
- **Suppressions**: Rules for auto-suppressing noise (e.g., test-only images)
- **Architecture decisions**: Tooling and process choices for the OS itself

Git history IS the audit trail — every change is a commit with context.

### 4. Delegation & Accountability Tracker
A simple YAML file tracking who owes what, by when, across all parties: VE team, Rule4,
InfusionPoints, 3PAO, individual team members. The `/compliance` skill checks this daily
and flags overdue items.

### 5. Compliance Calendar
A YAML definition of all recurring obligations — monthly ConMon deliverables, quarterly
access reviews, annual testing, policy reviews, training deadlines — derived from the
SSP and its supporting documents. The skill uses this to auto-generate reminders and
verify that obligations are being met on schedule.

### 6. Artifact Generator
On-demand generation of compliance deliverables from live data + decision records. Produces
DRAFTS — human reviews and approves before submission. Accelerates preparation from days
of data gathering to minutes of review.

### 7. Gap Detector
Integrated into the daily/weekly Attention Engine flow. Checks for: policies past review
date, scanner coverage gaps, overdue delegations, findings past SLA with no disposition,
vendor dependencies without check-in evidence, reference docs past staleness threshold.

## Data Structure

All compliance OS data lives in `ve-tools/compliance/`:

```
compliance/
  calendar/
    recurring.yaml          — All recurring obligations
  decisions/
    dispositions.yaml       — Vulnerability finding dispositions
    risk-acceptances.yaml   — Formal risk acceptance decisions
    suppressions.yaml       — Finding suppression rules
    architecture.yaml       — OS architecture/tooling decisions
  delegations/
    tracker.yaml            — Cross-party commitments
```

This is intentionally small. The decision record will grow as triage sessions populate
it, but we're talking hundreds of entries, not thousands — because scanner data isn't
replicated here.

## Operational Commitments

A full mapping of every recurring compliance obligation — sourced from VE-CA-SOP-7
(Continuous Monitoring Plan), VE-RA-SOP-2, VE-SC-POL-3, and FedRAMP Rev 5 — is in
`compliance-commitments-map.md`. Summary of the highest-scrutiny items:

**Monthly (to AO):**
- ConMon Executive Summary (Rule4 prepares, CTO reviews)
- Vulnerability & configuration scan results
- POA&M updates
- Asset inventory updates

**Quarterly:**
- Infrastructure + application access reviews
- Vulnerability trend report

**Annually:**
- SSP + supporting docs update (30 days before assessment — mid-November)
- Contingency Plan testing + results
- Incident Response testing + results
- Penetration testing (3PAO)
- Security awareness training for all personnel
- All policies annual review

**Ad-hoc:**
- CISA Emergency/Binding Operational Directive compliance (BOD 22-01: KEV CVEs within 14 days)
- Significant change notifications to AO/PMO

## SSP Review Findings

During the process of designing this system, we reviewed the ConMon Plan (VE-CA-SOP-7),
Vulnerability Management Policy (VE-SC-POL-3), Vulnerability Management Procedure
(VE-RA-SOP-2), and other supporting documents. Seven findings were identified that
should be addressed during the current SSP periodic review cycle. These are documented
in `ssp-review-findings.md` and include:

- **F-1 (HIGH)**: Remediation timelines contradict each other between policy and procedure
- **F-3 (MEDIUM)**: Grype (primary infrastructure scanner) not referenced in SSP
- **F-4 (MEDIUM)**: BOD 22-01 / CISA KEV 14-day requirement not addressed in any document

Full details and recommendations in the findings document.

## Vulnerability Management: Three-Scanner Model

VE operates three vulnerability scanners, each covering a different layer. No single
scanner provides complete coverage.

| Scanner | Coverage | Authoritative For |
|---------|----------|-------------------|
| AWS Inspector2 | ECR container images (deployed) | App-layer container vulns |
| Grype | SBOM-based, runs in ve-zarf CI | Infrastructure/OS-level container vulns |
| Dependabot | GitHub app-layer dependencies | Ruby gems, npm, Python packages |

**Key finding from investigation**: Inspector2 reports 0 findings on infrastructure
images where Grype finds 1,279. This means 77% of total container vulnerability
findings are invisible to Inspector2. Both scanners are necessary.

The `/compliance` skill queries all three sources on demand and synthesizes a unified
view, with dedup happening at query time (AI-assisted) rather than through a persistent
normalization pipeline.

## Remediation Timelines

FedRAMP Rev 5 governs (note: VE's own policy documents have inconsistencies here — see
F-1 in SSP findings):

| Severity | Remediation Deadline | Notes |
|----------|---------------------|-------|
| Critical | 15 calendar days | |
| High | 30 calendar days | |
| Medium | 90 calendar days | |
| Low | 180 calendar days | |
| KEV-listed | 14 calendar days | BOD 22-01, regardless of CVSS severity |

Clock starts on CVE publication date or VE awareness (whichever is first).
Clock stops on remediation scan verification (not code commit or deploy).

## Implementation Status

| Component | Status |
|-----------|--------|
| Data foundation (calendar, decisions, delegations) | Built, in PR |
| Design document (this file) | Draft |
| Commitments map | Complete |
| SSP review findings | 7 findings documented, SSP review ongoing |
| `/compliance` skill | Not yet built |
| First vulnerability triage | Not yet done |
| CMMC endpoint integration | Not yet scoped |

## Open Questions

Twenty open questions are documented in `compliance-os-design.md` covering:
- **Current state** (#1-10): What's actually happening today with ConMon deliverables,
  access reviews, training, POA&Ms, etc.
- **Design** (#11-15): Data location, approval workflows, Jira integration
- **CMMC** (#16-20): Timeline, gap assessment, endpoint tooling

These do not block the current work but must be answered to complete the implementation.

## How to Provide Feedback

This is a PR in `ve-tools` (branch: `feature/compliance-os-foundation`). Review the
files, comment on the PR or specific lines, and flag anything that doesn't match your
understanding of how things work or should work. Key areas where feedback is especially
valuable:

- **Calendar accuracy**: Are the recurring obligations correct? Missing any?
- **Delegation tracker**: Are the current items and owners right?
- **SSP findings**: Do the recommendations make sense? Any findings to add?
- **Design philosophy**: Does the "assessor impact drives priority" framework resonate,
  or should we approach this differently?
- **Skill architecture**: One `/compliance` skill vs. multiple? (ARCH-002, pending)
