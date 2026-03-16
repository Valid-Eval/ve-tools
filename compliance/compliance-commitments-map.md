# Compliance Commitments Map

*Created: 2026-03-16*
*Source: SSP v1.0, VE-CA-SOP-7, VE-RA-SOP-2, VE-SC-POL-3, VE-SR-SOP-1, plus
supply chain investigation findings (I-1 through I-9)*
*Status: Working draft — will expand as more SSP content is reviewed*

---

## How to Read This Document

Every commitment below comes from a document VE has published or a requirement VE is
subject to. They're organized by operational time horizon — what you need to care about
today vs. this week vs. this month vs. longer.

Each commitment is tagged:

- **Owner**: Who is responsible (Jacob/CTO, Rule4/CISO, InfusionPoints, 3PAO, Dev team)
- **Source**: Which document/requirement creates this obligation
- **Assessor scrutiny**: HIGH / MEDIUM / LOW — how likely a 3PAO or AO is to check this
- **Flexibility**: How much real-world judgment room exists
- **Current state**: What's actually happening today (where known)
- **OS piece**: Which piece of the operating system (1-7) supports this

OS pieces reference:
1. Compliance Picture
2. Attention Engine
3. Decision Record
4. Delegation & Accountability Tracker
5. Compliance Calendar & Cadence
6. Artifact Generator
7. Gap Detector

---

## Daily / Continuous

### Automated scanning runs
- **Owner**: Automated (Inspector2, Dependabot, Grype in CI)
- **Source**: VE-RA-SOP-2 §5.2, ConMon Plan §6.1
- **Assessor scrutiny**: MEDIUM — they want to see scans happen, but daily is above minimum
- **Flexibility**: HIGH — requirement is monthly minimum, daily is a bonus
- **Current state**: Inspector2 runs continuously on ECR. Dependabot runs on GitHub events.
  Grype runs on ve-zarf CI builds. All exceed the monthly minimum.
- **OS piece**: 2 (Attention Engine queries results), 7 (Gap Detector flags if scanning stops)

### CISA KEV / BOD 22-01 monitoring
- **Owner**: Jacob/CTO (no one is currently doing this systematically)
- **Source**: BOD 22-01, FedRAMP guidance, ConMon Plan SI-05
- **Assessor scrutiny**: HIGH — KEV compliance is a FedRAMP focus area
- **Flexibility**: LOW — 14-day deadline is hard, applies to all KEV CVEs
- **Current state**: NOT systematically monitored. Gap.
- **OS piece**: 2 (Attention Engine checks KEV against open findings daily)

### Critical vulnerability notification
- **Owner**: Jacob/CTO, with support from scanning tools
- **Source**: VE-RA-SOP-2 §5.2.3 ("Critical vulns communicated to CTO immediately")
- **Assessor scrutiny**: MEDIUM
- **Flexibility**: LOW — "immediately" means when discovered, not next weekly review
- **Current state**: Inspector2 findings visible in AWS console. Dependabot creates GitHub
  alerts. No unified notification for critical findings across all scanners.
- **OS piece**: 2 (Attention Engine surfaces critical findings at session start)

### Build/CI health
- **Owner**: Dev team
- **Source**: Operational need (not a direct compliance commitment)
- **Assessor scrutiny**: LOW — assessors don't check CI health directly
- **Flexibility**: HIGH
- **Current state**: No monitoring. Failures go undetected for days (A-2).
- **OS piece**: 2 (Attention Engine checks build status)

---

## Weekly

### Vulnerability triage and prioritization
- **Owner**: Jacob/CTO (approves risk ranking), with SA support
- **Source**: VE-RA-SOP-2 §5.1, VE-SC-POL-3 §6.3
- **Assessor scrutiny**: HIGH — they want to see findings are being actively managed
- **Flexibility**: MEDIUM — the 5-day justification window for criticals is tight, but
  the broader triage cadence has room. What matters is that findings don't pile up
  untouched for months.
- **Current state**: Ad-hoc. No regular triage cadence. Findings accumulate.
- **OS piece**: 2 (Attention Engine presents untriaged findings), 3 (Decision Record
  captures dispositions), 5 (Cadence ensures weekly review happens)

### Renovate PR review and merge
- **Owner**: Jacob/CTO + dev team
- **Source**: Operational (supports vuln remediation timelines)
- **Assessor scrutiny**: LOW directly, but HIGH indirectly — unmerged dependency updates
  are the main reason vuln remediation timelines get missed
- **Flexibility**: HIGH — no compliance doc mandates a PR merge cadence
- **Current state**: 20+ open PRs across repos, nobody merging. Renovate configs deployed
  (A-4) but review cadence not established.
- **OS piece**: 2 (Attention Engine shows PR backlog), 5 (Cadence includes PR review)

### Vendor check-ins (where active issues exist)
- **Owner**: Jacob/CTO as Vendor Manager, Rule4 as InfoSec
- **Source**: VE-SR-SOP-1 §5.2 ("at least monthly check-ins"), FedRAMP vendor dependency
  policy (monthly evidence for mitigated High VDs)
- **Assessor scrutiny**: MEDIUM — they'll want evidence of vendor engagement for any
  finding in "vendor-dependency" status
- **Flexibility**: MEDIUM — monthly is the commitment, weekly is only needed when there
  are active vendor-dependent critical/high findings
- **Current state**: Unknown — need to check with Jacob
- **OS piece**: 4 (Delegation Tracker tracks vendor deliverables), 5 (Cadence)

---

## Monthly

### ConMon Executive Summary submission
- **Owner**: Rule4/CISO prepares, Jacob/CTO reviews
- **Source**: VE-CA-SOP-7 Appendix A (CA-05), due end of month
- **Assessor scrutiny**: HIGH — this is the primary ConMon artifact. FedRAMP PMO tracks these.
- **Flexibility**: LOW — monthly submission is a hard commitment. Missing a month is
  a reportable event.
- **Current state**: Unknown — need to confirm with Jacob/Trent what's been submitted
- **OS piece**: 4 (Delegation Tracker ensures Rule4 delivers), 5 (Calendar deadline),
  6 (Artifact Generator can help draft), 1 (Compliance Picture shows submission status)

### Vulnerability & Configuration Scan Results submission
- **Owner**: Jacob/CTO (CSP responsibility per ConMon plan)
- **Source**: VE-CA-SOP-7 Appendix A (RA-05a, CA-07, CM-06), due end of month
- **Assessor scrutiny**: HIGH — scan results are core ConMon evidence
- **Flexibility**: LOW — must include OS/infra, web app, DB, container, and config scans
- **Current state**: Scans run but results aren't being compiled/submitted monthly
  (repository links still TBD per F-6)
- **OS piece**: 6 (Artifact Generator compiles scan results), 5 (Calendar deadline)

### POA&M update submission
- **Owner**: Rule4/CISO maintains, Jacob/CTO reviews
- **Source**: VE-CA-SOP-7 Appendix A (CA-05), due end of month
- **Assessor scrutiny**: HIGH — POA&M is the central compliance tracking artifact
- **Flexibility**: LOW — must reflect current state of all open findings
- **Current state**: Rule4 occasionally provides POA&M tracking documents. Cadence unclear.
- **OS piece**: 4 (Delegation Tracker), 6 (Artifact Generator helps maintain POA&M),
  1 (Compliance Picture shows POA&M health)

### Asset inventory update
- **Owner**: Jacob/CTO
- **Source**: VE-CA-SOP-7 Appendix A (CM-08), due end of month
- **Assessor scrutiny**: MEDIUM — they check it annually, monthly updates are for currency
- **Flexibility**: MEDIUM — inventory should be current but small changes month-to-month
  are normal. What matters is it's not wildly stale.
- **Current state**: Org repo inventory (A-11) and container fleet doc (A-10) exist but
  are not in the format expected for ConMon submission. IIW (Appendix M) format unknown.
- **OS piece**: 6 (Artifact Generator), 7 (Gap Detector flags staleness)

### Vulnerability remediation timeline compliance check
- **Owner**: Jacob/CTO
- **Source**: FedRAMP Rev 5 timelines (Critical=15d, High=30d, Med=90d, Low=180d),
  BOD 22-01 (KEV=14d)
- **Assessor scrutiny**: HIGH — this is what POA&M entries are measured against
- **Flexibility**: LOW on paper. In practice, the key is showing active progress and
  having documented justification for any timeline miss. A finding that's 2 days past
  deadline with an active PR is very different from one that's 60 days past with no action.
- **Current state**: No systematic timeline tracking. No SLA engine.
- **OS piece**: 2 (Attention Engine calculates and surfaces SLA status), 1 (Compliance
  Picture shows overall timeline health)

---

## Quarterly

### Periodic access review
- **Owner**: Jacob/CTO
- **Source**: VE-AC-SOP-10 (Periodic Access Audit Procedure), AC-02
- **Assessor scrutiny**: HIGH — access reviews are a frequent audit finding
- **Flexibility**: LOW — must be done, must be documented. But scope can be practical
  (review who has AWS access, GitHub org access, production cluster access — not every
  permission on every system)
- **Current state**: Procedure exists (VE-AC-SOP-10). Execution cadence unknown.
  Templates exist (VE_Quarterly_Access_Review-infrastructure.pdf,
  VE_Quarterly_Access_Review-super_admin.pdf).
- **OS piece**: 5 (Calendar triggers quarterly), 6 (Artifact Generator produces evidence)

### Vulnerability scan trend report
- **Owner**: Jacob/CTO
- **Source**: VE-SC-POL-3 §6.1.3 ("every quarter, results from all scans assessed and
  recorded in comprehensive report")
- **Assessor scrutiny**: MEDIUM
- **Flexibility**: MEDIUM — the assessor wants to see you know the trend. A simple
  "findings went from X to Y, here's why" is sufficient.
- **Current state**: No trend tracking. Grype artifact retention is only ~17 days.
- **OS piece**: 6 (Artifact Generator), 1 (Compliance Picture)

### Vendor re-evaluation
- **Owner**: Jacob/CTO + Rule4
- **Source**: VE-SR-SOP-1 §5.3 ("at least annually or following significant changes")
- **Assessor scrutiny**: LOW — annual is the commitment, quarterly is proactive
- **Flexibility**: HIGH — annual is the requirement. Quarterly check-ins per VE-SR-SOP-1
  §5.2 are for active monitoring, not full re-evaluation.
- **Current state**: Vendors: AWS, GitHub, Defense Unicorns, Rule4, InfusionPoints.
  Formal evaluation records in Jira unknown.
- **OS piece**: 4 (Delegation Tracker), 5 (Calendar)

### Escalation avoidance KPI review
- **Owner**: Jacob/CTO + Rule4
- **Source**: VE-CA-SOP-7 §6.5 (Table 1, "at least quarterly")
- **Assessor scrutiny**: LOW — nice to have, shows mature program
- **Flexibility**: HIGH — this is internal process improvement
- **Current state**: Not being tracked
- **OS piece**: 1 (Compliance Picture), 5 (Calendar)

---

## Annually

### SSP + supporting docs update
- **Owner**: Rule4 prepares, Jacob/CTO reviews and approves
- **Source**: VE-CA-SOP-7 Appendix A (PL-02c), due mid-November (30 days before assessment)
- **Assessor scrutiny**: HIGH — the SSP is THE artifact. Must be current.
- **Flexibility**: LOW — hard deadline tied to annual assessment cycle
- **Current state**: SSP v1.0 dated 12/4/2024. Currently undergoing periodic review.
- **OS piece**: 4 (Delegation Tracker — Rule4 deliverable), 5 (Calendar)

### Static code analysis methodology update
- **Owner**: Jacob/CTO
- **Source**: VE-CA-SOP-7 Appendix A (SA-11(01), PL-02d), due mid-November
- **Assessor scrutiny**: MEDIUM
- **Flexibility**: MEDIUM — needs to reflect actual practice. SonarQube + Dependabot +
  Grype is the real methodology. Document it once, update when tools change.
- **Current state**: SSP references SonarQube. Actual practice includes more tools.
- **OS piece**: 5 (Calendar), 6 (Artifact Generator)

### Contingency Plan test + results
- **Owner**: Jacob/CTO + relevant team
- **Source**: VE-CA-SOP-7 Appendix A (CP-04a), at least annually, due end of year
- **Assessor scrutiny**: HIGH — CP testing is a common audit focus
- **Flexibility**: LOW — must be done. But "testing" can be a tabletop exercise, doesn't
  have to be a full DR failover. Scale to what's realistic.
- **Current state**: DR/BC Plan exists (VE-SC-SOP-2, 2269 lines). Test execution unknown.
- **OS piece**: 5 (Calendar), 4 (Delegation Tracker)

### Incident Response test + results
- **Owner**: Jacob/CTO + Rule4 + relevant team
- **Source**: VE-CA-SOP-7 Appendix A (IR-03), at least annually, due end of year
- **Assessor scrutiny**: HIGH — IR testing is a common audit focus
- **Flexibility**: LOW — must be done. Can be a tabletop exercise. Document participants,
  scenario, findings, lessons learned.
- **Current state**: IR Plan exists (VE-SSP Appendix I). Test execution unknown.
- **OS piece**: 5 (Calendar), 4 (Delegation Tracker)

### Penetration testing (3PAO)
- **Owner**: 3PAO conducts, Rule4 coordinates
- **Source**: VE-CA-SOP-7 Appendix A (CA-08), annually + ad-hoc
- **Assessor scrutiny**: HIGH — it's done BY the assessor
- **Flexibility**: LOW — required. Timing coordinated with annual assessment.
- **Current state**: Rule4 has conducted pen tests previously.
- **OS piece**: 4 (Delegation Tracker), 5 (Calendar)

### Red team test plan + results
- **Owner**: 3PAO/third party conducts, Rule4 coordinates
- **Source**: VE-CA-SOP-7 Appendix A (CA-08(02)), annually
- **Assessor scrutiny**: HIGH
- **Flexibility**: MEDIUM — required for Moderate, but scope is negotiable with the 3PAO
- **Current state**: Unknown
- **OS piece**: 4 (Delegation Tracker), 5 (Calendar)

### Security awareness training
- **Owner**: Jacob/CTO ensures completion for all personnel
- **Source**: VE-AT-POL-1, VE-AT-SOP-1 (AT-02)
- **Assessor scrutiny**: HIGH — training records are routinely checked
- **Flexibility**: LOW — every person with system access needs documented annual training
- **Current state**: Unknown. Training policy and procedure docs exist.
- **OS piece**: 5 (Calendar), 7 (Gap Detector flags personnel without training records)

### All policy/procedure annual review
- **Owner**: Jacob/CTO reviews, Rule4 may assist
- **Source**: Each policy states "must be reviewed on an annual basis"
- **Assessor scrutiny**: MEDIUM — they check revision history dates
- **Flexibility**: MEDIUM — review can be "reviewed, no changes needed" with updated date.
  Doesn't require rewriting every document. But revision history must show annual touch.
- **Current state**: All current docs show v1.0 from late 2024. Annual review would be
  due by late 2025. (Already past due if the clock started at initial publication?)
- **OS piece**: 5 (Calendar), 7 (Gap Detector flags policies past review date)

---

## Ad-hoc / Event-driven

### CISA Emergency & Binding Operational Directives
- **Owner**: Jacob/CTO
- **Source**: VE-CA-SOP-7 Appendix A (SI-05), "per FedRAMP guidance"
- **Assessor scrutiny**: HIGH when applicable
- **Flexibility**: LOW — when a directive applies, compliance is mandatory
- **Current state**: No systematic monitoring of CISA directives
- **OS piece**: 2 (Attention Engine monitors), 3 (Decision Record documents response)

### Significant change request
- **Owner**: Jacob/CTO + Rule4
- **Source**: FedRAMP Significant Change Process
- **Assessor scrutiny**: HIGH — missed significant changes are a major finding
- **Flexibility**: LOW — must notify AO/PMO of significant changes per FedRAMP policy
- **Current state**: Unknown if any significant changes have occurred since ATO
- **OS piece**: 7 (Gap Detector helps identify if a change qualifies as "significant")

### Security incident response
- **Owner**: Jacob/CTO + Rule4 + InfusionPoints (when operational)
- **Source**: VE-IR-POL-1, IR Plan (Appendix I)
- **Assessor scrutiny**: HIGH when it happens
- **Flexibility**: LOW — response timelines are defined in the IR plan
- **Current state**: IR Plan and templates exist. InfusionPoints SOC will help with
  detection once operational.
- **OS piece**: 3 (Decision Record for incident documentation), 6 (Artifact Generator
  for incident reports using templates)

---

## Not Yet Mapped (need more SSP content review)

- Configuration management baseline monitoring and drift detection
- Backup verification and restoration testing
- Log review and retention compliance
- FIPS cryptographic module validation currency
- Separation of duties enforcement
- Media protection and disposal procedures
- Physical security (if applicable — VE is cloud-hosted)
- CMMC Level 2 practices (separate framework, partially overlapping)

---

## Summary: What Matters Most to Assessors

Based on the commitments above, these are the items where assessor scrutiny is HIGH
and flexibility is LOW — the things that MUST be excellent:

1. **Monthly ConMon deliverables** (executive summary, scans, POA&M, inventory)
2. **Vulnerability remediation timelines** (especially critical/high and KEV)
3. **Annual SSP update** (30 days before assessment)
4. **Annual CP/IR testing** (documented with results)
5. **Penetration testing** (3PAO-conducted)
6. **Security training records** (every person, annually)
7. **Periodic access reviews** (quarterly, documented)
8. **CISA directive compliance** (ad-hoc but mandatory)

Everything else is "must be competent" or "must exist" — important but with more room
for practical judgment about depth and timing.
