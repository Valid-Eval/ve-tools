# SSP & Policy Document Review Findings

*Created: 2026-03-16*
*Purpose: Issues identified during compliance operating system design work that should
be addressed during the current SSP periodic review cycle.*
*For: Trent Hein (Rule4 / CISO), Jacob Ablowitz (CTO)*

---

## How to Use This Document

Each finding has a severity (how much it matters to an assessor), a recommendation, and
the source documents involved. Findings are append-only — new issues get added as they're
discovered through ongoing analysis of SSP content and supporting documents.

---

## F-1: Vulnerability Remediation Timeline Inconsistency Across Documents

**Severity**: HIGH — a 3PAO will compare these documents and flag the conflict

**Finding**: FOUR sources define different remediation timelines for the same severity levels:

| Severity | SSP RA-5(d) | SSP SI-2(3) | VE-RA-SOP-2 | VE-SC-POL-3 | FedRAMP Rev 5 |
|----------|-------------|-------------|-------------|-------------|---------------|
| Critical | **30 days** | **30 days** | 30 days | 15 days | **15 days** |
| High | 30 days | 30 days | 30 days | 35 days | 30 days |
| Medium | 90 days | 90 days | 90 days | 180 days | 90 days |
| Low | 180 days | 180 days | 180 days | 360 days | 180 days |

The SSP (Appendix A v0.8) states 30 days for Critical in both RA-5(d) and SI-2(3)(b).
FedRAMP Rev 5 requires 15 days for Critical. This means the SSP itself commits to a
timeline that does NOT meet FedRAMP requirements for critical vulnerabilities.

VE-SC-POL-3 (the policy) actually has the correct 15-day critical timeline but has
incorrect values for Medium (180d vs 90d required) and Low (360d vs 180d required),
citing Iron Bank Acceptance Baseline Criteria rather than FedRAMP Rev 5.

**Risk**: HIGH. A 3PAO will compare the SSP control implementation to FedRAMP requirements
and flag that Critical=30d exceeds the 15-day requirement. They will also find the policy
and procedure documents disagree with each other and with the SSP. This is a multi-document
inconsistency that suggests the timelines were not systematically derived from a single
authoritative source.

**Recommendation**: Establish FedRAMP Rev 5 as the sole authoritative source for
remediation timelines. Update ALL documents to match:
- Critical: 15 calendar days
- High: 30 calendar days
- Medium: 90 calendar days
- Low: 180 calendar days
- KEV-listed: 14 calendar days (BOD 22-01 — see F-4)

**Documents involved**:
- SSP Appendix A, RA-5(d) implementation (line ~24530 in extracted text)
- SSP Appendix A, SI-2(3)(b) parameter and implementation (line ~29437, ~29486)
- `VE-RA-SOP-2_Vulnerability_Management_Procedure.pdf` (Section 5.1.2)
- `VE-SC-POL-3_Vulnerability_Management_Policy.pdf` (Section 6.3.2)

---

## F-2: Vulnerability Justification Timeline Not Reflected in Procedure

**Severity**: MEDIUM — operationally important, assessor may or may not check

**Finding**: VE-SC-POL-3 (Policy) defines vulnerability *justification* timelines — the
window to document WHY a vulnerability exists, separate from fixing it:

| Severity | Justification Deadline |
|----------|----------------------|
| Critical | 5 calendar days |
| High | 10 calendar days |
| Medium | 30 calendar days |
| Low | 60 calendar days |

These timelines do not appear in VE-RA-SOP-2 (Procedure), which is the document that
describes the actual operational workflow. If the policy commits to 5-day justification
for criticals, the procedure should describe how that happens.

**Risk**: Operationally, nobody will hit a 5-day justification window if the procedure
doesn't describe the workflow for doing so. An assessor checking policy-to-procedure
alignment will note the gap.

**Recommendation**: Either add justification workflow steps to VE-RA-SOP-2, or evaluate
whether these timelines are realistic for VE's team size and adjust the policy accordingly.

**Documents involved**:
- `VE-SC-POL-3_Vulnerability_Management_Policy.pdf` (Section 6.3.1)
- `VE-RA-SOP-2_Vulnerability_Management_Procedure.pdf` (missing)

---

## F-3: Grype Scanner Not Referenced in SSP or Vulnerability Management Docs

**Severity**: MEDIUM — SSP should accurately reflect the tools in use

**Finding**: The SSP (Table 8.1) and VE-RA-SOP-2 list the following vulnerability scanning
tools: AWS Inspector, AWS Config, GitHub Dependabot, SonarQube. However, Grype (run via
the ve-zarf CI pipeline) is the authoritative scanner for infrastructure/container images
and finds 1,279 findings that Inspector2 misses entirely on those same images. Grype is
actively in use and produces the most comprehensive container vulnerability data.

**Risk**: If an assessor asks "what tools do you use for container scanning?" and the answer
is Inspector2, but the actual data shows Grype is the primary source for infrastructure
images, there's a credibility gap. Conversely, if Grype findings are presented to an
assessor, they'll want to see it referenced in the SSP.

**Recommendation**: Add Grype to the scanning tools table in the SSP (Table 8.1) and to
VE-RA-SOP-2 Section 5.2. Describe the three-scanner model: Inspector2 (ECR/deployed images),
Grype (SBOM-based, infrastructure/container images), Dependabot (app-layer dependencies).

**Documents involved**:
- SSP Section 8, Table 8.1
- `VE-RA-SOP-2_Vulnerability_Management_Procedure.pdf` (Section 5.2)

---

## F-4: BOD 22-01 / CISA KEV 14-Day Override Not Addressed in Policy

**Severity**: MEDIUM — FedRAMP explicitly requires this

**Finding**: CISA Binding Operational Directive 22-01 requires remediation of Known
Exploited Vulnerabilities (KEV) within 14 days, regardless of CVSS severity. FedRAMP
has confirmed this applies to CSPs. Neither VE-SC-POL-3 nor VE-RA-SOP-2 mention BOD 22-01,
KEV, or a 14-day override.

The ConMon plan (VE-CA-SOP-7) references "Security Alerts, Advisories & Directives" as
an ad-hoc activity (SI-05) but does not specifically call out the KEV 14-day requirement.

**Risk**: If a KEV-listed CVE is discovered and VE follows the standard 30-day Critical
timeline instead of the 14-day BOD 22-01 timeline, it would be a compliance gap that
an assessor would flag.

**Recommendation**: Add KEV/BOD 22-01 language to VE-SC-POL-3 and VE-RA-SOP-2 specifying
that KEV-listed vulnerabilities follow a 14-day remediation timeline regardless of CVSS
severity. Reference the CISA KEV catalog as a monitoring source.

**Documents involved**:
- `VE-SC-POL-3_Vulnerability_Management_Policy.pdf`
- `VE-RA-SOP-2_Vulnerability_Management_Procedure.pdf`
- `VE-CA-SOP-7_Continuous_Monitoring_Plan.pdf`

---

## F-5: InfusionPoints SOC/ConMon Role Not Reflected in Documents

**Severity**: LOW (for now) — will become MEDIUM once InfusionPoints is operational

**Finding**: InfusionPoints is being onboarded to provide Continuous Monitoring / SOC-as-a-
Service. None of the current SSP documents reference this vendor or their role. As their
services come online, the following documents will need updates:

- ConMon Plan (VE-CA-SOP-7): Roles & Responsibilities, monitoring activities
- SSP Table 8.1: Security and Management Technologies
- SSP Table 7.1: External Systems/Services (if InfusionPoints tools connect to VE infra)
- SCRM Plan (VE-SR-SOP-1): Vendor evaluation record for InfusionPoints

**Risk**: Low risk now since they're still spooling up. Once operational, an assessor
would expect to see the SOC provider reflected in the ConMon plan.

**Recommendation**: Track this as a follow-up item for after InfusionPoints is operational.
Ensure vendor evaluation per VE-SR-SOP-1 Section 5.1 is documented in Jira.

---

## F-6: ConMon Deliverable Repository Links Are TBD

**Severity**: LOW — normal for a new SSP, but needs resolution

**Finding**: Every deliverable in VE-CA-SOP-7 Appendix A lists "Link: [Repository Link -
TBD]" for the designated repository where deliverables are submitted to the AO.

**Risk**: Without a designated repository, there's no defined mechanism for delivering
ConMon artifacts to the AO. This is expected for a pre-ATO SSP but should be resolved
as the authorization process progresses.

**Recommendation**: Establish the ConMon deliverable repository (likely a FedRAMP
repository or shared location agreed with the sponsoring agency) and update all
references in VE-CA-SOP-7 Appendix A.

---

## F-7: Vulnerability Scanning Frequency Inconsistency

**Severity**: LOW — both are defensible, but should be consistent

**Finding**: VE-SC-POL-3 (Policy) Section 6.1.2 states scanning should be performed "at
a minimum quarterly." VE-RA-SOP-2 (Procedure) Section 5.2.1 states "at a minimum monthly."
The ConMon plan commits to monthly scan submissions to the AO.

Actual practice exceeds both: internal tools (Inspector2, Dependabot, Grype in CI) run
daily or on every build.

**Risk**: Minor inconsistency. The procedure and ConMon plan are more restrictive (monthly)
which is fine. The policy saying "quarterly" could be read as allowing less frequent
scanning than what the ConMon plan commits to.

**Recommendation**: Align the policy minimum to "monthly" to match the procedure and
ConMon plan. Note that actual practice exceeds this minimum.

**Documents involved**:
- `VE-SC-POL-3_Vulnerability_Management_Policy.pdf` (Section 6.1.2)
- `VE-RA-SOP-2_Vulnerability_Management_Procedure.pdf` (Section 5.2.1)
- `VE-CA-SOP-7_Continuous_Monitoring_Plan.pdf` (Appendix A)

---

## F-8: SSP Appendix A Version Mismatch with SSP Main Body

**Severity**: LOW — minor, but an assessor may note it

**Finding**: The SSP main body is version 1.0 (dated 12/4/2024). Appendix A (Security
Controls) is version 0.8 (dated 12/31/2024). The appendix is newer but has a lower
version number, suggesting it may not have been finalized alongside the main body.

**Risk**: An assessor may question whether Appendix A is the final version or a draft.
The v0.8 designation suggests it was still being refined when the SSP was submitted.

**Recommendation**: Align version numbers during the current review cycle.

**Documents involved**:
- SSP main body (v1.0, 12/4/2024)
- SSP Appendix A (v0.8, 12/31/2024)

---

## F-9: SSP References NeuVector But Not in Security Tools Table

**Severity**: LOW — completeness issue

**Finding**: The CA-7 implementation narrative (Part b) mentions "NeuVector is incorporated
for container security" but NeuVector does not appear in Table 8.1 (Security and Management
Technologies). If NeuVector is deployed, it should be in the tools inventory. If it is NOT
deployed (aspirational language), the SSP should not claim it.

**Risk**: An assessor asking about container security tooling may reference this claim.
If NeuVector is not actually deployed, this is a misrepresentation.

**Recommendation**: Either add NeuVector to Table 8.1 (if deployed) or remove the
reference from the CA-7 narrative (if not deployed). Verify actual deployment status.

**Documents involved**:
- SSP Appendix A, CA-7 Part b implementation narrative
- SSP Table 8.1 (Security and Management Technologies)

---

## F-10: SSP Scanning Frequency Inconsistency with ConMon Plan

**Severity**: LOW — the more frequent commitment is the one that matters

**Finding**: The SSP's CA-7 Part a states "regular bi-weekly vulnerability scans" as a
monitored metric. The ConMon plan commits to monthly scan submission to the AO. The
Vulnerability Management Policy says quarterly minimum. Actual practice (Inspector2,
Dependabot, Grype) is continuous/daily.

All three are defensible since "at least" language applies, but the SSP's "bi-weekly"
creates a specific commitment that's different from the monthly cadence in the ConMon plan.

**Risk**: Minor. The monthly ConMon deliverable is the binding commitment. An assessor
is unlikely to hold VE to the bi-weekly claim specifically, but consistency across
documents is always better.

**Recommendation**: Align language. Consider stating scanning is "continuous" with
"results compiled and submitted monthly" to match actual practice and the ConMon plan.

**Documents involved**:
- SSP Appendix A, CA-7 Part a
- VE-CA-SOP-7 Appendix A (monthly scan submission)
- VE-SC-POL-3 §6.1.2 (quarterly minimum)

---

## F-11: SSP Supply Chain Control References Only Inspector + SonarQube

**Severity**: MEDIUM — supply chain controls should reflect actual tooling

**Finding**: The SR-2 implementation (Part a) states supply chain risks are managed with
"continuous, automated vulnerability scanning using AWS Inspector and SonarQube." This
omits Grype (primary infrastructure image scanner), Dependabot (app-layer dependencies),
and Renovate (automated dependency updates) — all of which are actively used and central
to VE's actual supply chain risk management.

This is the same class of issue as F-3 (Grype not in SSP) but specifically in the supply
chain controls section, where accurate tooling descriptions are most important.

**Risk**: A supply chain-focused assessor will ask what tools VE uses. The SSP answer
(Inspector + SonarQube) doesn't match reality (Inspector + Grype + Dependabot + Renovate +
SonarQube). This undermines credibility in an area of increasing FedRAMP focus.

**Recommendation**: Update SR-2 and SR-3 implementations to reference the full tooling set.
Describe the three-scanner model and Renovate's role in automated dependency management.

**Documents involved**:
- SSP Appendix A, SR-2 Part a implementation
- SSP Appendix A, SR-3 implementation

---

## F-12: SSP POA&M Appendix Listed as "To be completed"

**Severity**: MEDIUM — expected for initial SSP, but needs tracking

**Finding**: Appendix O (POA&M) is listed as "To be completed" in the SSP appendices table
(Table 12.1). This is normal for a pre-authorization SSP, but the ConMon plan commits to
monthly POA&M updates to the AO.

**Risk**: If VE is in ConMon (post-authorization), the POA&M must exist. If pre-authorization,
this is expected. Need to clarify VE's current authorization status.

**Recommendation**: Establish the POA&M document. The compliance OS is designed to help
generate and maintain POA&M entries from vulnerability finding dispositions.

**Documents involved**:
- SSP Table 12.1 (Appendix O: "To be completed")
- VE-CA-SOP-7 (commits to monthly POA&M submission)

---

## Future Findings

Additional findings will be added as more SSP content and supporting documents are
reviewed. Areas still to examine include:
- Remaining Appendix A controls (AC-2 account management, AT-2/AT-3 training, CP-4
  contingency testing, IR-4/IR-6 incident handling, CM-6/CM-7/CM-8 configuration mgmt)
- Configuration Management Plan (VE-CM-SOP-3 / Appendix H)
- DR/BC Plan (VE-SC-SOP-2 / Appendix G) — exercise schedule and evidence
- Incident Response Plan (Appendix I) — exercise schedule and templates
- Access Control procedures — periodic access review implementation details
- Security Training (AT-2, AT-3) — evidence and tracking mechanisms
- Risk Register (VE-RA-SOP-3) — currency and completeness
- Separation of Duties (Table 11.1) — verify role assignments match actual team structure
  for a <20 person company (10 roles defined; likely significant role overlap)
