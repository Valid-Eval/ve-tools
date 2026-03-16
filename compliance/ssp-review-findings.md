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

**Finding**: Three sources define different remediation timelines for the same severity levels:

| Severity | VE-RA-SOP-2 (Procedure) | VE-SC-POL-3 (Policy) | FedRAMP Rev 5 Actual |
|----------|------------------------|---------------------|---------------------|
| Critical | 30 days | 15 days | 15 days |
| High | 30 days | 35 days | 30 days |
| Medium | 90 days | 180 days | 90 days |
| Low | 180 days | 360 days | 180 days |

VE-SC-POL-3 cites Iron Bank Acceptance Baseline Criteria as its source. VE-RA-SOP-2 uses
different values without citing a source. Neither exactly matches FedRAMP Rev 5 requirements.

**Risk**: An assessor comparing the policy to the procedure will see conflicting commitments.
More importantly, if VE operates to the more lenient timelines (VE-SC-POL-3: 180d for Medium,
360d for Low), it would exceed FedRAMP Rev 5 requirements (90d / 180d respectively).

**Recommendation**: Align both documents to a single timeline that meets or exceeds FedRAMP
Rev 5 requirements. Consider whether Iron Bank timelines should be referenced at all, or
whether FedRAMP Rev 5 should be the sole authority. The policy should be the authoritative
source with the procedure referencing it.

**Documents involved**:
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

## Future Findings

Additional findings will be added as more SSP content and supporting documents are
reviewed. Areas still to examine include:
- Appendix A (Security Controls) — full control implementation details
- Configuration Management Plan (VE-CM-SOP-3)
- DR/BC Plan (VE-SC-SOP-2) — exercise schedule and evidence
- Access Control procedures — periodic access review cadence
- Security Training — evidence and tracking
- Risk Register (VE-RA-SOP-3) — currency and completeness
- Incident Response Plan (Appendix I) — exercise schedule
