# SSP & Policy Document Comprehensive Review Findings

*Created: 2026-03-16*
*Methodology: Manual review of SSP core + 17 parallel agent reviews of all Appendix A
control families (353 controls) + 4 supporting documents (IR Plan, DR/BC Plan, ISCP,
remaining procedures) + automated grep sweeps across full 47K-line SSP text.*
*For: Trent Hein (Rule4 / CISO), Jacob Ablowitz (CTO)*
*Raw agent outputs: ~/.claude/supply-chain-skill-development/ssp-review-workspace/output/*

---

## Authorization Context

**VE holds an active Agency ATO with NASA** and is listed as **FedRAMP Ready**
(FR2514747735) on the FedRAMP Marketplace. 3PAO: Igynte Platform (conducted the
readiness assessment). VE is pursuing FedRAMP authorization sponsorship with Army/DIU
for IL-4/5.

This means ConMon obligations (monthly deliverables to NASA as AO) are ACTIVE — not
future. Controls marked "Planned" that should already be operational for an ATO'd
system are more serious than they would be for a pre-authorization SSP. The SSP
appears to have been written as a pre-authorization document but VE is past that stage
for NASA.

---

## Executive Summary

**264 raw findings** identified across the full SSP v1.0, Appendix A v0.8, and ~30
supporting policy/procedure documents. After dedup and consolidation, the findings
organize into **9 systemic themes** plus document-specific issues.

**The three most critical themes:**

1. **~35 controls marked Planned or Partially Implemented** — concentrated in CM (13),
   AC (7), CA/PL (6), AT (3), SA (2). These all require POA&M entries before assessment.
   The CM family is the worst: 65% of controls not fully implemented.

2. **Remediation timeline inconsistency** — the SSP, policy, and procedure documents
   each state different timelines. The SSP says 30 days for Critical; FedRAMP requires
   15 days. BOD 22-01 KEV 14-day requirement is absent from all documents.

3. **DR/CP architecture fiction** — the SSP claims "hot site" with 30-minute RTO via
   AWS EDR, but recovery procedures describe a cold-site Terraform rebuild. RTO/RPO
   values are contradictory across 4+ locations. No CP test has been conducted (blank
   template in Appendix G). Risk Register Risk #1 flags this same issue.

---

## Theme 1: Controls Marked Planned or Partially Implemented

These controls are NOT fully implemented per the SSP's own checkboxes. Each requires
a POA&M entry with milestones. An assessor will focus on these.

### Planned (not implemented at all)

| Control | Family | Description | Agent |
|---------|--------|-------------|-------|
| AT-2(2) | Training | Insider threat training | ctrl-2 |
| AT-2(3) | Training | Social engineering training | ctrl-2 |
| AT-4 | Training | **Training records** — assessment blocker, no evidence capability | ctrl-2 |
| CA-2(1) | Assessment | Independent assessor (3PAO) — assessment blocker | ctrl-3 |
| CA-2(3) | Assessment | Leveraging external assessment results | ctrl-3 |
| CA-8(2) | Assessment | Red team exercises | ctrl-3 |
| CM-4 | Config Mgmt | **Impact analyses** — required Moderate control | ctrl-4a |
| CM-4(2) | Config Mgmt | Verification of controls after changes | ctrl-4a |
| CM-7 | Config Mgmt | **Least functionality** — critical control | ctrl-4a |
| CM-7(1) | Config Mgmt | Periodic review of least functionality | ctrl-4a |
| CM-7(2) | Config Mgmt | Prevent program execution | ctrl-4a |
| CM-7(5) | Config Mgmt | Authorized software allow-by-exception | ctrl-4a |
| PL-1 | Planning | **Planning policy and procedures** — foundational | ctrl-3 |
| SA-1 | Acquisition | **SA policy and procedures** — foundational | ctrl-7b |
| SA-4(10) | Acquisition | PIV products | ctrl-7b |
| AC-20(1) | Access | Limits on authorized use of external systems | ctrl-1 |

### Partially Implemented

| Control | Family | Description | Agent |
|---------|--------|-------------|-------|
| AC-2(2) | Access | Automated temp/emergency account management | ctrl-1 |
| AC-2(4) | Access | Automated audit actions | ctrl-1 |
| AC-2(9) | Access | Shared/group account restrictions | ctrl-1 |
| AC-4(21) | Access | Physical/logical separation of info flows | ctrl-1 |
| AC-17(4) | Access | Privileged commands and access logging | ctrl-1 |
| AC-20 | Access | Use of external systems | ctrl-1 |
| CA-5 | Assessment | POA&M process | ctrl-3 |
| CA-6 | Assessment | Authorization (pre-ATO) | ctrl-3 |
| CM-2 | Config Mgmt | Baseline configuration | ctrl-4a |
| CM-2(3) | Config Mgmt | Retention of previous configurations | ctrl-4a |
| CM-6 | Config Mgmt | **Configuration settings** — #1 assessment failure area | ctrl-4a |
| CM-6(1) | Config Mgmt | Automated config verification | ctrl-4a |
| CM-8 | Config Mgmt | **System component inventory** — common failure | ctrl-4a |
| CM-8(1) | Config Mgmt | Inventory updates during install/removal | ctrl-4a |
| CM-8(3) | Config Mgmt | Automated unauthorized component detection | ctrl-4a |
| AU-9 | Audit | Protection of audit information | ctrl-2 |

### Controls with Blank/Unreadable Checkboxes (status unknown)

MA-4(3), MA-4(6), AC-6(8), AC-17(6), AC-23, SC-7(10), SC-23(1), SC-23(3),
SI-2(6), SI-4(19), SI-4(20), SI-4(22), SI-10(3), IA-5(13), PE-3(1)

---

## Theme 2: Remediation Timeline Inconsistency

**The single most important finding for assessment readiness.**

| Severity | SSP RA-5(d) | SSP SI-2(3) | VE-RA-SOP-2 | VE-SC-POL-3 | FedRAMP Rev 5 |
|----------|-------------|-------------|-------------|-------------|---------------|
| Critical | **30 days** | **30 days** | 30 days | 15 days | **15 days** |
| High | 30 days | 30 days | 30 days | 35 days | 30 days |
| Medium | 90 days | 90 days | 90 days | 180 days | 90 days |
| Low | 180 days | 180 days | 180 days | 360 days | 180 days |
| KEV | not mentioned | not mentioned | not mentioned | not mentioned | **14 days** |

**Action**: Align ALL documents to FedRAMP Rev 5. Add KEV/BOD 22-01 14-day requirement.

Sources: RA-F1, RA-F2, SI-F1 (agents), F-1, F-4 (manual)

---

## Theme 3: DR/CP Architecture — Hot Site Fiction

Multiple HIGH findings across CP controls, ISCP, and DR/BC Plan:

- **No consistent RTO/RPO**: At least 4 different RTO values (12h, 24h, 30min, 72h)
  across ISCP and DR/BC Plan. RPO never explicitly defined at system level.
- **"Hot Site" claim unsupported**: Both documents say us-gov-west-1 is a hot site.
  Recovery procedures describe Terraform rebuild from scratch (cold site pattern).
- **AWS EDR for EKS**: SSP claims 30-minute failover via AWS Elastic Disaster Recovery.
  EDR is designed for EC2 lift-and-shift, not EKS/Kubernetes workloads.
- **Velero misclassified**: Listed as "Log aggregation" under Loki in both documents.
  Its actual role (k8s state backup) is never properly described.
- **No CP test completed**: Appendix G test report is blank template text. Appendix J
  test schedule says "N/A". Directly confirms Risk Register Risk #1.
- **Recovery depends on Confluence**: Procedures reference wiki URLs as primary source.
  If SaaS unavailable during disaster, recovery team has no instructions.

Sources: CP-F2/F3/F4/F5/F6, ISCP-F1 through F6, DRBC-F1 through F3, CROSS-F1/F2

**Action**: Define single authoritative RTO/RPO. Reclassify as cold site or pre-provision
resources. Conduct first CP test. Embed procedures in document (not Confluence links).

---

## Theme 4: Incomplete/Stale Tool References

Pervasive across the entire SSP. Automated sweep confirmed:

| Issue | Count | Locations |
|-------|-------|-----------|
| Inspector/SonarQube mentioned without Grype/Dependabot/Renovate | 53 lines | RA-5, SI-2, SR-2, CA-7, CM-5(6), SA-11, and more |
| "Terraform" instead of "OpenTofu" | 15 instances | CM-2, CM-3(6), CM-4, SA-10, SR-12 |
| "Kibana"/"Elasticsearch" instead of Grafana Loki | 7 instances | CA-7, SI-4, Table 8.1 |
| "lstio" typo (should be "Istio") | 8 instances | SC-8, SC-10, SC-13, SI-3 |
| "BigBang" instead of "UDS Core" | 2 instances | SSP §8, CMP §3.2.1 |
| NeuVector missing from Table 8.1 | 1 | SSP Table 8.1 |
| SonarQube described as SCA tool (it's SAST) | 2 | SR-11, CM-8(3) |

**Action**: Global find-and-replace for Terraform→OpenTofu, lstio→Istio,
Kibana/Elasticsearch→Grafana Loki. Add Grype, Dependabot, Renovate, NeuVector
to all scanning tool references. Fix SonarQube role description.

---

## Theme 5: IR Plan Critical Gaps

The IR Plan (Appendix I) has **5 HIGH findings**:

1. **Wrong document ID on every page** — footer says VE-CM-SOP-3 (Config Management!)
   instead of VE-IR-SOP-1
2. **1-hour reporting scope too narrow** — conditions on "potential or confirmed loss of
   CIA" when FedRAMP requires 1-hour for ALL confirmed incidents
3. **Zero cadence commitments** — no training, testing, or plan review schedule anywhere
   in the plan, despite IR-2/IR-3/IR-8 requiring these
4. **CISA/FedRAMP/Agency POC contacts blank** — empty fields in the reporting contacts table
5. **IR Leader contacts blank** — Jacob and Trent's phone/email not populated

Also: FedRAMP notification checkpoint missing for Minor/Negligible incidents that still
trigger reporting obligations. Templates have duplicate IDs (two VE-IR-TMP-1). No
cross-reference to SSP, ConMon Plan, or other VE documents.

Sources: IRP-F1 through IRP-F5 (doc-9 agent)

---

## Theme 6: Aspirational Language vs. Implementation Status

Multiple controls have detailed implementation narratives written in present tense
("Valid Eval has implemented...") while the checkbox says "Planned." This pattern
appears in: AT-2(2), AT-2(3), CM-4, CM-7, CM-7(1), CM-7(2), CM-7(5), CA-8(2),
PL-1, SA-1.

An assessor will flag these as either: (a) the checkbox is wrong and the control IS
implemented, or (b) the narrative is aspirational and overstates the current state.
Either way, the documents need to be reconciled.

**Action**: For each control, determine the truth — is it implemented or not?
Update either the checkbox or the narrative to match reality.

---

## Theme 7: Missing Referenced Documents

7 documents referenced in SSP security controls have no corresponding file in the
plan content directory:

| Document ID | Referenced In | Description |
|-------------|---------------|-------------|
| VE-AC-SOP-8 | AC-2 | External System Integration Procedure |
| VE-CA-SOP-2 | CA-7 | Continuous Threat Monitoring Procedure |
| VE-CM-SOP-5 | CM-10 | Software and Tooling Inventory |
| VE-IA-SOP-2 | IA-4 | Identifier Assignment Tracking |
| VE-IA-SOP-3 | IA-12 | Identity Verification Process |
| VE-PL-SOP-3 | PL-2 | FIPS 199 Categorization Report |
| VE-RA-OPS-1 | RA-9, SI-2(6) | Criticality Analysis / System Inventory |

Additionally, VE-CM-INV-2 (Software Inventory) contains archived entries and is
missing actively-used tools (Grype, Renovate, Zarf, Flux, OpenTofu, crane).

**Action**: Either create these documents or update the SSP references. An assessor
will request every referenced document.

---

## Theme 8: Role/Terminology Inconsistencies

- **CAB vs CCB**: Change Management Policy uses "CAB" (14 instances). Configuration
  Management Plan uses "CCB" (11 instances). Same body (CEO + CTO).
- **SecOps Group**: Referenced 19 times but never defined. With InfusionPoints not yet
  operational, unclear who this is.
- **SIEM**: Variously described as "Kibana," "Elasticsearch Kibana," "SIEM solutions,"
  and "Grafana." No single authoritative SIEM product identified.
- **AO role confusion**: CA-6 positions the ISO as the authorizing official. In FedRAMP,
  the AO is the government agency or JAB representative, not the CSP's ISO.
- **Separation of duties**: 10 roles defined for <20 people. No compensating controls
  documented for unavoidable role overlap.
- **"VR-" typos**: IR-5 uses "VR-IR-TMP-5" and "VR-IR-TMP-1" instead of "VE-" prefix.

---

## Theme 9: Crypto and Authentication

- **Phishing-resistant MFA not addressed**: FedRAMP now requires phishing-resistant MFA.
  SSP describes TOTP/virtual MFA which does NOT qualify. Hardware FIDO2/WebAuthn or PIV
  required. (IA-F1)
- **PIV acceptance claimed but possibly aspirational**: IA-8(1) says Keycloak supports
  PIV authentication with FIPS 201 validation. Needs verification. (IA-F13)
- **IAL3 claimed for privileged roles**: May overstate the identity proofing process for
  a small company. (IA-F15)
- **CMVP certificate #4631**: Referenced for SSM endpoints but may be Historical status.
  Needs verification against NIST CMVP site. (CRYPTO-F1)
- **"Other" crypto section empty**: Appendix Q has no entries for MFA, code signing,
  or integrity hashing despite VE using these capabilities. (CRYPTO-F5)
- **TLS 1.1 referenced**: Multiple Appendix Q entries include "TLS 1.1 or earlier" as
  an option. Must be clearly marked as NOT in use. (CRYPTO-F3)
- **FIPS 140-2 vs 140-3**: Inconsistent references across documents. (MP-F10)

---

## Theme 10: Document-Specific Findings (Not Covered Above)

### MP/PE Family
- Systematic "Service Provider Corporate" over-marking on facility controls where VE
  has no facility (PE-F10 — affects ~17 controls)
- Endpoint media gaps: MP-4, MP-6, MP-7 say "no control responsibility" despite VE
  having employee laptops that store/process data
- PE-17 (Alternate Work Site) incorrectly marked as inherited from AWS — it's purely VE

### SA Family
- GitHub not FedRAMP authorized but used extensively — no documented risk acceptance (SA-F4)
- Nightwatch e2e testing described as "DAST" — it's functional testing, not DAST (SSDLC-F1)
- NIST SP 800-31 cited instead of 800-30 (SA-F8)
- Section 889 NDAA cited as "Section 899" (SA-F3)

### MA Family
- AWS SSM Session Manager (actual remote access tool) never mentioned; VPN referenced
  instead (MA-F13, MA-F14)
- MA-4(3) and MA-4(6) are HIGH-baseline controls voluntarily included — creates
  unnecessary audit obligations (MA-F10, MA-F12)

### Audit Procedure (VE-AU-SOP-1)
- No defined log review frequency (AUS-F6)
- References VE-AU-SOP-3 as parent policy with wrong naming convention (AUS-F1)
- Log pipeline (app→Loki→S3) not described (AUS-F3)

### Vendor Notification (VE-SR-SOP-2)
- No response SLA beyond 1-day acknowledgment (VNT-F2)
- No cross-reference to VE-SR-SOP-1 or VE-IR-SOP-1 for escalation (VNT-F3)

### Risk Register (VE-RA-SOP-3)
- Static since 12/7/2024. All 11 risks Open. No evidence of updates. (F-19)

---

## Automated Sweep Results

| Pattern | Instances | Action |
|---------|-----------|--------|
| "Planned" checkboxes | ~16 controls | POA&M entries required |
| "Partially Implemented" checkboxes | ~19 controls | POA&M entries required |
| "Terraform" (not OpenTofu) | 15 | Global replace |
| "lstio" (should be Istio) | 8 | Global replace |
| "Kibana"/"Elasticsearch" | 7 | Replace with Grafana Loki |
| "BigBang" | 2 | Replace with UDS Core |
| Inspector/SonarQube without Grype | 53 lines | Add Grype/Dependabot/Renovate |
| "SecOps" (undefined) | 19 | Define or replace |
| "CAB" | 14 | Standardize with CCB |
| "CCB" | 11 | Standardize with CAB |
| "VR-" prefix (should be "VE-") | 2 | Fix |
| Missing referenced documents | 7 | Create or fix references |
| Blank checkboxes (rendering) | ~15 controls | Verify and fix in source |

---

## Priority Action Items for SSP Review

### Must Fix Before Assessment (HIGH)

1. **Remediation timelines**: Align all documents to FedRAMP Rev 5 (Critical=15d). Add KEV 14d.
2. **POA&M**: Create entries for all ~35 Planned/Partially Implemented controls.
3. **CP test**: Conduct first test, document results in Appendix G.
4. **RTO/RPO**: Define single authoritative values. Reclassify site type.
5. **IR Plan**: Fix document ID (VE-CM-SOP-3→VE-IR-SOP-1), populate contacts, add cadences.
6. **IR Plan reporting**: Remove CIA-loss qualifier from 1-hour reporting scope.
7. **Phishing-resistant MFA**: Document migration plan or current implementation.
8. **Missing documents**: Create or fix references for 7 missing documents.
9. **AT-4 training records**: Implement tracking before assessment.

### Should Fix (MEDIUM)

10. **Tool references**: Global updates for Terraform, Kibana, BigBang, lstio, scanner tools.
11. **Aspirational narratives**: Reconcile "Planned" status with present-tense narratives.
12. **CAB/CCB/SecOps/AO terminology**: Standardize across all documents.
13. **Velero documentation**: Properly describe its backup role in DR/BC and ISCP.
14. **GitHub risk acceptance**: Document the risk decision for using non-FedRAMP service.
15. **Software inventory**: Remove archived entries, add active tools.
16. **Risk register**: Conduct review, update statuses, add new risks.
17. **Separation of duties**: Add role-to-person mapping with compensating controls.
18. **Recovery procedures**: Embed in documents (not Confluence links).
19. **DAST gap**: Either add actual DAST tool or reframe Nightwatch honestly.
20. **Appendix Q "Other" section**: Populate with MFA, signing, hashing entries.

### Nice to Fix (LOW)

21. Typos: lstio, Grafrana, "principal"→"principle", Section 899→889, etc.
22. Duplicate paragraphs in MP controls.
23. Checkbox rendering issues (~15 controls).
24. Copyright date inconsistencies in IR templates.
25. "master branch"→"main branch" in CM-5(6).

---

## Methodology Notes

This review was conducted through:
1. Manual reading of SSP core sections (1-12), ConMon Plan, Vuln Mgmt Policy/Procedure,
   SCRM Plan, Access Audit Procedure, CMP, Risk Register, Software Inventory, MDM Policy,
   Host-Based Protections document
2. 17 parallel AI agent reviews of all Appendix A control families and supporting documents
3. Automated grep sweeps for systematic patterns across the full 47K-line SSP text
4. Cross-reference of 89 VE-XX-XXX document IDs against the plan content directory

Agent outputs are preserved in `~/.claude/supply-chain-skill-development/ssp-review-workspace/output/`
for verification against source text. All HIGH findings include SSP quotes with approximate
line numbers for traceability.

**Verification**: 18 findings spot-checked against source PDFs (Appendix A, IR Plan,
ISCP) with **100% accuracy rate** — zero false positives. Verified findings include:
Planned/Partially Implemented checkboxes (AT-2(2), AT-2(3), CM-4), remediation timelines
(RA-5(d) Critical=30d), tool references (Grype missing, Terraform stale), IR Plan
document ID error (VE-CM-SOP-3 on every page), blank contacts (IR Plan, ISCP), blank
CP test report (ISCP Appendix F), and multiple "N/A" appendices in ISCP. Checkbox
rendering in the PDF is clean (☒/☐), confirming that controls flagged as having "blank
checkboxes" by agents are likely real source document issues, not extraction artifacts.

**Remaining unverified**: CMVP certificate statuses (#4631, #4177, #4816, #4856) not
checked against NIST website. ~15 controls with blank/unreadable checkboxes not individually
confirmed in source PDF. Individual LOW-severity findings (typos, formatting) not spot-checked.
