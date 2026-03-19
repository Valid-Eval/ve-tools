# SSP Review — Questions & Answers

*These questions arose during the comprehensive SSP review. Answers informed
finding severity and action item prioritization.*

---

## Resolved Questions

### Architecture / Tooling

**Q1: Is Cloudflare for Government deployed?**
**RESOLVED**: No. Not deployed. AWS-native tools (Shield, WAF, ELB) more appropriate
for the EKS environment. Remove Cloudflare references from SSP or replace with AWS.

**Q2: Is NeuVector actively deployed and functional?**
**RESOLVED**: NeuVector replaced by **Falco** as of UDS v0.56. Every NeuVector reference
needs to become Falco (CA-7, MA-4(3), SI-16, software inventory, Table 8.1).

**Q5: Is the "SecOps Group" anyone currently?**
**RESOLVED**: SecOps = Jacob (CTO) + Devon + InfusionPoints (M-F 8-5 ET, operational
since ~2026-03-09). Coverage expands to 24/7 post-ATO sponsorship. Update all 19 refs.

**Q6: What's the actual SIEM?**
**RESOLVED**: Graylog (feeds InfusionPoints SOC). Grafana Loki is app-level log
aggregation (UDS Core). Replace Kibana/Elasticsearch references accordingly.

**Q8: Is AWS EDR configured?**
**RESOLVED**: No. Not relevant for EKS. Remove from SSP. Describe actual DR: IaC
rebuild + DB restore from S3.

**Q10: Is Velero being used?**
**RESOLVED**: No. Actual backup: nightly cron DB dumps (Neo4j + PostgreSQL) to S3
with demonstrated recovery. Infrastructure rebuilt via OpenTofu. Remove Velero refs.

**Q12: Does Keycloak support PIV/CAC?**
**RESOLVED**: Yes. Live with NASA Launchpad as IdP. Other integrations pending.

**Q13: What identity proofing for privileged roles?**
**RESOLVED**: IAL3 via agency IdP (NASA Launchpad PIV/CAC). Not VE's own proofing —
inherited through federated authentication. Also required for SuperAdmin portal.

**Q18: InfusionPoints go-live?**
**RESOLVED**: Live since ~2026-03-09. Graylog SIEM operational.

**Q19: 3PAO selected?**
**RESOLVED**: Igynte Platform. Conducted FedRAMP readiness assessment. CA-2(1)
"Planned" is a stale checkbox.

**Q20: Authorization status?**
**RESOLVED**: FedRAMP Ready (FR2514747735) + NASA Agency ATO. Pursuing Army/DIU
for FedRAMP authorization + IL-4/5.

### DR/CP

**Q7: What exists in us-gov-west-1?**
**RESOLVED**: Minimal. Cold site, not hot site. Pre-provisioning planned for when
ATO sponsorship confirmed.

---

## Open Aspects Requiring Follow-up

### For Trent / Rule4

**Q3: DAST tool integration**
No DAST tool currently. Nightwatch is functional e2e testing, not DAST.
**Open**: Rule4 to help evaluate and integrate a DAST tool (OWASP ZAP or similar).

**Q4: CodeQL vs SonarQube**
SonarQube active (upgrade urgent — A-15). SA-11(1) also references CodeQL.
**Open**: Clarify with Trent whether CodeQL is in use. If not, remove from SSP.

**Q9: Does the NASA tabletop count as a CP test?**
Jacob conducted a tabletop with Dr. Damian (NASA ISSM) on DR.
**Open**: (1) Does this satisfy CP-4? Trent to advise. (2) Document retroactively
in ISCP Appendix F regardless. (3) Schedule formal exercise with Rule4.

**Q14: Do monthly meetings satisfy ConMon artifact requirements?**
Monthly meetings with Dr. Damian are happening.
**Open**: FedRAMP ConMon requires artifact *submission* (executive summary doc, scan
results, POA&M, inventory) — not just meetings. Clarify with Trent whether formal
deliverables are being produced and submitted, or if this is verbal only.

**Q15: AO repository documentation**
NASA uses Box. Other AOs TBD.
**Open**: Trent to add AO-specific repository info to VE-CA-SOP-7 Appendix A
(replace "[Repository Link - TBD]").

### For Compliance OS Implementation

**Q11: Phishing-resistant MFA migration timeline**
Current: TOTP (not phishing-resistant). Path: Keycloak migration enables FIDO2/WebAuthn.
**Open**: Define migration timeline and milestones for POA&M entry. This depends on
the broader Keycloak authentication stack migration.

**Q16: Access review formalization**
Quarterly reviews happening but insufficiently formal/tracked.
**Open**: Build into compliance OS — `/compliance` skill pre-populates access review
worksheets from AWS IAM/Keycloak data. Formalize documentation going forward.

**Q17: Training records integration**
Rule4 has some tracking.
**Open**: Determine what tracking exists at Rule4, whether it satisfies AT-4, and
integrate with compliance OS data store.
