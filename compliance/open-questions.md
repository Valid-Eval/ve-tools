# Open Questions — SSP Review Follow-up

*These questions arose during the comprehensive SSP review. Answers determine
whether findings need to be escalated, downgraded, or resolved differently.
All 20 questions answered as of 2026-03-17.*

---

## Architecture / Tooling Questions

**Q1: Is Cloudflare for Government deployed?**
**ANSWERED**: No. Not presently deployed. Given the AWS EKS environment, AWS-native
tools (Shield, WAF, ELB) may be more appropriate. SC-F1 CONFIRMED as finding —
remove Cloudflare references from SSP (SC-5, SC-7) or replace with AWS tooling.
Consider refocusing on AWS tools for next SSP revision.

**Q2: Is NeuVector actively deployed and functional?**
**ANSWERED**: NeuVector has been **replaced by Falco** as of UDS v0.56. NeuVector was
deployed in the default UDS configuration but is no longer the active tool. **NEW
FINDING**: Every NeuVector reference in the SSP, software inventory, and supporting
docs needs to become Falco. This is a significant change that touches CA-7, MA-4(3),
SI-16, the software inventory, and Table 8.1.

**Q3: Is there a DAST tool in the CI/CD pipeline?**
**ANSWERED**: No DAST tool currently. Jacob would like Rule4's help getting this wired
up. SSDLC-F1 CONFIRMED — Nightwatch is not DAST. **Action for Trent**: Help VE
evaluate and integrate a DAST tool (OWASP ZAP or similar) into the CI/CD pipeline.
Until implemented, reframe SSDLC language honestly.

**Q4: Is SonarQube still actively used?**
**ANSWERED**: Yes. Active, licensed, integrated with GitHub quality gate. On an old
version — upgrade to current LTA is urgent (A-15, D-007). CodeQL reference in
SA-11(1) needs clarification with Trent — likely should be removed if not in use.

**Q5: Is the "SecOps Group" anyone currently?**
**ANSWERED**: SecOps = Jacob (CTO) + Devon, with InfusionPoints as first line of
defense (operational since ~2026-03-09, M-F 8-5 ET). Coverage will expand to 24/7
upon FedRAMP/IL-4 ATO sponsorship. **Action for SSP**: Define "SecOps Group" as
InfusionPoints (ConMon/SOC) + VE CTO + VE DevOps. Update all 19 references.

**Q6: What's the actual SIEM?**
**ANSWERED**: Graylog. Set up as part of InfusionPoints onboarding — pulls log data
from AWS environment to InfusionPoints' monitoring environment. **Action for SSP**:
Replace all Kibana/Elasticsearch references with Graylog. Describe Grafana Loki as
the application-level log aggregation platform (UDS Core) and Graylog as the SIEM
feeding InfusionPoints SOC.

## DR/CP Questions

**Q7: What actually exists in us-gov-west-1?**
**ANSWERED**: Minimal. This is a to-do for compliance, planned for implementation
when ATO sponsorship is confirmed and full audit preparation begins. **Action for
SSP**: Reclassify from "Hot Site" to "Cold Site" or "Planned Alternate Site."
Document the current state honestly and the pre-provisioning plan as a milestone.

**Q8: Is AWS EDR (Elastic Disaster Recovery) actually configured?**
**ANSWERED**: Not configured. Not relevant for EKS architecture — EKS handles node
recovery via cluster autoscaling. **Action for SSP**: Remove AWS EDR reference.
Describe the actual DR mechanism: IaC rebuild via OpenTofu + database restore from
S3 backups. Adjust RTO expectations accordingly (hours, not 30 minutes).

**Q9: Has any CP/DR test ever been conducted?**
**ANSWERED**: Jacob performed a tabletop exercise with Dr. Tony Damian at NASA on DR.
This likely qualifies as a CP test but needs formal documentation. **Action**: (1)
Document the tabletop exercise retroactively (date, participants, scenario, findings)
for ISCP Appendix F. (2) Schedule a more formal exercise with Rule4 in advance of
full ATO. The ISCP Appendix F should not remain blank if a tabletop was conducted.

**Q10: Is Velero actually being used for k8s backup?**
**ANSWERED**: No. Velero is not used. Current approach: nightly cron job backing up
full copies of Neo4j and PostgreSQL databases to S3 (demonstrated recovery capability).
Infrastructure is fully managed by OpenTofu/Terraform — can be rebuilt from code.
**Action for SSP/ISCP/DR-BC**: Remove all Velero references. Document the actual
backup strategy: nightly DB dumps to S3 + IaC-managed infrastructure rebuild. This is
a defensible approach for a cloud-native architecture. The question of whether to
adopt Velero is a future architecture decision, not an SSP revision item.

## Authentication Questions

**Q11: What MFA mechanism is actually in use?**
**ANSWERED**: Virtual MFA (TOTP via Google Authenticator and similar). No SMS/email
MFA. Federal PIV/CAC via agency-provided IdPs (NASA Launchpad currently live).
Migration path: moving authentication stack into Keycloak would enable hardware
security key (FIDO2/WebAuthn) support.
**Why TOTP is not phishing-resistant**: Real-time phishing proxies (attacker-in-the-
middle) can intercept TOTP codes. User enters credentials + TOTP on a fake login page;
attacker relays to real site within the 30-second window. FIDO2/WebAuthn prevents
this because the authenticator cryptographically binds to the origin domain — it won't
respond to a phishing domain. FedRAMP's requirement specifically targets this vector.
**Action for SSP**: Document the Keycloak migration plan as the path to phishing-
resistant MFA. This should be a POA&M item with milestones.

**Q12: Does Keycloak actually support PIV/CAC authentication?**
**ANSWERED**: Yes. Live with NASA Launchpad as IdP. Other agency integrations pending.
IA-F13 downgraded — SSP claim is accurate. Strengthen by naming NASA Launchpad.

**Q13: What identity proofing is actually performed for privileged roles?**
**ANSWERED**: IAL3 is achieved via agency-provided IdP integration (e.g., federal PIV/
CAC through NASA Launchpad). Agencies that integrate their IdP with VE's Keycloak can
achieve IAL3 for their users. IAL3 is also required for SuperAdmin portal access.
This is accurate but should be clarified in the SSP — IAL3 is not performed by VE
directly but is inherited from the agency's identity proofing process via federated
authentication.

## Operational Questions

**Q14: Is Rule4 currently delivering monthly ConMon executive summaries?**
**ANSWERED**: Yes, in the form of a monthly meeting with Dr. Tony Damian (NASA ISSM).
**Note**: Need to clarify whether this meeting produces the formal ConMon deliverables
(executive summary document, scan results, POA&M, inventory) or is a verbal update.
FedRAMP ConMon requires artifact submission, not just meetings.

**Q15: Has the AO deliverable repository been established?**
**ANSWERED**: Varies by AO. NASA uses a Box drive. This should be documented in the
SSP/ConMon plan. **Action for Trent**: Add AO-specific repository information to
VE-CA-SOP-7 Appendix A (replace "[Repository Link - TBD]").

**Q16: Are quarterly access reviews happening?**
**ANSWERED**: Yes, but insufficiently formal/tracked. **Action**: Good candidate for
compliance OS automation — the `/compliance` skill can pre-populate access review
worksheets from AWS IAM/Keycloak data. Formalize documentation going forward.

**Q17: Is security awareness training being tracked?**
**ANSWERED**: Rule4/Trent has some tracking. Integration with the compliance OS data
store would improve visibility. **Action**: Determine what tracking exists at Rule4
and whether it satisfies AT-4 evidence requirements. If not, implement tracking.

**Q18: What's InfusionPoints' expected go-live date?**
**ANSWERED**: Live since ~2026-03-09. M-F 8-5 ET coverage. 24/7 planned for post-ATO
sponsorship. Graylog SIEM operational.

**Q19: Has a 3PAO been selected?**
**ANSWERED**: Igynte Platform. Conducted the FedRAMP readiness assessment. CA-2(1)
"Planned" is stale — should be updated.

**Q20: What's VE's current authorization status?**
**ANSWERED**: FedRAMP Ready (FR2514747735) + NASA Agency ATO. Pursuing Army/DIU
for FedRAMP authorization sponsorship + IL-4/5.
