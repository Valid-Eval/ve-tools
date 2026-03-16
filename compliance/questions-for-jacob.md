# Questions for Jacob — SSP Review Follow-up

*These questions arose during the comprehensive SSP review. Answers will determine
whether certain findings need to be escalated, downgraded, or resolved differently.*

---

## Architecture / Tooling Questions

**Q1: Is Cloudflare for Government deployed?**
The SSP (SC-5, SC-7) references "Cloudflare for Government CDN" for DDoS protection
and traffic monitoring. Is this actually deployed, or is it aspirational language?
If not deployed, SC-F1 is a MEDIUM finding. If deployed, we need to add it to the
environment documentation.

**Q2: Is NeuVector actively deployed and functional?**
Referenced in CA-7 narrative and the software inventory (VE-CM-INV-2), ships with
UDS Core. Is it actually running in the production cluster with policies configured?
Affects F-9 (not in Table 8.1) and multiple agent findings about container security.

**Q3: Is there a DAST tool in the CI/CD pipeline?**
The SSDLC policy (VE-SA-POL-2) describes "DAST" testing but the actual tool is
Nightwatch (functional e2e testing, not security scanning). Is there an actual DAST
tool (OWASP ZAP, Burp Suite, etc.) or is this a gap?

**Q4: Is SonarQube still actively used?**
Referenced throughout the SSP as the SAST tool. The SSP also mentions GitHub CodeQL
in SA-11(1). Are both in use, or has one replaced the other?

**Q5: Is the "SecOps Group" anyone currently?**
Referenced 19 times in the SSP. With InfusionPoints not yet operational, who currently
receives and acts on security alerts outside business hours?

**Q6: What's the actual SIEM?**
The SSP variously references "Kibana," "Elasticsearch Kibana," "SIEM solutions," and
the monitoring stack is actually Grafana Loki + Prometheus. Is there a dedicated SIEM
with correlation rules and alerting, or is Grafana Loki serving that function?

## DR/CP Questions

**Q7: What actually exists in us-gov-west-1?**
The SSP and ISCP claim a "hot site" in us-gov-west-1. Is there any pre-provisioned
infrastructure there (VPC, EKS cluster, RDS replica)? Or would recovery be a
from-scratch Terraform build?

**Q8: Is AWS EDR (Elastic Disaster Recovery) actually configured?**
The SSP claims 30-minute failover via AWS EDR. EDR is designed for EC2 lift-and-shift,
not EKS. Is it actually configured for the VE environment?

**Q9: Has any CP/DR test ever been conducted?**
The ISCP Appendix F test report is blank template text. Appendix E validation test
plan is also unfilled. Risk Register Risk #1 flags untested backup/restore. Has any
test — even informal — been done?

**Q10: Is Velero actually being used for k8s backup?**
Both ISCP and DR/BC Plan misclassify Velero as "Log aggregation" under Loki. Is Velero
actually configured and running backups of k8s state? If so, where do backups go?

## Authentication Questions

**Q11: What MFA mechanism is actually in use?**
FedRAMP now requires phishing-resistant MFA. The SSP describes TOTP/virtual MFA.
Are hardware security keys (YubiKey, FIDO2) deployed for any accounts? Is there a
migration plan?

**Q12: Does Keycloak actually support PIV/CAC authentication?**
IA-8(1) claims Keycloak supports PIV with FIPS 201 validation. Is this configured
and tested, or aspirational?

**Q13: What identity proofing is actually performed for privileged roles?**
IA-12 claims IAL3 (in-person ISSO verification with biometric capture). Is this the
actual process, or closer to IAL2?

## Operational Questions

**Q14: Is Rule4 currently delivering monthly ConMon executive summaries?**
The ConMon plan commits to monthly submission to the AO. Is this happening?

**Q15: Has the AO deliverable repository been established?**
All ConMon deliverable links in VE-CA-SOP-7 Appendix A say "[Repository Link - TBD]".

**Q16: Are quarterly access reviews happening?**
AC-2(j) commits to quarterly privileged access reviews. Templates exist
(VE_Quarterly_Access_Review-infrastructure.pdf, -super_admin.pdf). Are these being
conducted and documented?

**Q17: Is security awareness training being tracked?**
AT-4 (Training Records) is marked "Planned" in the SSP. Is there any training tracking
mechanism in place (even a spreadsheet)?

**Q18: What's InfusionPoints' expected go-live date?**
**ANSWERED (2026-03-16)**: InfusionPoints went live approximately 2026-03-09.
This resolves F-5 (InfusionPoints not reflected in docs) — they now need to be added
to the SSP and ConMon plan. Also resolves the "SecOps Group" ambiguity — InfusionPoints
can now be named as the SOC provider. AU-6 weekly audit review should transition to
InfusionPoints.

**Q19: Has a 3PAO been selected?**
**ANSWERED (2026-03-16)**: Igynte Platform is the 3PAO. They conducted the FedRAMP
readiness assessment. CA-2(1) "Planned" checkbox is stale — should be at least
"Partially Implemented" given the readiness assessment is complete.

**Q20: What's VE's current authorization status?**
**ANSWERED (2026-03-16)**: VE is FedRAMP Ready (FR2514747735) with an active Agency
ATO from NASA. Pursuing FedRAMP authorization sponsorship with Army/DIU for IL-4/5.
This means ConMon deliverables should be active NOW (monthly to NASA). Controls marked
"Planned" are more serious than they appeared — an ATO assessor has already reviewed
these. The SSP reads as pre-authorization but VE is past that for NASA.
