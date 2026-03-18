# SSP v1.1 Delta Report

*Comparing v1.0 (12/4/2024) → v1.1 (2/23/2026) and related appendix updates*
*Generated: 2026-03-18*
*Authoritative findings list: `ssp-review-findings.md` (this report is a summary view)*

---

## Documents Updated

| Document | Old Version | New Version | Change Volume |
|----------|------------|-------------|---------------|
| SSP Main Body | v1.0 (12/4/2024) | v1.1 (2/23/2026) | ~440 lines |
| Appendix A (Controls) | v0.8 (12/31/2024) | v1.1 (2/23/2026) | ~13K lines |
| Appendix H (CMP) | v1.0 (12/17/2024) | v1.2 (2/19/2026) | ~256 lines |
| Appendix G (ISCP) | v0.1 (11/25/2024) | v0.1 (unchanged header) | ~440 lines (content changed, version NOT updated) |
| Appendix Q (Crypto) | v1.1 (1/15/2025) | v1.2 (2/23/2026) | ~328 lines |
| Appendix I (IR Plan) | v3.6 | v3.6 (unchanged) | 0 |
| Appendix P (SCRM) | v1.0 | v1.0 (unchanged) | 0 |
| POA&M | did not exist | v1.0 (2/18/2026) | NEW |

## Items Resolved by v1.1

These findings from `ssp-review-findings.md` have been addressed:

1. **Kibana/Elasticsearch → OpenSearch** (Theme 4) — all references replaced
2. **BigBang → UDS** (Theme 4, SSP main + CMP) — updated in both
3. **Velero references removed** (Theme 3, Appendix A CP controls) — removed
4. **GitHub FedRAMP status** (Theme 10, SA-F4) — moved to Table 6.1 as authorized
5. **POA&M "to be completed"** (F-12) — document now exists (v1.0)
6. **Cloudflare de-branded in SC-5** — genericized to "a CDN" (still in SC-7)
7. **InfusionPoints Graylog added** to SIEM in Table 8.1
8. **CMP BigBang → UDS Core** (F-16)
9. **Crypto DAR #4 corrected** — ECR images now KMS, not Chainguard
10. **"platorm" typo fixed** in MA-4(3)

## Items NOT Resolved — Still Need Action

See `ssp-review-findings.md` Themes 1-9 for full details. Key remaining:

- **Critical=30 days** (Theme 2) — still 30d in RA-5(d) and SI-2(3). Must be 15d.
- **KEV/BOD 22-01** (Theme 2) — still absent
- **All 13 Planned controls unchanged** (Theme 1) — none upgraded
- **All 16 Partially Implemented unchanged** (Theme 1)
- **Terraform → OpenTofu** (Theme 4) — 12 instances still say Terraform
- **NeuVector → Falco** (Theme 4) — 11 instances still say NeuVector, 0 Falco
- **lstio typos** (Theme 4) — 8 instances unchanged
- **Grype absent** (Theme 4) — still not referenced anywhere
- **IR Plan unchanged** (Theme 5) — wrong doc ID, blank contacts, no cadences
- **ISCP findings unchanged** (Theme 3) — RTO contradictions, blank test report, placeholders
- **Blank checkboxes** (~145 instances) — rendering issue unchanged
- **Cloudflare still in SC-7** — one remaining reference

## NEW Issues Introduced in v1.1

These need to be added to the findings tracking:

1. **ISCP "CSP Name" regression** — template placeholders replaced "Valid Evaluation"
   in ~5 locations. Someone re-merged from FedRAMP template without filling in fields.
2. **"ECT" typo** in Appendix A (should be "ECR") — new sentence about container scanning
3. **NeuVector scanning references removed without replacement** — RA-5, MA-5, SI-4(4)
   lost NeuVector scanning descriptions; nothing replaced them. Creates a gap in
   documented container scanning capability.
4. **Velero removed but backup tooling not replaced** — CP-6/CP-7 no longer name any
   backup tool. Should document actual approach (nightly DB dumps to S3 + IaC rebuild).
5. **SCRMP filename typo** — "Magement" instead of "Management" in SSP Appendix P ref
6. **Istio port entry incomplete** — Table 9.1 has "??" in a field for port 15021
7. **"Chainguards" typo** in SSP main (should be "Chainguard" — and per Jacob, Chainguard
   should be removed entirely, now using RapidFort only)
8. **"Bash" listed twice** in CMP §3.2.1 component list
9. **ISCP version not incremented** despite substantive content changes
10. **CMP "Valkey" removed** — may still be in use (Redis fork); verify

## Items That Need Further Updates Beyond v1.1

Based on Jacob's answers to open questions (2026-03-17):

- **Chainguard → RapidFort** throughout (SSP Table 8.1, CMP, Appendix Q FIPS modules)
- **NeuVector → Falco** (UDS v0.56 change, 11 remaining references)
- **Actual backup approach** needs to replace Velero gap (nightly cron DB dumps to S3)
- **"Hot Site" → "Cold Site"** in ISCP (us-gov-west-1 is minimal)
- **AWS EDR reference** should be removed (not configured, not relevant for EKS)
- **InfusionPoints** needs to be added to IR Plan, ISCP contact lists, and ConMon plan roles
- **Graylog** should replace remaining OpenSearch/generic "SIEM" references where applicable
- **SecOps Group** should be defined (Jacob + Devon + InfusionPoints)
