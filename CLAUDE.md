# ve-tools

Operational tooling and compliance data for Valid Eval.

## Repository Structure

### Operational Tooling
- `vetools/` — Python package for Kubernetes and Redis operations (kubectl plugins)
- `credbridge/` — Go binary for AWS ECR credential bridging in containers
- `bin/` — kubectl plugins (`kubectl-ve-console`, `kubectl-ve-queue`, `kubectl-ve-queues`, `dockercredrot`)
- `.github/workflows/` — Credential rotation reminder workflow

### Compliance Operating System (`compliance/`)
Data foundation for VE's compliance management across FedRAMP Moderate, IL-4/5, and CMMC L2.

**Key files:**
- `DESIGN.md` — Architecture and vision (start here for compliance context)
- `ssp-review-findings.md` — Authoritative SSP findings list (264 findings, 9 themes)
- `calendar/recurring.yaml` — All recurring compliance obligations
- `delegations/tracker.yaml` — Cross-party commitments
- `decisions/` — Dispositions, risk acceptances, suppressions, architecture decisions

**Design principle**: Scanner data stays in source systems (Inspector2, Grype, Dependabot).
Only human decisions are stored here. The `/compliance` Claude skill queries live data
and combines it with the decision record.

See `compliance/DESIGN.md` for the full architecture.

## Environment Context

- **VE Authorization**: FedRAMP Ready (FR2514747735), NASA Agency ATO
- **Infrastructure**: AWS GovCloud, EKS, UDS Core (Defense Unicorns)
- **Container images**: RapidFort hardened base images
- **Runtime security**: Falco (replaced NeuVector in UDS v0.56)
- **SIEM**: Graylog (InfusionPoints SOC)
- **SAST**: SonarQube (upgrade to current LTA is urgent — A-15)
- **Scanning**: AWS Inspector, Grype (ve-zarf CI), Dependabot (GitHub)
- **IaC**: OpenTofu (formerly Terraform)
- **GitOps**: Flux, Zarf, Helm

## Cross-Repo References

- **ve-app**: Main application repository
- **ve-zarf**: Air-gap packaging, Zarf bundles, container image fleet doc
- **ve-iac**: OpenTofu IaC for IL2 stg/prod
- **ve-deployments**: Flux/Helm configs for CI cluster (branch: `ve-com-testing-v2`)
- **infosec-iac**: FedRAMP compliance automation, Graylog, security tooling
- **valid-eval-skills**: Claude Code skills including supply-chain-assessment
- **image-***: 12 container image build repos

## Working With Compliance Data

When modifying files in `compliance/`:
- `ssp-review-findings.md` is the single authoritative findings list — do not create parallel tracking
- `calendar/recurring.yaml` defines what the `/compliance` skill checks — keep it accurate
- `decisions/` files are append-mostly — git history is the audit trail
- `delegations/tracker.yaml` tracks cross-party commitments — update status, don't delete entries
