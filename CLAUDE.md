# ve-tools

Operational tooling and compliance data for Valid Eval.

## Commands

```bash
# Python package (kubectl plugins)
pip install -e .                     # Install vetools + kubectl plugins
kubectl ve-console                   # Interactive k8s console
kubectl ve-queues                    # List Redis queues
kubectl ve-queue <name>              # Inspect a specific queue

# Go binary (ECR credential bridging)
cd credbridge && go build -o ../build/credbridge .

# Credential rotation workflow
# Runs daily at 9 AM UTC via GitHub Actions
# Configure credentials in .github/credential-rotations.yml
# After rotating: update expires date, close GH issue + Jira ticket
```

## Repository Structure

### Operational Tooling
- `vetools/` — Python package (click CLI, kubernetes client, PyRSMQ). Requires Python 3.x.
- `credbridge/` — Go 1.22+ binary for AWS ECR credential bridging in containers
- `bin/` — kubectl plugins (`kubectl-ve-console`, `kubectl-ve-queue`, `kubectl-ve-queues`, `dockercredrot`)
- `.github/workflows/credential-rotation-reminder.yml` — Daily credential expiry checks → GH issues + Jira + email
- `.github/credential-rotations.yml` — Credential inventory with expiry dates and rotation steps
- `scratch/` — Gitignored working directory for local experiments

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

## Gotchas

- **credbridge is built into every VE container image** — it provides ECR auth at runtime. Changes here affect all image-* repos.
- **Credential rotation workflow** uses org-level secrets (JIRA_API_TOKEN, SG_API_KEY) — test with `dry_run: true` workflow dispatch.
- **The compliance/ directory is on a feature branch** (`feature/compliance-os-foundation`, PR #3) — not yet on main.
- **Go module uses `replace` directive** — `credbridge/` is a local sub-module, not a separate repo.
