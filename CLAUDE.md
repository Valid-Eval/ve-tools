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

# Credential rotation + compliance review reminder workflow
# Runs daily at 9 AM UTC via GitHub Actions
# Configure credentials in .github/credential-rotations.yml
# After rotating: update expires date, close GH issue + Jira ticket
# Configure compliance reviews in .github/compliance-reviews.yml
# After a review: record the outcome, set the next due date (or remove the entry), close GH issue + Jira ticket
```

## Repository Structure

### Operational Tooling
- `vetools/` — Python package (click CLI, kubernetes client, PyRSMQ). Requires Python 3.x.
- `credbridge/` — Go 1.22+ binary for AWS ECR credential bridging in containers
- `bin/` — kubectl plugins (`kubectl-ve-console`, `kubectl-ve-queue`, `kubectl-ve-queues`, `dockercredrot`)
- `.github/workflows/credential-rotation-reminder.yml` — Daily credential expiry and compliance-review due-date checks → GH issues + Jira + email
- `.github/credential-rotations.yml` — Credential inventory with expiry dates and rotation steps (credentials only)
- `.github/compliance-reviews.yml` — Scheduled compliance reviews (e.g. exception re-reviews) with due dates, steps, and links to the ve-compliance record and Jira ticket
- `scratch/` — Gitignored working directory for local experiments

### Compliance Operating System
Compliance data lives in the dedicated [ve-compliance](https://github.com/Valid-Eval/ve-compliance) repo.

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
- **ve-deployments**: Flux/Helm configs for CI cluster
- **infosec-iac**: FedRAMP compliance automation, Graylog, security tooling
- **valid-eval-skills**: Claude Code skills including supply-chain-assessment
- **image-***: 12 container image build repos

## Gotchas

- **credbridge is built into every VE container image** — it provides ECR auth at runtime. Changes here affect all image-* repos.
- **Credential rotation workflow** uses org-level secrets (JIRA_API_TOKEN, SG_API_KEY) — test with `dry_run: true` workflow dispatch. It also sends compliance-review reminders from `.github/compliance-reviews.yml`; each file has its own email/Jira routing, and credential notification wording must stay unchanged. A failed or unconfigured delivery channel (GH issue, Jira, email) for an in-window item fails the run; repo or org variable `ALLOW_UNCONFIGURED_CHANNELS=true` waives only the unconfigured case. When the item's issue exists, an undelivered Jira/email channel leaves a `pending:jira`/`pending:email` label on it and is retried on later runs until delivered (red until then; the opt-out never clears it); don't remove those labels by hand unless you delivered manually. Offline check (also run by the `test-notify` job on PRs touching the workflow, harness, or data files): `node .github/tests/notify-outcomes.test.js`.
- **Go module uses `replace` directive** — `credbridge/` is a local sub-module, not a separate repo.
