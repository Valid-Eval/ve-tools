# ve-tools Code Review Guidelines

## Project Context

ve-tools is a mixed-language repository containing operational tooling and compliance data
for the Valid Eval platform. It includes Python CLI tools, a Go binary, GitHub Actions
workflows, YAML compliance data, and markdown documentation.

For full project context, read these files in order of priority:

1. **`CLAUDE.md`** — Repository structure, commands, environment context, cross-repo references
2. **`compliance/DESIGN.md`** — Compliance OS architecture, data model, and vision
3. **`compliance/ssp-review-findings.md`** — Authoritative SSP findings list

## Tech Stack — Avoid Common False Positives

- **credbridge (Go)**: AWS ECR credential bridging binary built into every VE container image.
  The `replace` directive in `go.mod` is intentional — `credbridge/` is a local sub-module.
- **vetools (Python)**: Click-based CLI with kubernetes-client and PyRSMQ dependencies.
  Installed as kubectl plugins (`kubectl ve-console`, `kubectl ve-queues`, etc.).
- **Compliance YAML**: Human-authored decision records. Scanner data stays in source systems
  (Inspector2, Grype, Dependabot). Only structural/schema issues are reviewable — content
  accuracy is a human responsibility.
- **GitHub Actions**: Credential rotation workflow uses org-level secrets (`JIRA_API_TOKEN`,
  `SG_API_KEY`). These are intentional and documented.

## What to Focus On

- Logic errors and correctness bugs in Python and Go code
- YAML schema consistency and cross-reference integrity in compliance data
- GitHub Actions workflow correctness (action versions, permissions, secret references)
- Go module dependency issues (go.mod/go.sum consistency)
- Breaking changes to credbridge (affects all VE container images downstream)
- Markdown cross-reference integrity

## What NOT to Flag

- Pre-existing code not changed in the PR
- The `replace` directive in `go.mod` (intentional local sub-module pattern)
- Hardcoded AWS GovCloud regions or account IDs in compliance docs (intentional)
- Compliance YAML content accuracy (humans own compliance decisions)
- Style, formatting, or naming suggestions
- Org-level secret references (`JIRA_API_TOKEN`, `SG_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`)
