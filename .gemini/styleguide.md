# ve-tools Code Review Guidelines

## Project Context

For full project context, read `CLAUDE.md` — repository structure, commands, environment context, and cross-repo references.

## Tech Stack — Avoid Common False Positives

- **credbridge (Go)**: AWS ECR credential bridging binary built into every VE container image.
  The `replace` directive in `go.mod` is intentional — `credbridge/` is a local sub-module.
- **vetools (Python)**: Click-based CLI with kubernetes-client and PyRSMQ dependencies.
  Installed as kubectl plugins (`kubectl ve-console`, `kubectl ve-queues`, etc.).
- **Compliance YAML**: Human-authored decision records. Scanner data stays in source systems
  (Inspector2, Grype, Dependabot). Only structural/schema issues are reviewable — content
  accuracy is a human responsibility.
- **GitHub Actions**: Credential rotation workflow uses org-level secrets (`JIRA_API_TOKEN`,
  `SG_API_KEY`).

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
