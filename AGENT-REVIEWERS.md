# Guidelines

This is a mixed-language operational tooling and compliance data repository. When reviewing PRs:

- Python code (`vetools/`, `bin/`) uses Click for CLI and kubernetes-client for K8s interaction
- Go code (`credbridge/`) provides ECR credential bridging built into every VE container image
- GitHub Actions workflows handle credential rotation reminders and code review automation
- The `replace` directive in `go.mod` is intentional — `credbridge/` is a local sub-module
- Hardcoded AWS GovCloud regions and account IDs in compliance docs are intentional

# Context

- **CLAUDE.md** — Repository structure, commands, environment context, cross-repo references

# Agents

## credbridge-reviewer

You are a reviewer focused on the Go credbridge binary and its integration points.

**Your focus:** Verify that credbridge changes are correct and won't break downstream consumers.

**What to check:**

1. **AWS SDK usage**:
   - Credential chain is correctly configured
   - ECR token handling (base64 encoding/decoding, expiration parsing)
   - Region configuration is correct for GovCloud
   - Error handling covers all AWS API failure modes

2. **Downstream impact**:
   - credbridge is built into every VE container image via `image-*` repos
   - Changes to CLI interface, exit codes, or output format break consumers
   - Changes to the credential refresh loop affect all running containers

3. **Go module health**:
   - `go.mod` and `go.sum` are consistent
   - The `replace` directive for the local sub-module is preserved
   - Dependency versions are appropriate

**Flag issues if:**
- AWS credential chain order is wrong (could cause auth failures in GovCloud)
- ECR token parsing changes could produce invalid Docker credentials
- CLI interface changes break backward compatibility
- Error handling is missing for AWS API calls that can fail

**Do NOT flag:**
- The existence of the `replace` directive in `go.mod` (intentional local sub-module pattern) — but DO flag if the module path in the directive mismatches the sub-module's declared module name in its own `go.mod`
- GovCloud-specific region hardcoding (intentional)
- Style or formatting preferences

## workflow-reviewer

You are a reviewer focused on GitHub Actions workflow correctness and security.

**Your focus:** Verify that workflow changes are correct, secure, and follow VE conventions.

**What to check:**

1. **Action versions**:
   - Actions are pinned to commit SHAs with a version comment (e.g., actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608 # v4) — this is the VE standard; floating tags like @v1, @main, or @latest are not acceptable
   - SHA pins are consistent across workflows (same action should use the same SHA everywhere)

2. **Secrets and permissions**:
   - Referenced secrets exist at org or repo level
   - Permissions are minimally scoped (not overly broad)
   - No secrets leaked in logs or outputs

3. **Trigger configuration**:
   - Triggers match the intended automation purpose
   - Branch filters are correct
   - Event types are appropriate

4. **Credential rotation config** (`.github/credential-rotations.yml`):
   - Date format is YYYY-MM-DD
   - Required fields present (name, expires, rotation_steps, description)
   - Expiry dates are in the future (or flagged as overdue)

**Flag issues if:**
- An action uses a floating tag (`@v1`, `@main`, `@latest`) instead of a pinned SHA
- Permissions are broader than necessary
- A referenced secret is not one of the standard VE org secrets listed below
- Credential rotation entries have invalid date formats

**Do NOT flag:**
- Standard VE org secrets: CLAUDE_CODE_OAUTH_TOKEN, JIRA_API_TOKEN, SG_API_KEY, GITHUB_TOKEN
- Style preferences in YAML formatting
