This issue lists Renovate updates and detected dependencies. Read the [Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/) docs to learn more.<br>[View this repository on the Mend.io Web Portal](https://developer.mend.io/github/Valid-Eval/ve-tools).

## Pending Approval

The following branches are pending approval. To create them, click on a checkbox below.

 - [ ] <!-- approve-branch=renovate/kubernetes-36.x -->chore(deps): update dependency kubernetes to v36
 - [ ] <!-- approve-branch=renovate/pandas-3.x -->chore(deps): update dependency pandas to v3
 - [ ] <!-- approve-branch=renovate/major-github-actions -->chore(deps): update github-actions to v7
 - [ ] <!-- approve-all-pending-prs -->🔐 **Create all pending approval PRs at once** 🔐

## Awaiting Schedule

The following updates are awaiting their schedule. To get an update now, click on a checkbox below.

 - [ ] <!-- unschedule-branch=renovate/pandas-2.x -->chore(deps): update dependency pandas to v2.3.3
 - [ ] <!-- unschedule-branch=renovate/tabulate-0.x -->chore(deps): update dependency tabulate to v0.10.0
 - [ ] <!-- unschedule-branch=renovate/github-actions -->chore(deps): update github actions (`actions/checkout`, `anthropics/claude-code-action`)
 - [ ] <!-- create-all-awaiting-schedule-prs -->🔐 **Create all awaiting schedule PRs at once** 🔐

## Pending Status Checks

The following updates await pending status checks. To force their creation now, click on a checkbox below.

 - [ ] <!-- unpend-branch=renovate/cgr.dev-chainguard-melange-latest -->chore(deps): update cgr.dev/chainguard/melange:latest docker digest to 9d5e855

## Detected Dependencies

<details><summary>github-actions (5)</summary>
<blockquote>

<details><summary>.github/workflows/claude-code-review.yml (2)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `anthropics/claude-code-action v1.0.236@8ce9314fa9a404564fa7e954cd84f25bcba2b829` → [Updates: `v1.0.237`]

</details>

<details><summary>.github/workflows/claude.yml (2)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `anthropics/claude-code-action v1.0.236@8ce9314fa9a404564fa7e954cd84f25bcba2b829` → [Updates: `v1.0.237`]

</details>

<details><summary>.github/workflows/credential-rotation-reminder.yml (5)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/github-script v9.0.0@3a2844b7e9c422d3c10d287c895573f7108da1b3`

</details>

<details><summary>.github/workflows/fips-invariant-check.yml (2)</summary>

 - `actions/checkout v6.0.3@df4cb1c069e1874edd31b4311f1884172cec0e10` → [Updates: `v6.1.0`, `v7.0.1`]
 - `actions/setup-go v7.0.0@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`

</details>

<details><summary>.github/workflows/melange.yml (3)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`

</details>

</blockquote>
</details>

<details><summary>gomod (3)</summary>
<blockquote>

<details><summary>credbridge/go.mod (1)</summary>

 - `go 1.22.0`

</details>

<details><summary>fips-invariant-check/go.mod (1)</summary>

 - `go 1.24`

</details>

<details><summary>go.mod (1)</summary>

 - `go 1.22.0`

</details>

</blockquote>
</details>

<details><summary>pip_requirements (1)</summary>
<blockquote>

<details><summary>requirements.txt (7)</summary>

 - `click ==8.5.0`
 - `sh ==2.4.0`
 - `PyRSMQ ==0.6.1`
 - `kubernetes ==31.0.0` → [Updates: `==36.0.3`]
 - `PyYAML ==6.0.3`
 - `pandas ==2.2.3` → [Updates: `==2.3.3`, `==3.0.6`]
 - `tabulate ==0.9.0` → [Updates: `==0.10.0`]

</details>

</blockquote>
</details>

<details><summary>pyenv (1)</summary>
<blockquote>

<details><summary>.python-version</summary>


</details>

</blockquote>
</details>

<details><summary>regex (2)</summary>
<blockquote>

<details><summary>melange/build.sh (1)</summary>

 - `cgr.dev/chainguard/melange latest@sha256:15dd85c0e35c099e4142c463d8479da769f319f01ab0f9e6ff427f79d63091f9` → [Updates: `latest`]

</details>

<details><summary>melange/libpq-17.yaml (1)</summary>

 - `postgres/postgres REL_17_11@083ac033419f690758508e08c1736089384bbee8`

</details>

</blockquote>
</details>

---

- [ ] <!-- manual job -->Check this box to trigger a request for Renovate to run again on this repository


