// Offline harness for the "Create notifications" github-script step in
// .github/workflows/credential-rotation-reminder.yml. It extracts the script from the
// workflow file and runs it with mocked github/context/core/fetch: nothing touches
// GitHub, Jira, or SendGrid, and all credentials below are dummy values.
// CI runs it on pull requests that touch the workflow, the harness, or the data files
// (the test-notify job in the same workflow).
//
//   node .github/tests/notify-outcomes.test.js                    # run the outcome scenarios
//   node .github/tests/notify-outcomes.test.js --calls [workflow]  # run that workflow file
//       (default: the repo one) on an all-success scenario and print every outgoing call as
//       JSON to stdout; redirect two versions and cmp them for a byte-for-byte payload check
//   WORKFLOW_FILE=<path> node ...                                  # run the scenarios against another version
'use strict';
const fs = require('fs');
const assert = require('assert');

const ROUTING = { email_to: 'to@example.test', email_from: 'from@example.test' };
const ITEMS = {
  credential: { kind: 'credential', name: 'CRED_A', description: 'Cred desc', date: '2026-10-10', days_left: 8,
    notes: 'a note', jira_priority: 'Medium', steps: '1. Rotate\n   - sub bullet\n2. Update', ...ROUTING, jira_project: 'VEP' },
  expired: { kind: 'credential', name: 'CRED_OLD', description: 'Old cred', date: '2026-09-25', days_left: -7,
    steps: '1. Rotate', ...ROUTING, jira_project: 'VEP' },
  review: { kind: 'compliance_review', name: 'REVIEW_A', description: 'Review desc', date: '2026-10-20', days_left: 18,
    notes: 'review note', steps: '1. Look\n2. Record', compliance_ref: 'https://example.test/record',
    jira_ref: 'INF-382', email_to: 'review-to@example.test', email_from: 'review-from@example.test', jira_project: 'INF' },
  reviewToday: { kind: 'compliance_review', name: 'REVIEW_T', description: 'd', date: '2026-10-02', days_left: 0,
    steps: '1. x', compliance_ref: 'https://example.test/record', jira_ref: 'INF-382', ...ROUTING, jira_project: 'INF' },
  reviewOver: { kind: 'compliance_review', name: 'REVIEW_O', description: 'd', date: '2026-10-01', days_left: -1,
    steps: '1. x', compliance_ref: 'https://example.test/record', jira_ref: 'INF-382', ...ROUTING, jira_project: 'INF' },
  credToday: { kind: 'credential', name: 'CRED_T', description: 'd', date: '2026-10-02', days_left: 0,
    steps: '1. x', ...ROUTING, jira_project: 'VEP' },
  test: { kind: 'credential', name: 'TEST_CREDENTIAL', description: 'Test', date: '2026-10-02', days_left: 0,
    is_test: true, steps: '1. none', ...ROUTING, jira_project: 'VEP' },
  noEmail: { kind: 'credential', name: 'CRED_NOMAIL', description: 'd', date: '2026-10-10', days_left: 8,
    steps: '1. x', email_to: '', email_from: '', jira_project: 'VEP' },
  badKind: { kind: 'mystery', name: 'ODD', description: 'd', date: '2026-10-10', days_left: 8, steps: '1. x',
    ...ROUTING, jira_project: 'VEP' },
};
const TITLES = { CRED_A: 'Rotate credential: CRED_A', REVIEW_A: 'Compliance review due: REVIEW_A' };

// Locate the step by its action (actions/github-script), then take its `script: |` block at
// whatever indentation it has, so re-indenting or reordering steps does not break extraction.
function extractScript(path) {
  const lines = fs.readFileSync(path, 'utf8').split('\n');
  const usesIdx = lines.map((l, i) => (/^\s*uses:\s*actions\/github-script@/.test(l) ? i : -1)).filter(i => i >= 0);
  assert.strictEqual(usesIdx.length, 1, `expected exactly one actions/github-script step, found ${usesIdx.length}`);
  const start = lines.findIndex((l, i) => i > usesIdx[0] && /^\s*script:\s*\|\s*$/.test(l));
  assert(start >= 0, 'script: | block not found after the github-script step');
  const keyIndent = lines[start].match(/^\s*/)[0].length;
  const out = [];
  let bodyIndent = null;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === '') { out.push(''); continue; }
    const ind = l.match(/^\s*/)[0].length;
    if (ind <= keyIndent) break;
    if (bodyIndent === null) bodyIndent = ind;
    out.push(l.slice(bodyIndent));
  }
  assert(out.join('').includes('async function notify'), 'extracted block does not look like the notify script');
  return out.join('\n');
}

// opts: items, env, jira/sendgrid ({status, body, badJson} or {throws}), issueFails,
//       existing ({title: [labels]}, matched by exact phrase), searchItems ([{title, labels}],
//       returned for every query, like a phrase match), searchThrows, searchBroken (no data),
//       labelBootstrap ('fail' | 'missing' | 'race'), removeLabelFails (HTTP status, every removal), removeLabelFailsFor (one label name, HTTP 500), matchedNumber (issue number the search returns; default 7), createDropsLabels, createLabelsShape ('strings' | 'absent'), liveLabels ([labels issues.get returns; default = what search showed]), getIssueFails (HTTP status), liveState ('closed'), liveShape ('strings' | 'absent'), existingLabels ([names that getLabel finds; others 404]), itemOverrides ({item: fields})
async function run(workflowPath, opts) {
  const calls = [], logs = [], failed = [];
  const env = { JIRA_USER_EMAIL: 'dummy@example.test', JIRA_API_TOKEN: 'dummy-jira-token',
    SG_API_KEY: 'dummy-sg-key', ...opts.env };
  const saved = { ...process.env };
  for (const k of ['JIRA_USER_EMAIL', 'JIRA_API_TOKEN', 'SG_API_KEY', 'ALLOW_UNCONFIGURED_CHANNELS']) delete process.env[k];
  Object.assign(process.env, env, { CHECK_RESULT: JSON.stringify({ due: opts.items.map(k => ({ ...ITEMS[k], ...((opts.itemOverrides || {})[k] || {}) })) }) });
  const realFetch = global.fetch, realLog = console.log, realErr = console.error;
  global.fetch = async (url, init) => {
    calls.push({ fetch: url, init });
    const b = url.includes('atlassian') ? opts.jira : opts.sendgrid;
    if (b && b.throws) throw new Error(b.throws);
    const status = (b && b.status) || (url.includes('atlassian') ? 201 : 202);
    return { ok: status < 300, status,
      json: async () => { if (b && b.badJson) throw new SyntaxError('Unexpected token <'); return { key: 'FAKE-1' }; },
      text: async () => (b && b.body) || `body-${status}` };
  };
  console.log = (...a) => logs.push(a.join(' '));
  console.error = (...a) => logs.push('ERR ' + a.join(' '));
  const existing = opts.existing || {};
  let n = 100;
  let lastSearchLabels = [];
  const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
  const github = { rest: {
    issues: {
      get: async p => {
        calls.push({ issueGet: p });
        if (opts.getIssueFails) throw httpErr(opts.getIssueFails, `issues.get ${opts.getIssueFails}`);
        const names = opts.liveLabels || lastSearchLabels;  // the issue itself; default: what search showed
        const labels = opts.liveShape === 'strings' ? names : opts.liveShape === 'absent' ? undefined : names.map(name => ({ name }));
        return { data: { number: p.issue_number, state: opts.liveState || 'open', labels } };
      },
      getLabel: async p => {
        calls.push({ getLabel: p });
        if (opts.labelBootstrap === 'fail') throw httpErr(500, 'getLabel 500');
        if (opts.labelBootstrap === 'missing' || opts.labelBootstrap === 'race') throw httpErr(404, 'Not Found');
        if (opts.existingLabels && !opts.existingLabels.includes(p.name)) throw httpErr(404, 'Not Found');
        return {};
      },
      createLabel: async p => {
        calls.push({ createLabel: p });
        if (opts.labelBootstrap === 'fail') throw httpErr(403, 'createLabel 403');
        if (opts.labelBootstrap === 'race') throw httpErr(422, 'already_exists');
        return {};
      },
      create: async p => { calls.push({ issueCreate: p, failed: !!opts.issueFails }); if (opts.issueFails) throw new Error('GitHub 500'); return { data: { number: n++, labels: opts.createDropsLabels ? [] : opts.createLabelsShape === 'strings' ? p.labels : opts.createLabelsShape === 'absent' ? undefined : p.labels.map(name => ({ name })) } }; },
      removeLabel: async p => {
        calls.push({ removeLabel: p });
        if (opts.removeLabelFails) throw httpErr(opts.removeLabelFails, `removeLabel ${opts.removeLabelFails}`);
        if (opts.removeLabelFailsFor === p.name) throw httpErr(500, `removeLabel ${p.name} 500`);
        return {};
      },
    },
    search: { issuesAndPullRequests: async p => {
      calls.push({ search: p });
      if (opts.searchThrows) throw httpErr(403, 'secondary rate limit');
      if (opts.searchBroken) return { data: null };
      const toItem = ([title, labels]) => ({ number: opts.matchedNumber || 7, title, labels: ['maintenance', ...labels].map(name => ({ name })) });
      if (opts.searchItems) { lastSearchLabels = (opts.searchItems[0] || {}).labels || []; return { data: { items: opts.searchItems.map(i => (i.noLabelsField ? { number: 7, title: i.title } : toItem([i.title, i.labels]))) } }; }
      const items = Object.entries(existing).filter(([t]) => p.q.includes(`"${t}"`)).map(toItem);
      lastSearchLabels = items[0] ? items[0].labels.map(l => l.name).filter(l => l !== 'maintenance') : [];
      return { data: { items } };
    } },
  } };
  const core = { setFailed: m => failed.push(m) };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  try {
    await new AsyncFunction('github', 'context', 'core', extractScript(workflowPath))(
      github, { repo: { owner: 'o', repo: 'r' } }, core);
  } finally {
    global.fetch = realFetch; console.log = realLog; console.error = realErr;
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, saved);
  }
  const count = pred => calls.filter(pred).length;
  return { calls, logs, failed,
    issues: count(c => c.issueCreate), jira: count(c => c.fetch && c.fetch.includes('atlassian')),
    email: count(c => c.fetch && c.fetch.includes('sendgrid')),
    // Pending labels left on newly created issues at the end of the run: the labels issues.create
    // attached, minus those later removed. (addLabels is no longer called: issues are born pending.)
    added: calls.filter(c => c.issueCreate && !c.failed).flatMap(c => c.issueCreate.labels.filter(l => l.startsWith('pending:')))
      .filter(l => !calls.some(c => c.removeLabel && c.removeLabel.name === l)),
    createdLabels: calls.filter(c => c.issueCreate).map(c => c.issueCreate.labels),
    removed: calls.filter(c => c.removeLabel).map(c => c.removeLabel.name),
    labelCreates: count(c => c.createLabel) };
}

const issueOf = r => r.calls.find(x => x.issueCreate).issueCreate;
// Parsed outgoing request bodies, in call order.
const fetchesTo = (r, host) => r.calls.filter(c => c.fetch && c.fetch.includes(host)).map(c => ({ url: c.fetch, headers: c.init.headers, body: JSON.parse(c.init.body) }));
const green = r => assert.deepStrictEqual(r.failed, []);
// red(r, ...parts) or red(r, {lines: n}, ...parts): one setFailed containing every part,
// and optionally exactly n recorded failures (summary lines after the header).
const red = (r, ...parts) => {
  const opts = parts[0] && typeof parts[0] === 'object' && !(parts[0] instanceof RegExp) ? parts.shift() : {};
  assert.strictEqual(r.failed.length, 1, `expected exactly one setFailed, got ${r.failed.length}`);
  for (const p of parts) assert(p instanceof RegExp ? p.test(r.failed[0]) : r.failed[0].includes(p), `missing ${p} in: ${r.failed[0]}`);
  if (opts.lines !== undefined) assert.strictEqual(r.failed[0].split('\n').length - 1, opts.lines, `expected ${opts.lines} failure line(s): ${r.failed[0]}`);
};

async function main() {
  const wf = process.env.WORKFLOW_FILE || '.github/workflows/credential-rotation-reminder.yml';
  if (process.argv[2] === '--calls') {
    const r = await run(process.argv[3] || wf, { items: ['credential', 'expired', 'review', 'test'] });
    process.stdout.write(JSON.stringify(r.calls, null, 1) + '\n');
    return;
  }
  const all = ['credential', 'review'];
  const cases = [
    ['success is green and every channel runs once per item', { items: all }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [2, 2, 2]);
      // Both items are created owing both channels, and each delivered channel's label is removed.
      assert.deepStrictEqual(r.createdLabels, [['maintenance', 'pending:jira', 'pending:email'], ['maintenance', 'pending:jira', 'pending:email']]);
      assert.deepStrictEqual(r.added, []); assert.deepStrictEqual(r.removed, ['pending:jira', 'pending:email', 'pending:jira', 'pending:email']);
    }],
    ['zero in-window items is green and sends nothing (only the label bootstrap may run)', { items: [] }, r => {
      green(r); assert.deepStrictEqual(r.calls.filter(c => !c.getLabel && !c.createLabel), []);
    }],
    ['Jira HTTP 500 fails, names item x channel, email still sent', { items: all, jira: { status: 500 } }, r => {
      red(r, 'credential CRED_A x jira', 'compliance_review REVIEW_A x jira'); assert(!r.failed[0].includes('x email'));
      assert.strictEqual(r.email, 2);
    }],
    ['Jira network error fails', { items: ['credential'], jira: { throws: 'ECONNREFUSED' } }, r => red(r, /CRED_A x jira: ECONNREFUSED/)],
    ['failure detail carries the HTTP status and is capped at 300 characters', { items: ['credential'], jira: { status: 400, body: 'x'.repeat(1000) } }, r => {
      red(r, { lines: 1 }, 'CRED_A x jira: HTTP 400 xxx');
      const detail = r.failed[0].split('\n')[1].split('x jira: ')[1];
      assert.strictEqual(detail.length, 300);
    }],
    ['Jira 2xx with unparseable body is delivered, not a failure', { items: ['credential'], jira: { status: 201, badJson: true } }, r => {
      green(r); assert.deepStrictEqual(r.added, []);
    }],
    ['SendGrid HTTP 500 fails and names item x channel', { items: all, sendgrid: { status: 500 } }, r => {
      red(r, 'credential CRED_A x email', 'compliance_review REVIEW_A x email'); assert(!r.failed[0].includes('x jira'));
    }],
    ['multi-line error body stays one summary line per failure', { items: ['credential'], jira: { status: 400, body: '{\n "errors": {\n  "priority": "bad"\n }\n}' } }, r => {
      red(r, 'CRED_A x jira'); assert.strictEqual(r.failed[0].split('\n').length, 2);
    }],
    ['GitHub issue failure fails; Jira and email still attempted; no label call', { items: ['credential'], issueFails: true }, r => {
      red(r, 'CRED_A x github-issue'); assert.deepStrictEqual([r.jira, r.email], [1, 1]); assert.deepStrictEqual(r.added, []); assert.deepStrictEqual(r.removed, []);
    }],
    ['all channels failing for several items are all listed in one setFailed', { items: all, issueFails: true, jira: { status: 500 }, sendgrid: { throws: 'boom' } }, r => {
      red(r); assert.strictEqual(r.failed[0].split('\n').length, 1 + 6);
    }],
    ['Jira token missing fails by default and labels the issue pending:jira', { items: ['credential'], env: { JIRA_API_TOKEN: '' } }, r => {
      red(r, /CRED_A x jira: not configured/); assert.deepStrictEqual(r.added, ['pending:jira']);
    }],
    ['Jira user email missing fails by default', { items: ['credential'], env: { JIRA_USER_EMAIL: '' } }, r => { red(r, /CRED_A x jira: not configured/); assert.strictEqual(r.jira, 0); }],
    ['SendGrid failure detail carries the HTTP status', { items: ['credential'], sendgrid: { status: 400, body: 'bad' } }, r => red(r, { lines: 1 }, 'CRED_A x email: HTTP 400 bad')],
    ['SendGrid key missing fails by default', { items: ['credential'], env: { SG_API_KEY: '' } }, r => red(r, /CRED_A x email: not configured/)],
    ['empty email_to fails by default and sends nothing to SendGrid', { items: ['noEmail'] }, r => { red(r, /CRED_NOMAIL x email: not configured/); assert.strictEqual(r.email, 0); }],
    ['unconfigured passes with ALLOW_UNCONFIGURED_CHANNELS=true, and leaves no pending label', { items: all, env: { JIRA_API_TOKEN: '', SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' } }, r => {
      green(r); assert.deepStrictEqual(r.added, []);
    }],
    ['opt-out does not hide real failures', { items: ['credential'], env: { SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' }, jira: { status: 500 } }, r => {
      red(r, 'x jira'); assert(!r.failed[0].includes('x email'));
    }],
    // Retry state: the red must not be one-shot.
    ['first-run Jira failure labels the new issue pending:jira only', { items: ['credential'], jira: { status: 500 } }, r => {
      red(r, 'CRED_A x jira'); assert.deepStrictEqual(r.added, ['pending:jira']);
    }],
    ['first-run email failure labels the new issue pending:email only', { items: ['credential'], sendgrid: { status: 500 } }, r => {
      red(r, 'CRED_A x email'); assert.deepStrictEqual(r.added, ['pending:email']);
    }],
    ['first-run email throw labels the new issue pending:email', { items: ['credential'], sendgrid: { throws: 'ETIMEDOUT' } }, r => {
      assert.deepStrictEqual(r.added, ['pending:email']);
    }],
    ['unconfigured channel (no opt-out) labels the issue pending', { items: ['credential'], env: { SG_API_KEY: '' } }, r => {
      assert.deepStrictEqual(r.added, ['pending:email']);
    }],
    ['open issue without pending labels is skipped: green, no sends', { items: ['credential'], existing: { [TITLES.CRED_A]: [] } }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 0, 0]);
    }],
    ['open issue with pending:jira retries only Jira; success clears the label', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] } }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 1, 0]); assert.deepStrictEqual(r.removed, ['pending:jira']);
      assert.deepStrictEqual(r.added, []);
    }],
    ['open issue with pending:email retries only email; success clears the label', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:email'] } }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 0, 1]); assert.deepStrictEqual(r.removed, ['pending:email']);
    }],
    ['both pending: Jira delivered, email fails again -> only pending:jira removed, red on email', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira', 'pending:email'] }, sendgrid: { status: 500 } }, r => {
      red(r, { lines: 1 }, 'CRED_A x email'); assert.deepStrictEqual([r.jira, r.email], [1, 1]);
      assert.deepStrictEqual(r.removed, ['pending:jira']); assert.deepStrictEqual(r.added, []);
    }],
    ['retry with Jira now waived by the opt-out keeps pending:jira', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, env: { JIRA_API_TOKEN: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' } }, r => {
      green(r); assert.deepStrictEqual(r.removed, []); assert.deepStrictEqual(r.added, []);
    }],
    ['retry with email now waived by the opt-out keeps pending:email', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:email'] }, env: { SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' } }, r => {
      green(r); assert.deepStrictEqual(r.removed, []); assert.deepStrictEqual(r.added, []);
    }],
    ['both delivered on retry: removal 404s count as already removed, and both removals are attempted', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira', 'pending:email'] }, removeLabelFails: 404 }, r => {
      green(r); assert.deepStrictEqual(r.removed, ['pending:jira', 'pending:email']);
    }],
    ['label removal failure (non-404) is recorded as retry-state', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, removeLabelFails: 500 }, r => {
      red(r, { lines: 1 }, 'CRED_A x retry-state', 'could not remove pending:jira');
    }],
    ['a phrase-matching but non-exact open issue is not treated as the item\'s issue', { items: ['credential'], searchItems: [{ title: 'Rotate credential: CRED_A_OLD', labels: ['pending:jira'] }] }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]); assert.deepStrictEqual(r.removed, ['pending:jira', 'pending:email']);
    }],
    ['retry that fails again stays red and keeps the label', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, jira: { status: 401 } }, r => {
      red(r, 'CRED_A x jira'); assert.deepStrictEqual(r.removed, []); assert.deepStrictEqual(r.added, []);
    }],
    ['retry with the channel still unconfigured stays red (fix-then-rerun must not go falsely green)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:email'] }, env: { SG_API_KEY: '' } }, r => {
      red(r, /CRED_A x email: not configured/); assert.deepStrictEqual(r.removed, []);
    }],
    ['an issue created without its pending labels is a recorded failure (the retry state would otherwise be missing)', { items: ['credential'], createDropsLabels: true }, r => {
      red(r, 'CRED_A x retry-state', 'created without pending:jira, pending:email');
    }],
    ['failure to remove a delivered channel\'s label is itself a failure (a stale label would re-send)', { items: ['credential'], removeLabelFails: 500 }, r => {
      red(r, 'CRED_A x retry-state', 'could not remove pending:jira');
    }],
    ['first run: a Jira failure keeps pending:jira on the new issue and still removes pending:email', { items: ['credential'], jira: { status: 500 } }, r => {
      red(r, 'CRED_A x jira'); assert.deepStrictEqual(r.removed, ['pending:email']); assert.deepStrictEqual(r.added, ['pending:jira']);
    }],
    // Whole-item failures are loud, recorded in the single summary, and do not stop other items.
    ['dedup search failure skips that item, is recorded, and the next item is still delivered', { items: ['credential', 'review'], searchThrows: true }, r => {
      red(r, { lines: 2 }, 'CRED_A x dedup-search', 'REVIEW_A x dedup-search'); assert.deepStrictEqual([r.jira, r.email], [0, 0]);
    }],
    ['unknown kind is recorded and the next item is still delivered', { items: ['badKind', 'credential'] }, r => {
      red(r, { lines: 1 }, 'mystery ODD x kind'); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
    }],
    ['an unexpected error inside an item is recorded as x item and the run continues', { items: ['credential', 'review'], searchBroken: true }, r => {
      red(r, { lines: 2 }, 'CRED_A x item', 'REVIEW_A x item');
    }],
    // Wording and structure the sender produces per kind (pins the OVERDUE boundary, titles and References).
    ['compliance review due today is not OVERDUE', { items: ['reviewToday'] }, r => {
      green(r); const i = issueOf(r); assert.strictEqual(i.title, 'Compliance review due: REVIEW_T');
      assert(i.body.includes('**0 days** until due'), i.body); assert(!i.body.includes('OVERDUE'), i.body);
    }],
    ['compliance review one day past due is OVERDUE', { items: ['reviewOver'] }, r => {
      green(r); assert(issueOf(r).body.includes('**OVERDUE** (1 days ago)'), issueOf(r).body);
    }],
    ['credential expiring today is EXPIRED (its boundary differs from a review)', { items: ['credToday'] }, r => {
      green(r); assert(issueOf(r).body.includes('**EXPIRED** (0 days ago)'), issueOf(r).body);
    }],
    ['compliance review issue carries a References block; a credential issue does not', { items: all }, r => {
      green(r); const [c, v] = [r.calls.filter(x => x.issueCreate)[0].issueCreate, r.calls.filter(x => x.issueCreate)[1].issueCreate];
      assert.strictEqual(c.title, TITLES.CRED_A); assert(!c.body.includes('### References'), c.body);
      assert.strictEqual(v.title, TITLES.REVIEW_A);
      for (const line of ['### References', '- Compliance record: https://example.test/record', '- Jira: https://valideval.atlassian.net/browse/INF-382']) assert(v.body.includes(line), v.body);
    }],
    // Dedup query, test credentials, routing and payload content (what actually goes out).
    ['dedup search is scoped to this repo, open issues, the maintenance label and the exact title', { items: ['credential'] }, r => {
      green(r); const q = r.calls.find(c => c.search).search.q;
      for (const part of ['repo:o/r', 'is:issue', 'is:open', 'in:title', `"${TITLES.CRED_A}"`, 'label:maintenance']) assert(q.includes(part), `${part} missing from: ${q}`);
    }],
    ['first-run Jira network error keeps pending:jira and removes pending:email', { items: ['credential'], jira: { throws: 'ECONNREFUSED' } }, r => {
      red(r, /CRED_A x jira: ECONNREFUSED/); assert.deepStrictEqual(r.added, ['pending:jira']); assert.deepStrictEqual(r.removed, ['pending:email']);
    }],
    ['test credential skips dedup and is prefixed and labelled test everywhere', { items: ['test'], existing: { 'Rotate credential: TEST_CREDENTIAL': [] } }, r => {
      green(r); assert(!r.calls.some(c => c.search), 'test credentials must not search for an existing issue');
      assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
      const issue = r.calls.find(c => c.issueCreate).issueCreate;
      assert(issue.title.startsWith('[TEST] '), issue.title); assert(issue.labels.includes('test'), issue.labels);
      assert(fetchesTo(r, 'atlassian')[0].body.fields.summary.startsWith('[TEST] '));
      assert(fetchesTo(r, 'sendgrid')[0].body.subject.includes('[TEST] '));
    }],
    ['each item is routed by its own email_to / email_from / jira_project', { items: all }, r => {
      green(r); const [jc, jr] = fetchesTo(r, 'atlassian'), [ec, er] = fetchesTo(r, 'sendgrid');
      assert.deepStrictEqual([jc.body.fields.project.key, jr.body.fields.project.key], ['VEP', 'INF']);
      assert.deepStrictEqual([ec.body.personalizations[0].to[0].email, ec.body.from.email], ['to@example.test', 'from@example.test']);
      assert.deepStrictEqual([er.body.personalizations[0].to[0].email, er.body.from.email], ['review-to@example.test', 'review-from@example.test']);
    }],
    ['email falls back to email_to as the sender when email_from is empty', { items: ['credential'], itemOverrides: { credential: { email_from: '' } } }, r => {
      green(r); assert.strictEqual(fetchesTo(r, 'sendgrid')[0].body.from.email, 'to@example.test');
    }],
    ['Jira payload: auth, type, priority (own or per-kind default), wiki steps, references, footer', { items: ['credential', 'review'] }, r => {
      green(r); const [jc, jr] = fetchesTo(r, 'atlassian');
      assert.strictEqual(jc.url, 'https://valideval.atlassian.net/rest/api/2/issue');
      assert.strictEqual(jc.headers.Authorization, 'Basic ' + Buffer.from('dummy@example.test:dummy-jira-token').toString('base64'));
      assert.strictEqual(jc.body.fields.issuetype.name, 'Task');
      assert.strictEqual(jc.body.fields.priority.name, 'Medium');   // the item's own jira_priority, not the default
      assert.strictEqual(jr.body.fields.priority.name, 'High');     // review default
      assert(jc.body.fields.description.includes('# Rotate\n   - sub bullet\n# Update'), jc.body.fields.description);  // numbered lines become wiki items, others pass through
      assert(jr.body.fields.description.includes('Compliance record: https://example.test/record'));
      assert(jr.body.fields.description.includes('Jira: https://valideval.atlassian.net/browse/INF-382'));
      assert(jc.body.fields.description.endsWith('close this ticket.'));
      assert(jr.body.fields.description.includes('close this ticket.'));
    }],
    ['SendGrid payload: auth, notes and references present; expired item says how long ago', { items: ['credential', 'review', 'expired'] }, r => {
      green(r); const [ec, er, ex] = fetchesTo(r, 'sendgrid'), [, , jx] = fetchesTo(r, 'atlassian');
      assert.strictEqual(ec.url, 'https://api.sendgrid.com/v3/mail/send'); assert.strictEqual(ec.headers.Authorization, 'Bearer dummy-sg-key');
      assert(ec.body.content[0].value.includes('Notes:\na note'));
      assert(er.body.content[0].value.includes('References:') && er.body.content[0].value.includes('Compliance record: https://example.test/record'));
      assert(ex.body.content[0].value.includes('EXPIRED (7 days ago)'), ex.body.content[0].value);
      assert(jx.body.fields.description.includes('EXPIRED (7 days ago)'), jx.body.fields.description);
    }],
    ['an open issue whose labels field is absent is treated as delivered', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, liveShape: 'absent' }, r => {
      green(r); assert.strictEqual(r.calls.filter(c => c.issueCreate).length, 0); assert.deepStrictEqual([r.jira, r.email], [0, 0]);
    }],
    ['string labels from issues.get are read (defensive shape)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, liveShape: 'strings' }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 1, 0]); assert.deepStrictEqual(r.removed, ['pending:jira']);
    }],
    ['an issue closed since the search indexed it is skipped even with a pending label (no resend)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, liveState: 'closed' }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 0, 0]); assert.deepStrictEqual(r.removed, []);
      assert(r.logs.some(l => l.includes('is closed (search index lag)')), r.logs.join('\n'));
    }],
    ['any 2xx from SendGrid or Jira counts as delivered', { items: ['credential'], sendgrid: { status: 200 }, jira: { status: 200 } }, r => {
      green(r); assert.deepStrictEqual(r.added, []);
    }],
    ['a credential without jira_priority gets the credential default (Highest)', { items: ['expired'] }, r => {
      green(r); assert.strictEqual(fetchesTo(r, 'atlassian')[0].body.fields.priority.name, 'Highest');
    }],
    ['footers and notes: credential email footer verbatim, issue body notes (and None)', { items: ['credential', 'expired'] }, r => {
      green(r); const [ec] = fetchesTo(r, 'sendgrid');
      assert(ec.body.content[0].value.endsWith('After rotating, update the expires date in .github/credential-rotations.yml in the ve-tools repo.'));
      const [c, x] = r.calls.filter(c => c.issueCreate).map(c => c.issueCreate.body);
      assert(c.includes('### Notes\n\na note'), c); assert(x.includes('### Notes\n\nNone'), x);
    }],
    ['issue create returning string labels is read correctly (no retry-state failure)', { items: ['credential'], createLabelsShape: 'strings' }, green],
    ['issue create response with no labels field records retry-state for both labels', { items: ['credential'], createLabelsShape: 'absent' }, r => {
      red(r, 'CRED_A x retry-state', 'created without pending:jira, pending:email');
    }],
    ['a label that already exists when createLabel runs (422 race) is silent and delivery proceeds', { items: ['credential'], labelBootstrap: 'race' }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]); assert(!r.logs.some(l => l.startsWith('ERR createLabel')), r.logs.join('\n'));
    }],
    ['only the missing labels are created: maintenance exists, the pending labels do not', { items: ['credential'], existingLabels: ['maintenance'] }, r => {
      green(r);
      assert.deepStrictEqual(r.calls.filter(c => c.getLabel).map(c => c.getLabel.name), ['maintenance', 'pending:jira', 'pending:email']);
      assert.deepStrictEqual(r.calls.filter(c => c.createLabel).map(c => c.createLabel.name), ['pending:jira', 'pending:email']);
    }],
    ['stale search index: search shows no pending labels but the issue still has pending:jira -> retried', { items: ['credential'], existing: { [TITLES.CRED_A]: [] }, liveLabels: ['pending:jira'] }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 1, 0]); assert.deepStrictEqual(r.removed, ['pending:jira']);
    }],
    ['stale search index: search still shows a pending label the issue no longer has -> skipped, no resend', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira', 'pending:email'] }, liveLabels: [] }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 0, 0]); assert.deepStrictEqual(r.removed, []);
    }],
    ['a failed issues.get skips the item and fails the run (cannot tell delivered from owed)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, getIssueFails: 500 }, r => {
      red(r, { lines: 1 }, 'CRED_A x dedup-labels', 'could not read labels of open issue #7: HTTP 500', 'issues.get 500'); assert.deepStrictEqual([r.issues, r.jira, r.email], [0, 0, 0]);
    }],
    ['issues.get and removeLabel target the matched issue (number, owner, repo)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, matchedNumber: 4242 }, r => {
      green(r);
      assert.deepStrictEqual(r.calls.filter(c => c.issueGet).map(c => c.issueGet), [{ owner: 'o', repo: 'r', issue_number: 4242 }]);
      assert.deepStrictEqual(r.calls.filter(c => c.removeLabel).map(c => c.removeLabel.issue_number), [4242]);
    }],
    ['no duplicate -> issues.get is not called', { items: ['credential'] }, r => {
      green(r); assert.strictEqual(r.calls.filter(c => c.issueGet).length, 0);
    }],
    ['a removal failure on one label does not stop the next label being removed', { items: ['credential'], removeLabelFailsFor: 'pending:jira' }, r => {
      red(r, 'could not remove pending:jira'); assert.deepStrictEqual(r.removed, ['pending:jira', 'pending:email']);
    }],
    // Non-fatal setup path: not a recorded failure.
    ['label bootstrap failure does not stop delivery, still tries to create each label, and logs both errors', { items: ['credential'], labelBootstrap: 'fail' }, r => {
      assert.strictEqual(r.labelCreates, 3);
      for (const n of ['maintenance', 'pending:jira', 'pending:email']) {
        assert(r.logs.includes(`ERR getLabel(${n}) failed: getLabel 500`), r.logs.join('\n'));
        assert(r.logs.includes(`ERR createLabel(${n}) failed: createLabel 403`), r.logs.join('\n'));
      }
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
    }],
    ['missing labels (maintenance and both pending) are created, then delivery proceeds', { items: ['credential'], labelBootstrap: 'missing' }, r => {
      green(r); assert.strictEqual(r.labelCreates, 3);
      const LABEL_FIELDS = { owner: 'o', repo: 'r' };
      assert.deepStrictEqual(r.calls.filter(c => c.createLabel).map(c => c.createLabel), [
        { ...LABEL_FIELDS, name: 'maintenance', color: '0e8a16', description: 'Maintenance and operational tasks' },
        { ...LABEL_FIELDS, name: 'pending:jira', color: 'fbca04', description: 'Reminder: Jira ticket not yet delivered; the daily run retries it' },
        { ...LABEL_FIELDS, name: 'pending:email', color: 'fbca04', description: 'Reminder: email not yet delivered; the daily run retries it' },
      ]);
      assert(!r.logs.some(l => l.startsWith('ERR getLabel')), 'a 404 is the expected answer and is not logged'); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
    }],
  ];
  for (const v of ['TRUE', 'True', 'true']) {
    cases.push([`opt-out value '${v}' waives the unconfigured check`, { items: ['credential'], env: { SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: v } }, green]);
  }
  for (const v of ['false', '0', '1', 'yes', ' true', '']) {
    cases.push([`opt-out value '${v}' does not waive it`, { items: ['credential'], env: { SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: v } }, r => red(r, /x email: not configured/)]);
  }
  let bad = 0;
  for (const [name, opts, check] of cases) {
    try { const r = await run(wf, opts); check(r); console.log(`PASS  ${name}`); }
    catch (e) { bad++; console.log(`FAIL  ${name}: ${e.message}`); }
  }
  console.log(`${cases.length - bad}/${cases.length} passed`);
  if (cases.length === 0) bad = 1;  // never pass vacuously
  process.exit(bad ? 1 : 0);
}
main();
