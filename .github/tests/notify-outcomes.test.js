// Offline harness for the "Create notifications" github-script step in
// .github/workflows/credential-rotation-reminder.yml. It extracts the script from the
// workflow file and runs it with mocked github/context/core/fetch: nothing touches
// GitHub, Jira, or SendGrid, and all credentials below are dummy values.
// CI runs it on pull requests (the test-notify job in the same workflow).
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
    notes: 'a note', jira_priority: 'Highest', steps: '1. Rotate\n2. Update', ...ROUTING, jira_project: 'VEP' },
  expired: { kind: 'credential', name: 'CRED_OLD', description: 'Old cred', date: '2026-09-25', days_left: -7,
    steps: '1. Rotate', ...ROUTING, jira_project: 'VEP' },
  review: { kind: 'compliance_review', name: 'REVIEW_A', description: 'Review desc', date: '2026-10-20', days_left: 18,
    notes: 'review note', steps: '1. Look\n2. Record', compliance_ref: 'https://example.test/record',
    jira_ref: 'INF-382', ...ROUTING, jira_project: 'INF' },
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
//       existing ({title: [labels]}), searchThrows, labelBootstrap ('fail'), addLabelsFails
async function run(workflowPath, opts) {
  const calls = [], logs = [], failed = [];
  const env = { JIRA_USER_EMAIL: 'dummy@example.test', JIRA_API_TOKEN: 'dummy-jira-token',
    SG_API_KEY: 'dummy-sg-key', ...opts.env };
  const saved = { ...process.env };
  for (const k of ['JIRA_USER_EMAIL', 'JIRA_API_TOKEN', 'SG_API_KEY', 'ALLOW_UNCONFIGURED_CHANNELS']) delete process.env[k];
  Object.assign(process.env, env, { CHECK_RESULT: JSON.stringify({ due: opts.items.map(k => ITEMS[k]) }) });
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
  const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
  const github = { rest: {
    issues: {
      getLabel: async () => { if (opts.labelBootstrap === 'fail') throw httpErr(500, 'getLabel 500'); return {}; },
      createLabel: async () => { if (opts.labelBootstrap === 'fail') throw httpErr(403, 'createLabel 403'); return {}; },
      create: async p => { calls.push({ issueCreate: p }); if (opts.issueFails) throw new Error('GitHub 500'); return { data: { number: n++ } }; },
      addLabels: async p => { calls.push({ addLabels: p }); if (opts.addLabelsFails) throw new Error('labels 403'); return {}; },
      removeLabel: async p => { calls.push({ removeLabel: p }); return {}; },
    },
    search: { issuesAndPullRequests: async p => {
      calls.push({ search: p });
      if (opts.searchThrows) throw httpErr(403, 'secondary rate limit');
      const items = Object.entries(existing).filter(([t]) => p.q.includes(`"${t}"`))
        .map(([title, labels]) => ({ number: 7, title, labels: ['maintenance', ...labels].map(name => ({ name })) }));
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
    added: calls.filter(c => c.addLabels).flatMap(c => c.addLabels.labels),
    removed: calls.filter(c => c.removeLabel).map(c => c.removeLabel.name) };
}

const green = r => assert.deepStrictEqual(r.failed, []);
const red = (r, ...parts) => {
  assert.strictEqual(r.failed.length, 1, `expected exactly one setFailed, got ${r.failed.length}`);
  for (const p of parts) assert(p instanceof RegExp ? p.test(r.failed[0]) : r.failed[0].includes(p), `missing ${p} in: ${r.failed[0]}`);
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
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [2, 2, 2]); assert.deepStrictEqual(r.added, []);
    }],
    ['zero in-window items is green, no calls', { items: [] }, r => { green(r); assert.strictEqual(r.calls.length, 0); }],
    ['Jira HTTP 500 fails, names item x channel, email still sent', { items: all, jira: { status: 500 } }, r => {
      red(r, 'credential CRED_A x jira', 'compliance_review REVIEW_A x jira'); assert(!r.failed[0].includes('x email'));
      assert.strictEqual(r.email, 2);
    }],
    ['Jira network error fails', { items: ['credential'], jira: { throws: 'ECONNREFUSED' } }, r => red(r, /CRED_A x jira: ECONNREFUSED/)],
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
      red(r, 'CRED_A x github-issue'); assert.deepStrictEqual([r.jira, r.email], [1, 1]); assert.deepStrictEqual(r.added, []);
    }],
    ['all channels failing for several items are all listed in one setFailed', { items: all, issueFails: true, jira: { status: 500 }, sendgrid: { throws: 'boom' } }, r => {
      red(r); assert.strictEqual(r.failed[0].split('\n').length, 1 + 6);
    }],
    ['Jira token missing fails by default', { items: ['credential'], env: { JIRA_API_TOKEN: '' } }, r => red(r, /CRED_A x jira: not configured/)],
    ['Jira user email missing fails by default', { items: ['credential'], env: { JIRA_USER_EMAIL: '' } }, r => { red(r, /CRED_A x jira: not configured/); assert.strictEqual(r.jira, 0); }],
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
    ['retry that fails again stays red and keeps the label', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:jira'] }, jira: { status: 401 } }, r => {
      red(r, 'CRED_A x jira'); assert.deepStrictEqual(r.removed, []); assert.deepStrictEqual(r.added, []);
    }],
    ['retry with the channel still unconfigured stays red (fix-then-rerun must not go falsely green)', { items: ['credential'], existing: { [TITLES.CRED_A]: ['pending:email'] }, env: { SG_API_KEY: '' } }, r => {
      red(r, /CRED_A x email: not configured/); assert.deepStrictEqual(r.removed, []);
    }],
    ['failure to write retry state is itself a failure', { items: ['credential'], jira: { status: 500 }, addLabelsFails: true }, r => {
      red(r, 'CRED_A x jira', 'CRED_A x retry-state');
    }],
    // Whole-item paths are loud, recorded in the single summary, and do not stop other items.
    ['dedup search failure skips that item, is recorded, and the next item is still delivered', { items: ['credential', 'review'], searchThrows: true }, r => {
      red(r, 'CRED_A x dedup-search', 'REVIEW_A x dedup-search'); assert.deepStrictEqual([r.jira, r.email], [0, 0]);
    }],
    ['unknown kind is recorded and the next item is still delivered', { items: ['badKind', 'credential'] }, r => {
      red(r, 'mystery ODD x kind'); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
    }],
    ['label bootstrap failure does not stop delivery', { items: ['credential'], labelBootstrap: 'fail' }, r => {
      green(r); assert.deepStrictEqual([r.issues, r.jira, r.email], [1, 1, 1]);
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
