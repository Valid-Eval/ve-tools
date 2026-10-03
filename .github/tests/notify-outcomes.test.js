// Offline harness for the "Create notifications" github-script step in
// .github/workflows/credential-rotation-reminder.yml. It extracts the script from the
// workflow file and runs it with mocked github/context/core/fetch: nothing touches
// GitHub, Jira, or SendGrid, and all credentials below are dummy values.
//
//   node .github/tests/notify-outcomes.test.js                 # run the outcome scenarios
//   node .github/tests/notify-outcomes.test.js --calls [file]  # dump every outgoing call
//       (for a byte-for-byte payload comparison between two versions of the workflow)
//   WORKFLOW_FILE=<path> node ...                               # run against another version
'use strict';
const fs = require('fs');
const assert = require('assert');

const ITEMS = {
  credential: { kind: 'credential', name: 'CRED_A', description: 'Cred desc', date: '2026-10-10', days_left: 8,
    notes: 'a note', jira_priority: 'Highest', steps: '1. Rotate\n2. Update', email_to: 'to@example.test',
    email_from: 'from@example.test', jira_project: 'VEP' },
  expired: { kind: 'credential', name: 'CRED_OLD', description: 'Old cred', date: '2026-09-25', days_left: -7,
    steps: '1. Rotate', email_to: 'to@example.test', email_from: 'from@example.test', jira_project: 'VEP' },
  review: { kind: 'compliance_review', name: 'REVIEW_A', description: 'Review desc', date: '2026-10-20', days_left: 18,
    notes: 'review note', steps: '1. Look\n2. Record', compliance_ref: 'https://example.test/record',
    jira_ref: 'INF-382', email_to: 'to@example.test', email_from: 'from@example.test', jira_project: 'INF' },
  test: { kind: 'credential', name: 'TEST_CREDENTIAL', description: 'Test', date: '2026-10-02', days_left: 0,
    is_test: true, steps: '1. none', email_to: 'to@example.test', email_from: 'from@example.test', jira_project: 'VEP' },
};

function extractScript(path) {
  const lines = fs.readFileSync(path, 'utf8').split('\n');
  const start = lines.findIndex(l => /^ {10}script: \|$/.test(l));
  assert(start >= 0, 'github-script step not found');
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() !== '' && !/^ {12}/.test(lines[i])) break;
    out.push(lines[i].slice(12));
  }
  return out.join('\n');
}

// opts: items, env, jira/sendgrid ({status} or {throws}), issueFails
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
    return { ok: status < 300, status, json: async () => ({ key: 'FAKE-1' }), text: async () => `body-${status}` };
  };
  console.log = (...a) => logs.push(a.join(' '));
  console.error = (...a) => logs.push('ERR ' + a.join(' '));
  const github = { rest: {
    issues: {
      getLabel: async () => ({}), createLabel: async () => ({}),
      create: async p => { calls.push({ issueCreate: p }); if (opts.issueFails) throw new Error('GitHub 500'); return { data: { number: 1 } }; },
    },
    search: { issuesAndPullRequests: async p => { calls.push({ search: p }); return { data: { items: [] } }; } },
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
  return { calls, logs, failed };
}

async function main() {
  const wf = process.env.WORKFLOW_FILE || '.github/workflows/credential-rotation-reminder.yml';
  if (process.argv[2] === '--calls') {
    const r = await run(process.argv[3] || wf, { items: ['credential', 'expired', 'review', 'test'] });
    process.stdout.write(JSON.stringify(r.calls, null, 1) + '\n');
    return;
  }
  const all = ['credential', 'review'];
  const cases = [
    ['success is green', { items: all }, r => assert.deepStrictEqual(r.failed, [])],
    ['zero in-window items is green, no calls', { items: [] }, r => { assert.deepStrictEqual(r.failed, []); assert.strictEqual(r.calls.length, 0); }],
    ['Jira HTTP 500 fails and names item x channel', { items: all, jira: { status: 500 } }, r => {
      assert.strictEqual(r.failed.length, 1);
      assert(r.failed[0].includes('credential CRED_A x jira') && r.failed[0].includes('compliance_review REVIEW_A x jira'));
      assert(!r.failed[0].includes('email'));
      assert.strictEqual(r.calls.filter(c => c.fetch && c.fetch.includes('sendgrid')).length, 2); // email still attempted
    }],
    ['Jira network error fails', { items: ['credential'], jira: { throws: 'ECONNREFUSED' } }, r => assert(/CRED_A x jira: ECONNREFUSED/.test(r.failed[0]))],
    ['SendGrid HTTP 500 fails and names item x channel', { items: all, sendgrid: { status: 500 } }, r => {
      assert(r.failed[0].includes('credential CRED_A x email') && r.failed[0].includes('compliance_review REVIEW_A x email'));
      assert(!r.failed[0].includes('jira'));
    }],
    ['GitHub issue failure fails, Jira and email still attempted', { items: ['credential'], issueFails: true }, r => {
      assert(r.failed[0].includes('CRED_A x github-issue'));
      assert.strictEqual(r.calls.filter(c => c.fetch).length, 2);
    }],
    ['all channels failing for several items are all listed', { items: all, issueFails: true, jira: { status: 500 }, sendgrid: { throws: 'boom' } }, r => {
      assert.strictEqual(r.failed.length, 1);
      assert.strictEqual(r.failed[0].split('\n').length, 1 + 6); // header + 2 items x 3 channels
    }],
    ['Jira not configured fails by default', { items: ['credential'], env: { JIRA_API_TOKEN: '' } }, r => assert(/CRED_A x jira: not configured/.test(r.failed[0]))],
    ['SendGrid not configured fails by default', { items: ['credential'], env: { SG_API_KEY: '' } }, r => assert(/CRED_A x email: not configured/.test(r.failed[0]))],
    ['unconfigured passes with ALLOW_UNCONFIGURED_CHANNELS=true', { items: all, env: { JIRA_API_TOKEN: '', SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' } }, r => assert.deepStrictEqual(r.failed, [])],
    ['opt-out does not hide real failures', { items: ['credential'], env: { SG_API_KEY: '', ALLOW_UNCONFIGURED_CHANNELS: 'true' }, jira: { status: 500 } }, r => {
      assert(r.failed[0].includes('x jira') && !r.failed[0].includes('x email'));
    }],
  ];
  let bad = 0;
  for (const [name, opts, check] of cases) {
    try { const r = await run(wf, opts); check(r); console.log(`PASS  ${name}`); }
    catch (e) { bad++; console.log(`FAIL  ${name}: ${e.message}`); }
  }
  process.exit(bad ? 1 : 0);
}
main();
