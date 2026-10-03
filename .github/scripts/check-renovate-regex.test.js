// Tests for check-renovate-regex.js. Run: node --test .github/scripts/check-renovate-regex.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SCRIPT = path.join(__dirname, "check-renovate-regex.js");
const RECIPE = 'vars:\n  pg-tag: REL_17_11\n  pg-commit: 083ac033419f690758508e08c1736089384bbee8\npackage:\n  version: "17.11"\n';
const MANAGER = {
  description: "PostgreSQL source pin: test",
  customType: "regex",
  managerFilePatterns: ["/^melange/libpq-17\\.yaml$/"],
  matchStrings: ["pg-tag: (?<currentValue>REL_17_\\d+)\\n  pg-commit: (?<currentDigest>[0-9a-f]{40})\\npackage:\\n  version: \"[0-9.]+\""],
};

// Lay out renovate.json and melange/ in a temp dir and run the checker there.
function run({ managers = [MANAGER], files = { "melange/libpq-17.yaml": RECIPE }, args = ["melange/"] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "renovate-regex-"));
  fs.writeFileSync(path.join(dir, "renovate.json"), JSON.stringify({ customManagers: managers }));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.join(dir, path.dirname(name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, encoding: "utf8" });
  fs.rmSync(dir, { recursive: true, force: true });
  return { code: r.status, out: r.stdout + r.stderr };
}

test("one match per manager passes", () => {
  const r = run();
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /1 match\(es\)/);
});

test("a line inserted into the block fails", () => {
  const r = run({ files: { "melange/libpq-17.yaml": RECIPE.replace("package:\n", "package:\n  # x\n") } });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /::error file=melange\/libpq-17\.yaml::Renovate matchString matches 0 times/);
});

test("two matches fail", () => {
  const r = run({ files: { "melange/libpq-17.yaml": RECIPE + RECIPE } });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /matches 2 times/);
});

test("the annotation carries the whole matchString", () => {
  const r = run({ files: { "melange/libpq-17.yaml": "nothing\n" } });
  const line = r.out.split("\n").find((l) => l.startsWith("::error"));
  // renovate.json matchStrings hold regex escapes (backslash-n), not newlines; the pattern's tail
  // ("version") must reach the ::error line so the annotation is actionable.
  assert.ok(line && line.includes("version"), r.out);
});

test("a manager naming the prefix that targets no file fails (renamed recipe)", () => {
  const r = run({
    managers: [MANAGER, { ...MANAGER, description: "other", managerFilePatterns: ["/^melange/other\\.yaml$/"] }],
  });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /other: file pattern .* matches no file under melange\//);
});

test("legacy fileMatch is honoured", () => {
  const { managerFilePatterns, ...rest } = MANAGER;
  const r = run({ managers: [{ ...rest, fileMatch: ["^melange/libpq-17\\.yaml$"] }] });
  assert.strictEqual(r.code, 0, r.out);
});

test("a recipe no manager targets fails", () => {
  const r = run({ files: { "melange/libpq-17.yaml": RECIPE, "melange/new.yaml": "x: 1\n" } });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /::error file=melange\/new\.yaml::recipe is not targeted/);
});

test("no manager targets the prefix fails", () => {
  const r = run({ managers: [] });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /no Renovate regex customManager targets any file/);
});

test("a managerFilePatterns entry that is not /regex/ fails", () => {
  const r = run({ managers: [{ ...MANAGER, managerFilePatterns: ["melange/**"] }] });
  assert.notStrictEqual(r.code, 0, r.out);
});

test("missing argument exits 2", () => {
  const r = run({ args: [] });
  assert.strictEqual(r.code, 2, r.out);
});

test("nothing covered fails even when no recipe is present", () => {
  const r = run({ managers: [], files: { "melange/build.sh": "x\n" } });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /no Renovate regex customManager targets any file under melange\//);
  assert.doesNotMatch(r.out, /recipe is not targeted/);
});

test("non-regex customManagers are ignored", () => {
  const r = run({ managers: [MANAGER, { customType: "jsonata", managerFilePatterns: ["/^melange/libpq-17\\.yaml$/"] }] });
  assert.strictEqual(r.code, 0, r.out);
});

test("a recipe in a subdirectory must be covered too", () => {
  const r = run({ files: { "melange/libpq-17.yaml": RECIPE, "melange/sub/other.yml": "x: 1\n" } });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /::error file=melange\/sub\/other\.yml::recipe is not targeted/);
});

test("a manager with no matchStrings fails", () => {
  const r = run({ managers: [{ ...MANAGER, matchStrings: [] }] });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /no matchStrings/);
});

test("a match without a currentValue capture fails", () => {
  const r = run({ managers: [{ ...MANAGER, matchStrings: [MANAGER.matchStrings[0].replace("?<currentValue>", "?<value>")] }] });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /no currentValue capture/);
});

test("% in an annotation is encoded", () => {
  const r = run({ managers: [{ ...MANAGER, matchStrings: ["(?<currentValue>100%)"] }] });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /\(\?<currentValue>100%25\)/);
});
