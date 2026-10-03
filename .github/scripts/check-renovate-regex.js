// Fail if any Renovate regex customManager targeting files under <prefix> does not match each of
// its files exactly once. Renovate itself reports nothing when a matchString stops matching; it
// just stops proposing updates for that dependency.
//
// Usage: node .github/scripts/check-renovate-regex.js <path-prefix>
"use strict";
const fs = require("fs");
const path = require("path");

const prefix = process.argv[2];
if (!prefix) {
  console.error("usage: check-renovate-regex.js <path-prefix>");
  process.exit(2);
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
}

// managerFilePatterns entries are "/regex/" strings (or globs, which these managers don't use).
function toRegex(pattern) {
  const m = pattern.match(/^\/(.*)\/([a-z]*)$/);
  if (!m) throw new Error(`unsupported managerFilePatterns entry (not /regex/): ${pattern}`);
  return new RegExp(m[1], m[2]);
}

const config = JSON.parse(fs.readFileSync("renovate.json", "utf8"));
const files = walk(prefix);
let checked = 0;
let failed = false;

for (const mgr of config.customManagers || []) {
  if (mgr.customType !== "regex") continue;
  const patterns = (mgr.managerFilePatterns || []).map(toRegex);
  const targets = files.filter((f) => patterns.some((re) => re.test(f)));
  if (!targets.length) continue;
  for (const file of targets) {
    const content = fs.readFileSync(file, "utf8");
    for (const ms of mgr.matchStrings) {
      const n = [...content.matchAll(new RegExp(ms, "g"))].length;
      checked++;
      console.log(`${file}: ${n} match(es) for ${(mgr.description || mgr.depNameTemplate || "customManager").split(":")[0]}`);
      if (n !== 1) {
        console.log(`::error file=${file}::Renovate matchString matches ${n} times, expected 1: ${ms}`);
        failed = true;
      }
    }
  }
}

if (!checked) {
  console.log(`::error::no Renovate regex customManager targets any file under ${prefix}`);
  failed = true;
}
process.exit(failed ? 1 : 0);
