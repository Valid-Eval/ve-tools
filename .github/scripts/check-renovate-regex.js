// Fail unless Renovate's regex customManagers still cover the files under <path-prefix>:
//  - every regex customManager whose file pattern names the prefix targets at least one file;
//  - it has matchStrings, and each matches each targeted file exactly once, yielding what Renovate
//    needs: a non-empty currentValue, a depName and a datasource (captured or templated), and no
//    capture group Renovate doesn't recognise (a renamed currentDigest is silently ignored);
//  - every recipe (*.yaml, *.yml) under the prefix is targeted by at least one regex customManager.
// Renovate itself reports nothing when a manager stops matching (a renamed file, a typo'd
// pattern, an edit that breaks the matchString): it just stops proposing updates.
//
// Usage (from the repo root): node .github/scripts/check-renovate-regex.js <path-prefix>
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

// This checker only understands "/regex/" managerFilePatterns entries (Renovate also accepts globs).
// Legacy fileMatch entries are bare regexes, compiled directly below.
function toRegex(pattern) {
  const m = pattern.match(/^\/(.*)\/([a-z]*)$/);
  if (!m) throw new Error(`unsupported managerFilePatterns entry (not /regex/): ${pattern}`);
  return new RegExp(m[1], m[2]);
}

// A workflow command ends at the first raw newline; encode newlines (and % and CR) so the whole
// message reaches the annotation.
function annotate(file, msg) {
  const where = file ? ` file=${file}` : "";
  console.log(`::error${where}::${msg.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A")}`);
}

// Capture groups Renovate's regex manager reads; any other name is dropped without a warning.
const KNOWN_GROUPS = new Set(["depName", "packageName", "currentValue", "currentDigest", "datasource",
  "versioning", "extractVersion", "registryUrl", "depType", "indentation"]);

const config = JSON.parse(fs.readFileSync("renovate.json", "utf8"));
const files = walk(prefix).map((f) => f.split(path.sep).join("/"));
const prefixText = prefix.replace(/\/$/, "");
const covered = new Set();
let failed = false;

for (const mgr of config.customManagers || []) {
  if (mgr.customType !== "regex") continue;
  const label = (mgr.description || mgr.depNameTemplate || "regex customManager").split(":")[0];
  const sources = [...(mgr.managerFilePatterns || [])];
  const patterns = sources.map(toRegex).concat((mgr.fileMatch || []).map((s) => new RegExp(s)));
  const sourceText = sources.concat(mgr.fileMatch || []).join(" ");
  const targets = files.filter((f) => patterns.some((re) => re.test(f)));
  if (!targets.length) {
    // Only managers that name this prefix are expected to target something under it.
    if (sourceText.includes(prefixText)) {
      annotate(null, `${label}: file pattern ${sourceText} matches no file under ${prefix}`);
      failed = true;
    }
    continue;
  }
  if (!(mgr.matchStrings || []).length) {
    annotate(null, `${label}: no matchStrings`);
    failed = true;
    continue;
  }
  for (const file of targets) {
    covered.add(file);
    const content = fs.readFileSync(file, "utf8");
    for (const ms of mgr.matchStrings) {
      const matches = [...content.matchAll(new RegExp(ms, "g"))];
      console.log(`${file}: ${matches.length} match(es) for ${label}`);
      if (matches.length !== 1) {
        annotate(file, `Renovate matchString matches ${matches.length} times, expected 1: ${ms}`);
        failed = true;
      } else {
        // Renovate drops or misreads an incomplete match without saying so.
        const g = matches[0].groups || {};
        const problems = Object.keys(g).filter((k) => !KNOWN_GROUPS.has(k)).map((k) => `unknown capture group ${k}`);
        if (!g.currentValue) problems.push("no currentValue capture");
        if (!g.depName && !g.packageName && !mgr.depNameTemplate && !mgr.packageNameTemplate) problems.push("no depName");
        if (!g.datasource && !mgr.datasourceTemplate) problems.push("no datasource");
        for (const p of problems) {
          annotate(file, `Renovate matchString ${p}: ${ms}`);
          failed = true;
        }
      }
    }
  }
}

for (const file of files.filter((f) => /\.ya?ml$/.test(f))) {
  if (!covered.has(file)) {
    annotate(file, "recipe is not targeted by any Renovate regex customManager");
    failed = true;
  }
}
if (!covered.size) {
  annotate(null, `no Renovate regex customManager targets any file under ${prefix}`);
  failed = true;
}
process.exit(failed ? 1 : 0);
