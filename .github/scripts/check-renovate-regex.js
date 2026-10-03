// Fail unless Renovate's regex customManagers still cover the files under <path-prefix>:
//  - every regex customManager whose file pattern names the prefix targets at least one file;
//  - it has matchStrings, and each matches each targeted file exactly once with a currentValue;
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

// managerFilePatterns entries must be "/regex/" strings. (Legacy fileMatch entries are bare regexes,
// compiled directly below.)
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
      } else if (!matches[0].groups || matches[0].groups.currentValue === undefined) {
        // Renovate drops a match that yields no currentValue, again without saying so.
        annotate(file, `Renovate matchString has no currentValue capture: ${ms}`);
        failed = true;
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
