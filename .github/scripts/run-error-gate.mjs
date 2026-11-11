#!/usr/bin/env node
// The .NET run-error gate. A RunError or Timeout mutant was decided by no assertion (the test host crashed or was killed by the watchdog, every
// failing test hit OutOfMemoryException under the heap cap, or the run passed its limit), yet it would count as caught, so each must be listed in
// mutation-run-errors.json with a proof that the mutant itself loops or allocates without bound.
// A listed mutant that hangs can also be decided KILLED by a test that fails on its own assertion before the limit (test order is not fixed).
// The rule, the same as the Go, Rust and PHP gates: an entry covers `multiplicity` mutants (default 1); the run must show them as errored or
// timed out (n) plus plainly KILLED (c, after the isolate's re-classification: a crash, watchdog kill or OOM is never Killed); n + c must equal the
// multiplicity and n alone must not exceed it. A survivor, a mutant absent from the run, or too many errored occurrences fails. Every other
// check stays exact: unlisted errored mutants, blank or short reasons, stale source lines, duplicate entries, missing shard files.
import fs from 'node:fs';
import path from 'node:path';

const arg = (n) => process.argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const [reports, ledger, src, want] = [arg('reports'), arg('ledger'), arg('src'), Number(arg('shards'))];
const key = (m) => [m.file, m.line, m.occurrence || 1, m.mutant].join(' | ');

const lists = new Map(), shardReports = new Map(), killedFiles = new Map();
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { walk(p); continue; }
    const m = /^(run-errors|shard|killed)-(\d+)\.json$/.exec(e.name);
    if (!m) continue;
    const v = JSON.parse(fs.readFileSync(p, 'utf8'));
    (m[1] === 'shard' ? shardReports : m[1] === 'killed' ? killedFiles : lists).set(Number(m[2]), v);
  }
};
walk(reports);

// a zero-occurrence entry means nothing unless every shard really ran: a missing shard file fails the whole gate
let incomplete = false;
for (let n = 1; n <= want; n++) {
  for (const [what, map] of [['run-error list', lists], ['report', shardReports], ['killed list', killedFiles]])
    if (!map.has(n)) { console.error(`::error::shard ${n}: no ${what} (a missing file is a failure)`); incomplete = true; }
}
if (lists.size !== want || shardReports.size !== want || killedFiles.size !== want) { console.error(`::error::expected ${want} shards, have ${lists.size} lists, ${shardReports.size} reports, ${killedFiles.size} killed lists`); incomplete = true; }
for (const [n, r] of shardReports) {
  const c = r.counts ?? {};
  if (!['Killed', 'Survived', 'Timeout', 'NoCoverage', 'RunError'].some((k) => c[k] > 0)) { console.error(`::error::shard ${n}: its report counts no mutant at all`); incomplete = true; }
}
if (incomplete) process.exit(1);

const got = [...lists.values()].flat();
const have = new Map(), ev = new Map();
for (const m of got) {
  have.set(key(m), (have.get(key(m)) || 0) + 1);
  if (!ev.has(key(m))) ev.set(key(m), (m.evidence || '').slice(-300).replace(/\s+/g, ' '));
}
const killed = new Map();
for (const k of [...killedFiles.values()].flat()) killed.set(key(k), (killed.get(key(k)) || 0) + (k.count || 1));
const survived = new Set([...shardReports.values()].flatMap((r) => r.survivors ?? []).map(key));
const led = JSON.parse(fs.readFileSync(ledger, 'utf8'));
const fileLines = new Map();
const countOf = (file, line) => {
  const f = path.join(src, file);
  if (!fileLines.has(f)) fileLines.set(f, fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split(/\r?\n/).map((l) => l.trim()) : []);
  return fileLines.get(f).filter((l) => l === line.trim()).length;
};

let bad = 0;
const fail = (s) => { console.error(`::error::${s}`); bad++; };
const used = new Set(); let viaKills = 0;
for (const e of led) {
  const k = key(e);
  if (used.has(k)) fail(`run-error ledger entry listed twice: ${k}`);
  used.add(k);
  if (typeof e.reason !== 'string' || e.reason.trim().length < 40) fail(`run-error ledger entry without a reason of at least 40 characters: ${k}`);
  if (countOf(e.file, e.line) < (e.occurrence || 1)) fail(`STALE run-error ledger entry, the source line changed or is gone: ${k}`);
  if (survived.has(k)) fail(`a listed mutant SURVIVED: ${k}`);
  const n = have.get(k) || 0, c = killed.get(k) || 0, m = e.multiplicity || 1;
  if (n > m) fail(`run-error ledger entry covers ${m}, the run has ${n} errored or timed-out: ${k}`);
  else if (n + c !== m) fail(`STALE run-error ledger entry: it covers ${m}, the run has ${n} errored or timed-out and ${c} killed (the rest survived, are not covered, or are gone): ${k}`);
  else if (c > 0) { viaKills++; console.log(`::notice::${c} of ${m} killed this run, entry covers the rest: ${k}`); }
}
for (const [k, n] of have) if (!used.has(k)) fail(`UNPROVEN run error (x${n}), no test decided it: ${k} :: ${ev.get(k)}`);
console.log(`${got.length} errored or timed-out mutant(s) over ${want} shards, ${led.length} ledger entries, ${viaKills} partly or fully killed, ${bad} problem(s)`);
process.exit(bad ? 1 : 0);
