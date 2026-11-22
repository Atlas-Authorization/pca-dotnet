#!/usr/bin/env node
// Negative control for run-error-gate.mjs: a clean fixture passes (an entry with no errored occurrence passes only because the mutant was KILLED),
// and every condition the gate must refuse is refused, with the exact problem count the gate prints (the FAIL-count cross-check).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const gate = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run-error-gate.mjs');
const seen = { file: 'AtlasPca/A.cs', line: 'while (a) i++;', occurrence: 1, mutant: 'Statement mutation: ;' };
const quiet = { file: 'AtlasPca/A.cs', line: 'while (b) j++;', occurrence: 1, mutant: 'Statement mutation: ;' };
const SRC = 'class A {\nwhile (a) i++;\n  while (b) j++;\n}\n';
const why = 'The loop body is removed so the counter never advances and the loop never ends for any input.';
const L = (e, extra = {}) => ({ ...e, reason: why, ...extra });
const kill = (e, count = 1) => ({ ...e, count });

function run(over = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'run-error-gate-'));
  const c = { src: SRC, list1: [seen], list2: [], killed1: [kill(quiet)], killed2: [], survivors: [], ledger: [L(seen), L(quiet)], ...over };
  fs.mkdirSync(path.join(d, 'AtlasPca'));
  if (c.src !== null) fs.writeFileSync(path.join(d, 'AtlasPca/A.cs'), c.src);
  for (const n of [1, 2]) {
    const a = path.join(d, `reports/shard-${n}`);
    fs.mkdirSync(a, { recursive: true });
    for (const [name, v] of [['run-errors', c[`list${n}`]], ['killed', c[`killed${n}`]]])
      if (v !== null && !(c.noFile === `${name}-${n}`)) fs.writeFileSync(path.join(a, `${name}-${n}.json`), JSON.stringify(v));
    if (!(c.noFile === `shard-${n}`)) fs.writeFileSync(path.join(a, `shard-${n}.json`), JSON.stringify({ survivors: n === 1 ? c.survivors : [], counts: c.counts ?? { Killed: 1 } }));
  }
  fs.writeFileSync(path.join(d, 'ledger.json'), JSON.stringify(c.ledger));
  const r = spawnSync('node', [gate, `--reports=${d}/reports`, `--ledger=${d}/ledger.json`, `--src=${d}`, '--shards=2'], { encoding: 'utf8' });
  fs.rmSync(d, { recursive: true, force: true });
  return r;
}

// [overrides, text the gate's stderr must hold, the exact number of problems it must count]
const refuses = {
  'changed source line': [{ src: SRC.replace('while (b) j++;', 'while (c) j++;') }, 'source line changed or is gone', 1],
  'source file gone': [{ src: null }, 'source line changed or is gone', 2],
  'occurrence past the last match': [{ ledger: [L(seen), L(quiet, { occurrence: 2 })] }, 'source line changed or is gone', 2],
  'unlisted errored mutant': [{ list2: [{ ...quiet, mutant: 'Statement mutation: other' }] }, 'UNPROVEN', 1],
  'no reason': [{ ledger: [{ ...seen }, L(quiet)] }, 'without a reason', 1],
  'short reason': [{ ledger: [L(seen, { reason: 'loops' }), L(quiet)] }, 'without a reason', 1],
  'errored count above the multiplicity': [{ list2: [seen] }, 'covers 1, the run has 2 errored', 1],
  'killed in addition to the full multiplicity': [{ killed1: [kill(quiet), kill(seen)] }, 'covers 1, the run has 1 errored or timed-out and 1 killed', 1],
  'multiplicity 2 with one errored and nothing killed': [{ ledger: [L(seen, { multiplicity: 2 }), L(quiet)] }, 'covers 2, the run has 1 errored or timed-out and 0 killed', 1],
  'listed mutant survived': [{ survivors: [quiet], killed1: [] }, 'SURVIVED', 2],
  'zero occurrences, mutant absent from the run': [{ killed1: [] }, 'covers 1, the run has 0 errored or timed-out and 0 killed', 1],
  'missing run-error list': [{ noFile: 'run-errors-2' }, 'no run-error list', null],
  'missing killed list': [{ noFile: 'killed-2' }, 'no killed list', null],
  'missing shard report': [{ noFile: 'shard-2' }, 'no report', null],
  'shard that counts no mutant': [{ counts: { Killed: 0, Survived: 0 } }, 'counts no mutant', null],
  'entry listed twice': [{ ledger: [L(seen), L(seen), L(quiet)] }, 'listed twice', 1],
};

let bad = 0;
const ok = run();
if (ok.status !== 0 || !ok.stdout.includes('1 killed this run') && !ok.stdout.includes('1 of 1 killed this run') || !ok.stdout.includes('0 problem(s)')) {
  console.error(`clean fixture must pass (the zero-occurrence entry only because its mutant was killed): status ${ok.status}\n${ok.stdout}${ok.stderr}`);
  bad++;
}
// a partly killed entry passes: multiplicity 2 = one errored + one killed
const partial = run({ ledger: [L(seen, { multiplicity: 2 }), L(quiet)], killed1: [kill(seen), kill(quiet)] });
if (partial.status !== 0) { console.error(`multiplicity 2 = 1 errored + 1 killed must pass: status ${partial.status}\n${partial.stdout}${partial.stderr}`); bad++; }
for (const [name, [over, text, problems]] of Object.entries(refuses)) {
  const r = run(over);
  const counted = problems === null || r.stdout.includes(`${problems} problem(s)`);
  if (r.status !== 1 || !r.stderr.includes(text) || !counted) { console.error(`NOT refused as expected: ${name}: status ${r.status}, wanted "${text}" and ${problems} problem(s)\n${r.stdout}${r.stderr}`); bad++; }
  else console.log(`refused: ${name}`);
}
console.log(bad ? `${bad} control(s) failed` : `all ${Object.keys(refuses).length + 2} controls hold`);
process.exit(bad ? 1 : 0);
