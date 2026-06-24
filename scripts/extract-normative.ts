/**
 * Track the spec's RFC 2119 normative statements across spec revisions.
 *
 * Usage:
 *   node scripts/extract-normative.ts            # diff spec vs the committed ledger
 *   node scripts/extract-normative.ts --list      # print every normative statement
 *   node scripts/extract-normative.ts --update    # rewrite the ledger to match the spec
 *
 * The ledger (spec/normative-ledger.json) is a snapshot of every normative statement at
 * the pinned spec ref. After `sync-spec-fixtures.ts` pulls a new spec revision, the diff
 * mode prints exactly which MUST/SHALL/REQUIRED statements were ADDED or REMOVED — the
 * precise list to triage in spec/conformance.md before updating the code. Keyed by text
 * (not line number) so reflowed prose still matches. Exits 1 when there is undated drift.
 *
 * Run scripts/sync-spec-fixtures.ts first; it caches spec/spec.md.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC_MD = join(ROOT, "spec", "spec.md");
const LEDGER = join(ROOT, "spec", "normative-ledger.json");

const KEYWORD = /\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b/;
const HEADER_TOKENS = /PROOF-(REQUIRED|PRESENTATION|RESPONSE)/g;

/** Whitespace-insensitive key so reflowed prose still matches across revisions. */
function keyOf(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function normativeStatements(md: string): string[] {
  const out: string[] = [];
  let inFence = false;
  for (const raw of md.split("\n")) {
    const text = raw.trim();
    if (text.startsWith("```")) {
      inFence = !inFence;
      continue;
    }
    if (inFence || !text) continue;
    // Strip the header field names so "PROOF-REQUIRED" stops matching "REQUIRED".
    if (KEYWORD.test(text.replace(HEADER_TOKENS, ""))) out.push(keyOf(text));
  }
  return [...new Set(out)].sort();
}

function main(): void {
  const current = normativeStatements(readFileSync(SPEC_MD, "utf8"));

  if (process.argv.includes("--list")) {
    for (const s of current) console.log(s);
    console.log(`\n${current.length} normative statement(s).`);
    return;
  }

  if (process.argv.includes("--update")) {
    writeFileSync(LEDGER, JSON.stringify(current, null, 2) + "\n", "utf8");
    console.log(`Ledger updated: ${current.length} normative statement(s).`);
    return;
  }

  if (!existsSync(LEDGER)) {
    console.error("No ledger. Run: node scripts/extract-normative.ts --update");
    process.exitCode = 1;
    return;
  }

  const ledger: string[] = JSON.parse(readFileSync(LEDGER, "utf8"));
  const prev = new Set(ledger);
  const now = new Set(current);
  const added = current.filter((s) => !prev.has(s));
  const removed = ledger.filter((s) => !now.has(s));

  console.log(
    `Spec has ${current.length} normative statement(s); ledger has ${ledger.length}.`,
  );
  if (added.length === 0 && removed.length === 0) {
    console.log("No drift. Every normative statement is accounted for.");
    return;
  }
  if (added.length > 0) {
    console.log(
      `\nADDED (${added.length}) — triage each in spec/conformance.md:`,
    );
    for (const s of added) console.log(`  + ${s}`);
  }
  if (removed.length > 0) {
    console.log(`\nREMOVED (${removed.length}) — drop stale handling/tests:`);
    for (const s of removed) console.log(`  - ${s}`);
  }
  console.log(
    "\nAfter triaging, run: node scripts/extract-normative.ts --update",
  );
  process.exitCode = 1;
}

main();
