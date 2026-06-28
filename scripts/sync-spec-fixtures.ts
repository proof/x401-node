/**
 * Sync spec-authored ground truth into `spec/`.
 *
 * Fetches `spec.md` from the proof/x401 repo at a pinned git ref, extracts the
 * Appendix C JSON Schema and every JSON example block, classifies them by content,
 * and writes them to `spec/fixtures/`. Also refreshes `spec/SPEC_SOURCE.json`.
 *
 * Usage:
 *   node scripts/sync-spec-fixtures.ts [<git-ref>]
 *
 * The ref defaults to the value recorded in spec/SPEC_SOURCE.json. Requires the
 * GitHub CLI (`gh`) to be installed and authenticated.
 *
 * This script is the reproducible step in the spec-upgrade runbook (spec/UPGRADING.md):
 * it pins the fixtures to an exact spec commit so the conformance tests check the code
 * against spec text, not a paraphrase of it.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = "proof/x401";
const SPEC_PATH = "spec.md";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC_DIR = join(ROOT, "spec");
const FIXTURES_DIR = join(SPEC_DIR, "fixtures");
const SOURCE_FILE = join(SPEC_DIR, "SPEC_SOURCE.json");

interface SpecSource {
  repo: string;
  ref: string;
  branch: string;
  version: string;
  spec_url: string;
  schema_url: string;
  fetched_at: string;
}

function readSource(): SpecSource {
  return JSON.parse(readFileSync(SOURCE_FILE, "utf8")) as SpecSource;
}

function fetchSpec(ref: string): string {
  const b64 = execFileSync(
    "gh",
    [
      "api",
      `repos/${REPO}/contents/${SPEC_PATH}?ref=${ref}`,
      "--jq",
      ".content",
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  return Buffer.from(b64, "base64").toString("utf8");
}

/** Extract the bodies of every fenced ```json block, in document order. */
function jsonBlocks(md: string): string[] {
  const blocks: string[] = [];
  const re = /```json\n([\s\S]*?)```/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(md)) !== null) {
    if (m[1] !== undefined) blocks.push(m[1].trim());
  }
  return blocks;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function write(name: string, value: unknown): void {
  writeFileSync(
    join(FIXTURES_DIR, name),
    JSON.stringify(value, null, 2) + "\n",
    "utf8",
  );
  console.log(`  wrote spec/fixtures/${name}`);
}

function main(): void {
  const source = readSource();
  const ref = process.argv[2] ?? source.ref;
  console.log(`Fetching ${REPO}:${SPEC_PATH} at ${ref} ...`);
  const md = fetchSpec(ref);

  // Cache the raw spec so extract-normative.ts and conformance review run offline.
  mkdirSync(SPEC_DIR, { recursive: true });
  writeFileSync(join(SPEC_DIR, "spec.md"), md, "utf8");
  console.log("  wrote spec/spec.md");

  rmSync(FIXTURES_DIR, { recursive: true, force: true });
  mkdirSync(FIXTURES_DIR, { recursive: true });

  const parsed = jsonBlocks(md).flatMap((raw) => {
    try {
      return [JSON.parse(raw) as unknown];
    } catch {
      return []; // skip non-parseable blocks (e.g. truncated "..." JARs)
    }
  });

  let payloads = 0;
  let resultArtifacts = 0;
  let oid4vpRequests = 0;
  let schemaFound = false;

  for (const obj of parsed) {
    if (!isObject(obj)) continue;
    if (
      typeof obj["$schema"] === "string" &&
      obj["$schema"].includes("json-schema.org") &&
      obj["title"] !== undefined
    ) {
      write("request.schema.json", obj);
      schemaFound = true;
    } else if (obj["scheme"] === "x401") {
      if (obj["credential_requirements"] !== undefined) {
        write(`payload-${++payloads}.json`, obj);
      } else if (obj["error"] !== undefined) {
        write("error-object.json", obj);
      } else if (obj["access_token"] !== undefined) {
        write("token-object.json", obj);
      }
    } else if (
      obj["credential_result"] !== undefined ||
      obj["credential_result_uri"] !== undefined
    ) {
      write(`result-artifact-${++resultArtifacts}.json`, obj);
    } else if (obj["response_type"] === "vp_token") {
      // Informative: the decoded OpenID4VP request the Verifier signs into the JAR.
      write(`openid4vp-request-${++oid4vpRequests}.json`, obj);
    }
  }

  if (!schemaFound) {
    throw new Error("Appendix C JSON Schema not found in spec.md.");
  }
  if (payloads === 0) {
    throw new Error("No x401 payload examples found in spec.md.");
  }

  const updated: SpecSource = {
    ...source,
    ref,
    fetched_at: new Date().toISOString(),
  };
  writeFileSync(SOURCE_FILE, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log(
    `Done. ${payloads} payload(s), ${resultArtifacts} result artifact(s), ${oid4vpRequests} OID4VP request(s).`,
  );
}

main();
