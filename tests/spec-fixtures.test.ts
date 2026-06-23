import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { agent, verifier } from "../src/index.ts";
import { parseX401Payload } from "../src/validate.ts";

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "spec",
  "fixtures",
);

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
}

function names(re: RegExp): string[] {
  return readdirSync(FIXTURES)
    .filter((n) => re.test(n))
    .sort();
}

function hasRequests(p: unknown): boolean {
  const pr = (p as { presentation_requirements?: { requests?: unknown[] } })
    .presentation_requirements;
  return Array.isArray(pr?.requests) && pr.requests.length > 0;
}

test("complete spec payload fixtures parse and survive an encode round-trip", () => {
  const complete = names(/^payload-\d+\.json$/).filter((n) =>
    hasRequests(fixture(n)),
  );
  assert.ok(complete.length >= 1);
  for (const name of complete) {
    const payload = parseX401Payload(fixture(name));
    const decoded = agent.decodePayload(verifier.encodePayload(payload));
    assert.deepEqual(decoded, payload, name);
  }
});

test("the spec envelope skeleton is rejected by the parser", () => {
  const skeletons = names(/^payload-\d+\.json$/).filter(
    (n) => !hasRequests(fixture(n)),
  );
  for (const name of skeletons) {
    assert.throws(() => parseX401Payload(fixture(name)), name);
  }
});

test("spec VP Artifact fixtures (inline and by-reference) decode and round-trip", () => {
  const arts = names(/^vp-artifact-\d+\.json$/);
  assert.ok(
    arts.length >= 2,
    "expected inline and by-reference VP artifact fixtures",
  );
  let sawInline = false;
  let sawReference = false;
  for (const name of arts) {
    const raw = fixture(name) as Record<string, unknown>;
    if (raw["response"] !== undefined) sawInline = true;
    if (raw["presentation_uri"] !== undefined) sawReference = true;
    const decoded = verifier.decodeVPArtifact(
      agent.encodeVPArtifact(raw as never),
    );
    assert.deepEqual(decoded, raw, name);
  }
  assert.ok(sawInline, "no inline VP artifact fixture found");
  assert.ok(sawReference, "no by-reference VP artifact fixture found");
});

test("spec error object fixture decodes through PROOF-RESPONSE", () => {
  const raw = fixture("error-object.json") as Record<string, unknown>;
  const decoded = agent.decodeErrorObject(
    verifier.encodeErrorObject(raw as never),
  );
  assert.equal(decoded.error, raw["error"]);
  assert.equal(decoded.version, "0.2.0");
  assert.equal("challenge" in decoded, false);
});

test("spec token object fixture decodes through PROOF-PRESENTATION", () => {
  const raw = fixture("token-object.json") as Record<string, unknown>;
  const decoded = verifier.decodeTokenObject(
    agent.encodeTokenObject(raw as never),
  );
  assert.equal(decoded.token_type, "Bearer");
  assert.equal(decoded.access_token, raw["access_token"]);
});
