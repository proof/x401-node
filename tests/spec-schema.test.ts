import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { verifier } from "../src/index.ts";

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "spec",
  "fixtures",
);

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
}

function payloadFixtureNames(): string[] {
  return readdirSync(FIXTURES)
    .filter((n) => /^payload-\d+\.json$/.test(n))
    .sort();
}

/** A "complete" payload example carries at least one request entry; the spec also
 * shows an envelope skeleton (empty objects) that is illustrative, not valid. */
function isComplete(p: unknown): boolean {
  const digital = (
    p as {
      credential_requirements?: { digital?: { requests?: unknown[] } };
    }
  ).credential_requirements?.digital;
  return Array.isArray(digital?.requests) && digital.requests.length > 0;
}

const ajv = addFormats(new Ajv2020({ allErrors: true }));
const validate = ajv.compile(fixture("request.schema.json"));

test("every complete spec payload example validates against Appendix C schema", () => {
  const complete = payloadFixtureNames().filter((n) => isComplete(fixture(n)));
  assert.ok(
    complete.length >= 1,
    "expected at least one complete payload fixture",
  );
  for (const name of complete) {
    const ok = validate(fixture(name));
    assert.ok(ok, `${name} failed schema: ${ajv.errorsText(validate.errors)}`);
  }
});

test("the spec envelope skeleton is not a complete payload (sanity check on the schema)", () => {
  const skeletons = payloadFixtureNames().filter(
    (n) => !isComplete(fixture(n)),
  );
  for (const name of skeletons) {
    assert.equal(
      validate(fixture(name)),
      false,
      `${name} unexpectedly validated`,
    );
  }
});

test("payloads produced by verifier.buildPayload validate against the schema", () => {
  const signed = verifier.buildPayload({
    credentialRequirements: {
      digital: {
        requests: [
          { protocol: "openid4vp-v1-signed", data: { request: "eyJ..." } },
        ],
      },
    },
    oauth: { token_endpoint: "https://bank.example.com/oauth/token" },
    requestId: "proof-template-v1",
    satisfiedRequirements: ["urn:example:x401:satisfaction:v1"],
  });
  assert.ok(validate(signed), `signed: ${ajv.errorsText(validate.errors)}`);

  const unsigned = verifier.buildPayload({
    credentialRequirements: {
      digital: {
        requests: [
          { protocol: "openid4vp-v1-unsigned", data: { nonce: "abc" } },
        ],
      },
    },
    oauth: { token_endpoint: "https://bank.example.com/oauth/token" },
  });
  assert.ok(validate(unsigned), `unsigned: ${ajv.errorsText(validate.errors)}`);
});

test("schema rejects structurally invalid payloads", () => {
  const base = {
    scheme: "x401",
    version: "0.2.0",
    credential_requirements: {
      digital: {
        requests: [{ protocol: "openid4vp-v1-signed", data: {} }],
      },
    },
    oauth: { token_endpoint: "https://bank.example.com/oauth/token" },
  };
  // missing oauth
  assert.equal(
    validate({
      scheme: "x401",
      version: "0.2.0",
      credential_requirements: {
        digital: {
          requests: [{ protocol: "openid4vp-v1-signed", data: {} }],
        },
      },
    }),
    false,
  );
  // bad protocol enum
  assert.equal(
    validate({
      ...base,
      credential_requirements: {
        digital: {
          requests: [{ protocol: "openid4vp-signed", data: {} }],
        },
      },
    }),
    false,
  );
  // empty requests
  assert.equal(
    validate({
      ...base,
      credential_requirements: { digital: { requests: [] } },
    }),
    false,
  );
  // leftover 0.1.0 proof wrapper (additionalProperties: false)
  assert.equal(validate({ ...base, proof: {} }), false);
});
