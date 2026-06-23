import assert from "node:assert/strict";
import test from "node:test";

import {
  agent,
  verifier,
  ACCESS_TOKEN_TYPE,
  HEADER,
  TOKEN_EXCHANGE_GRANT_TYPE,
  VP_ARTIFACT_SUBJECT_TOKEN_TYPE,
  X401ValidationError,
} from "../src/index.ts";
import type { DigitalCredentialRequest } from "../src/index.ts";

const TOKEN_ENDPOINT = "https://research.example.com/oauth/token";
const RESOURCE = "https://research.example.com/papers/medical-study-123";

const SIGNED_REQUEST: DigitalCredentialRequest = {
  requests: [
    {
      protocol: "openid4vp-v1-signed",
      data: { request: "eyJhbGciOiJFUzI1NiJ9.signed-jar" },
    },
  ],
};

function buildRequirement() {
  return verifier.buildPayload({
    presentationRequirements: SIGNED_REQUEST,
    oauth: { token_endpoint: TOKEN_ENDPOINT },
    trustEstablishment:
      "https://research.example.com/.well-known/x401/trust/v1",
    requestId: "proof-template-age-over-21-v1",
    satisfiedRequirements: ["urn:example:x401:satisfaction:age-over-21:v1"],
  });
}

test("buildPayload emits a flat 0.2.0 payload with presentation_requirements", () => {
  const payload = buildRequirement();
  assert.equal(payload.version, "0.2.0");
  assert.equal(
    payload.presentation_requirements.requests[0]?.protocol,
    "openid4vp-v1-signed",
  );
  assert.equal(payload.oauth.token_endpoint, TOKEN_ENDPOINT);
  // No 0.1.0 proof wrapper.
  assert.equal("proof" in payload, false);
});

test("buildPayload rejects an empty requests array", () => {
  assert.throws(
    () =>
      verifier.buildPayload({
        presentationRequirements: { requests: [] },
        oauth: { token_endpoint: TOKEN_ENDPOINT },
      }),
    X401ValidationError,
  );
});

test("buildPayload rejects an unknown DC API protocol", () => {
  assert.throws(
    () =>
      verifier.buildPayload({
        presentationRequirements: {
          requests: [{ protocol: "openid4vp-signed" as never, data: {} }],
        },
        oauth: { token_endpoint: TOKEN_ENDPOINT },
      }),
    X401ValidationError,
  );
});

test("agent decodes the PROOF-REQUIRED header and exposes the composed request", () => {
  const payload = buildRequirement();
  const detected = agent.detectProofRequirement({
    headers: { [HEADER.PROOF_REQUIRED]: verifier.encodePayload(payload) },
  });
  assert.ok(detected);
  assert.equal(detected.source, "header");
  assert.deepEqual(
    agent.getDigitalCredentialRequest(detected.payload),
    SIGNED_REQUEST,
  );
});

test("agent detects the embedded <data> requirement and it round-trips", () => {
  const payload = buildRequirement();
  const detected = agent.detectProofRequirement({
    body: verifier.embedHtmlData(payload),
  });
  assert.ok(detected);
  assert.equal(detected.source, "embedded");
  assert.equal(detected.payload.request_id, "proof-template-age-over-21-v1");
});

test("parseX401Payload rejects a leftover 0.1.0 proof wrapper", () => {
  assert.throws(
    () =>
      agent.decodePayload(
        Buffer.from(
          JSON.stringify({
            scheme: "x401",
            version: "0.1.0",
            proof: { presentation_protocol: "openid4vp" },
          }),
        ).toString("base64url"),
      ),
    X401ValidationError,
  );
});

test("a comma-list proof header value is rejected as invalid", () => {
  assert.throws(() => agent.decodePayload("AAAA,BBBB"), X401ValidationError);
});

test("inline VP Artifact round-trips through PROOF-PRESENTATION", () => {
  const payload = buildRequirement();
  const artifact = agent.buildVPArtifact({
    response: {
      protocol: "openid4vp-v1-signed",
      data: "<wallet-returned-presentation-result>",
    },
    requestId: payload.request_id,
  });
  const decoded = verifier.decodeVPArtifact(agent.encodeVPArtifact(artifact));
  assert.equal(decoded.response?.protocol, "openid4vp-v1-signed");
  assert.equal(decoded.presentation_uri, undefined);
  assert.equal(decoded.request_id, "proof-template-age-over-21-v1");
});

test("by-reference VP Artifact round-trips through PROOF-PRESENTATION", () => {
  const artifact = agent.buildVPArtifactReference({
    presentationUri:
      "https://research.example.com/.well-known/x401/presentations/abc",
    expiresAt: "2026-05-06T18:50:00Z",
    agentId: "did:web:agent.example",
  });
  const decoded = verifier.decodeVPArtifact(agent.encodeVPArtifact(artifact));
  assert.equal(
    decoded.presentation_uri,
    "https://research.example.com/.well-known/x401/presentations/abc",
  );
  assert.equal(decoded.response, undefined);
  assert.equal(decoded.agent_id, "did:web:agent.example");
});

test("VP Artifact with neither response nor presentation_uri is rejected", () => {
  assert.throws(
    () =>
      verifier.decodeVPArtifact(
        Buffer.from(JSON.stringify({})).toString("base64url"),
      ),
    X401ValidationError,
  );
});

test("VP Artifact with a non-https presentation_uri is rejected", () => {
  const insecure = Buffer.from(
    JSON.stringify({ presentation_uri: "http://example.com/p/1" }),
  ).toString("base64url");
  assert.throws(() => verifier.decodeVPArtifact(insecure), X401ValidationError);
});

test("VP Artifact with both response and presentation_uri is rejected", () => {
  const both = Buffer.from(
    JSON.stringify({
      response: { protocol: "openid4vp-v1-signed", data: "x" },
      presentation_uri: "https://example.com/p/1",
    }),
  ).toString("base64url");
  assert.throws(() => verifier.decodeVPArtifact(both), X401ValidationError);
});

test("token-exchange request build and verifier parse agree on fixed parameters", () => {
  const artifact = agent.buildVPArtifact({
    response: { protocol: "openid4vp-v1-signed", data: "opaque" },
  });
  const form = agent.buildTokenExchangeForm(artifact, { resource: RESOURCE });
  assert.equal(form.get("grant_type"), TOKEN_EXCHANGE_GRANT_TYPE);
  assert.equal(form.get("subject_token_type"), VP_ARTIFACT_SUBJECT_TOKEN_TYPE);

  const parsed = verifier.parseTokenExchange(form);
  assert.equal(parsed.resource, RESOURCE);
  const reDecoded = verifier.decodeVPArtifact(parsed.subject_token);
  assert.equal(reDecoded.response?.data, "opaque");
});

test("token-exchange response carrying ACCESS_TOKEN_TYPE parses", () => {
  assert.equal(
    ACCESS_TOKEN_TYPE,
    "urn:ietf:params:oauth:token-type:access_token",
  );
  const parsed = agent.parseTokenExchangeResponse({
    access_token: "verification-token",
    token_type: "Bearer",
    issued_token_type: ACCESS_TOKEN_TYPE,
  });
  assert.equal(parsed.issued_token_type, ACCESS_TOKEN_TYPE);
  assert.equal(parsed.token_type, "Bearer");
});

test("parseTokenExchange rejects a wrong grant_type", () => {
  assert.throws(
    () =>
      verifier.parseTokenExchange({
        grant_type: "authorization_code",
        subject_token: "x",
      }),
    X401ValidationError,
  );
});

test("token object round-trips through PROOF-PRESENTATION", () => {
  const decoded = verifier.decodeTokenObject(
    agent.encodeTokenObject(agent.buildTokenObject("verification-token-123")),
  );
  assert.equal(decoded.token_type, "Bearer");
  assert.equal(decoded.access_token, "verification-token-123");
});

test("token object without a version is rejected", () => {
  const noVersion = Buffer.from(
    JSON.stringify({ scheme: "x401", token_type: "Bearer", access_token: "x" }),
  ).toString("base64url");
  assert.throws(
    () => verifier.decodeTokenObject(noVersion),
    X401ValidationError,
  );
});

test("error object without a version is rejected", () => {
  const noVersion = Buffer.from(
    JSON.stringify({ scheme: "x401", error: "invalid_presentation" }),
  ).toString("base64url");
  assert.throws(() => agent.decodeErrorObject(noVersion), X401ValidationError);
});

test("embedHtmlData content is directly parseable JSON (quotes not entity-escaped)", () => {
  const payload = buildRequirement();
  const html = verifier.embedHtmlData(payload);
  const inner = html.replace(/^<data[^>]*>/, "").replace(/<\/data>$/, "");
  assert.equal(inner.includes("&quot;"), false);
  const parsed = JSON.parse(inner);
  assert.equal(parsed.$schema, "https://x401.id/spec/schemas/request.json");
  assert.equal(parsed.scheme, "x401");
  assert.deepEqual(
    parsed.presentation_requirements,
    payload.presentation_requirements,
  );
});

test("error object round-trips through PROOF-RESPONSE without a challenge field", () => {
  const decoded = agent.decodeErrorObject(
    verifier.encodeErrorObject(
      verifier.buildErrorObject({
        error: "invalid_presentation",
        error_description: "nope",
        request_id: "proof-template-age-over-21-v1",
      }),
    ),
  );
  assert.equal(decoded.error, "invalid_presentation");
  assert.equal(decoded.scheme, "x401");
  assert.equal("challenge" in decoded, false);
});
