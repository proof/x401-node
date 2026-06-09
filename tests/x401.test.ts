import assert from "node:assert/strict";
import test from "node:test";

import {
  agent,
  verifier,
  createEncryptor,
  HEADER,
  TOKEN_EXCHANGE_GRANT_TYPE,
  VP_ARTIFACT_SUBJECT_TOKEN_TYPE,
  X401ValidationError,
} from "../src/index.ts";

const VERIFIER_ID = "https://research.example.com";
const RESOURCE = "https://research.example.com/papers/medical-study-123";
const TOKEN_ENDPOINT = "https://research.example.com/oauth/token";

function newEncryptor() {
  return createEncryptor({
    key: "test-key-long-enough-for-hkdf-derivation",
    purpose: "x401-demo",
  });
}

async function buildRequirement(encryptor = newEncryptor()) {
  const challenge = await verifier.createChallenge({
    verifierId: VERIFIER_ID,
    resource: RESOURCE,
    method: "GET",
    encryptor,
    ttlSeconds: 600,
  });
  const payload = verifier.buildPayload({
    proof: {
      challenge,
      oauth: { token_endpoint: TOKEN_ENDPOINT },
      scope: "urn:proof:params:scope:verifiable-credentials:basic",
      request_id: "proof-template-age-over-21-v1",
      satisfied_requirements: ["urn:example:x401:satisfaction:age-over-21:v1"],
    },
  });
  return { payload, challenge, encryptor };
}

test("challenge value matches the spec schema pattern (dotless nonce segment)", async () => {
  const { challenge } = await buildRequirement();
  assert.match(challenge.value, /^x401:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$/);
});

test("buildPayload rejects both dcql_query and scope", () => {
  assert.throws(
    () =>
      verifier.buildPayload({
        proof: {
          challenge: {
            value: "x401:a:b",
            expires_at: new Date().toISOString(),
          },
          oauth: { token_endpoint: TOKEN_ENDPOINT },
          scope: "s",
          dcql_query: { credentials: [] },
        },
      }),
    X401ValidationError,
  );
});

test("agent decodes the PROOF-REQUIRED header into a validated payload", async () => {
  const { payload } = await buildRequirement();
  const headerValue = verifier.encodePayload(payload);
  const detected = agent.detectProofRequirement({
    headers: { [HEADER.PROOF_REQUIRED]: headerValue },
  });
  assert.ok(detected);
  assert.equal(detected.source, "header");
  assert.equal(detected.payload.proof.presentation_protocol, "openid4vp");
  assert.deepEqual(agent.getCredentialQuery(detected.payload), {
    scope: "urn:proof:params:scope:verifiable-credentials:basic",
  });
  assert.equal(agent.getNonce(detected.payload), payload.proof.challenge.value);
});

test("agent detects the embedded <data> requirement when the header is absent", async () => {
  const { payload } = await buildRequirement();
  const body = `<html><body><data value="application/json;x401=proof-required" hidden>${embed(
    payload,
  )}</data></body></html>`;
  const detected = agent.detectProofRequirement({ headers: {}, body });
  assert.ok(detected);
  assert.equal(detected.source, "embedded");
  assert.equal(
    detected.payload.proof.challenge.value,
    payload.proof.challenge.value,
  );
});

test("embedHtmlData round-trips through the agent detector", async () => {
  const { payload } = await buildRequirement();
  const detected = agent.detectProofRequirement({
    body: verifier.embedHtmlData(payload),
  });
  assert.ok(detected);
  assert.equal(
    detected.payload.proof.request_id,
    "proof-template-age-over-21-v1",
  );
});

test("a comma-list proof header value is rejected as invalid", () => {
  assert.throws(() => agent.decodePayload("AAAA,BBBB"), X401ValidationError);
});

test("full direct-retry round trip: payload -> artifact -> verify challenge", async () => {
  const { payload, encryptor } = await buildRequirement();
  const headerValue = verifier.encodePayload(payload);

  const detected = agent.detectProofRequirement({
    headers: { [HEADER.PROOF_REQUIRED]: headerValue },
  });
  assert.ok(detected);
  const vpToken = "eyJ...wallet-returned-sd-jwt-vc";
  const artifact = agent.buildVPArtifact({
    payload: detected.payload,
    agentId: "did:web:agent.example",
    vpToken,
  });
  const presentationHeader = agent.encodeVPArtifact(artifact);

  const decoded = verifier.decodeVPArtifact(presentationHeader);
  assert.equal(decoded.agent_id, "did:web:agent.example");
  assert.equal(decoded.challenge, payload.proof.challenge.value);
  assert.equal(decoded.request_id, "proof-template-age-over-21-v1");
  assert.equal(decoded.vp_token, vpToken);

  const result = await verifier.verifyChallenge({
    value: decoded.challenge,
    encryptor,
    expectedVerifierId: VERIFIER_ID,
    expectedResource: RESOURCE,
    expectedMethod: "GET",
  });
  assert.ok(result.ok);
  if (result.ok) {
    assert.equal(result.verifierId, VERIFIER_ID);
    assert.equal(result.resource, RESOURCE);
    assert.equal(result.method, "GET");
  }
});

test("verifyChallenge rejects a tampered nonce", async () => {
  const { challenge, encryptor } = await buildRequirement();
  const tampered = `${challenge.value.slice(0, -2)}xx`;
  const result = await verifier.verifyChallenge({ value: tampered, encryptor });
  assert.equal(result.ok, false);
});

test("verifyChallenge rejects a swapped (unauthenticated) verifier-id segment", async () => {
  const { challenge, encryptor } = await buildRequirement();
  const [, , nonce] = challenge.value.split(":");
  const forgedVid = Buffer.from("https://evil.example.com").toString(
    "base64url",
  );
  const forged = `x401:${forgedVid}:${nonce}`;
  const result = await verifier.verifyChallenge({ value: forged, encryptor });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "verifier identifier mismatch");
});

test("verifyChallenge rejects a challenge sealed by a different encryptor", async () => {
  const { challenge } = await buildRequirement();
  const other = createEncryptor({
    key: "a-different-secret-key-entirely",
    purpose: "x401-demo",
  });
  const result = await verifier.verifyChallenge({
    value: challenge.value,
    encryptor: other,
  });
  assert.equal(result.ok, false);
});

test("verifyChallenge rejects an expired challenge", async () => {
  const encryptor = newEncryptor();
  const challenge = await verifier.createChallenge({
    verifierId: VERIFIER_ID,
    resource: RESOURCE,
    method: "GET",
    encryptor,
    ttlSeconds: 60,
    now: new Date(Date.now() - 120_000),
  });
  const result = await verifier.verifyChallenge({
    value: challenge.value,
    encryptor,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "challenge expired");
});

test("verifyChallenge rejects a route mismatch", async () => {
  const { challenge, encryptor } = await buildRequirement();
  const result = await verifier.verifyChallenge({
    value: challenge.value,
    encryptor,
    expectedResource: "https://research.example.com/other",
  });
  assert.equal(result.ok, false);
});

test("token-exchange request build and verifier parse agree on fixed parameters", async () => {
  const { payload } = await buildRequirement();
  const detected = agent.detectProofRequirement({
    headers: { [HEADER.PROOF_REQUIRED]: verifier.encodePayload(payload) },
  });
  assert.ok(detected);
  const artifact = agent.buildVPArtifact({
    payload: detected.payload,
    agentId: "did:web:agent.example",
    vpToken: "opaque",
  });
  const form = agent.buildTokenExchangeForm(artifact, { resource: RESOURCE });
  assert.equal(form.get("grant_type"), TOKEN_EXCHANGE_GRANT_TYPE);
  assert.equal(form.get("subject_token_type"), VP_ARTIFACT_SUBJECT_TOKEN_TYPE);

  const parsed = verifier.parseTokenExchange(form);
  assert.equal(parsed.resource, RESOURCE);
  const reDecoded = verifier.decodeVPArtifact(parsed.subject_token);
  assert.equal(reDecoded.agent_id, "did:web:agent.example");
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
  const header = agent.encodeTokenObject(
    agent.buildTokenObject("verification-token-123"),
  );
  const decoded = verifier.decodeTokenObject(header);
  assert.equal(decoded.token_type, "Bearer");
  assert.equal(decoded.access_token, "verification-token-123");
});

test("error object round-trips through PROOF-RESPONSE", () => {
  const encoded = verifier.encodeErrorObject(
    verifier.buildErrorObject({
      error: "invalid_presentation",
      error_description: "nope",
    }),
  );
  const decoded = agent.decodeErrorObject(encoded);
  assert.equal(decoded.error, "invalid_presentation");
  assert.equal(decoded.scheme, "x401");
});

function embed(payload: unknown): string {
  return JSON.stringify(payload)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
