import assert from "node:assert/strict";
import test from "node:test";

import {
  agent,
  verifier,
  ACCESS_TOKEN_TYPE,
  HEADER,
  RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  X401ValidationError,
} from "../src/index.ts";
import type { CredentialRequestOptions } from "../src/index.ts";

const TOKEN_ENDPOINT = "https://research.example.com/oauth/token";
const RESOURCE = "https://research.example.com/papers/medical-study-123";

const SIGNED_REQUEST: CredentialRequestOptions = {
  digital: {
    requests: [
      {
        protocol: "openid4vp-v1-signed",
        data: { request: "eyJhbGciOiJFUzI1NiJ9.signed-jar" },
      },
    ],
  },
};

function buildRequirement() {
  return verifier.buildPayload({
    credentialRequirements: SIGNED_REQUEST,
    oauth: { token_endpoint: TOKEN_ENDPOINT },
    requestId: "proof-template-age-over-21-v1",
    satisfiedRequirements: ["urn:example:x401:satisfaction:age-over-21:v1"],
  });
}

test("buildPayload emits a flat payload with credential_requirements", () => {
  const payload = buildRequirement();
  assert.equal(payload.version, "0.2.0");
  assert.equal(
    payload.credential_requirements.digital.requests[0]?.protocol,
    "openid4vp-v1-signed",
  );
  assert.equal(payload.oauth.token_endpoint, TOKEN_ENDPOINT);
  assert.equal("proof" in payload, false);
});

test("buildPayload rejects an empty requests array", () => {
  assert.throws(
    () =>
      verifier.buildPayload({
        credentialRequirements: { digital: { requests: [] } },
        oauth: { token_endpoint: TOKEN_ENDPOINT },
      }),
    X401ValidationError,
  );
});

test("buildPayload rejects an unknown DC API protocol", () => {
  assert.throws(
    () =>
      verifier.buildPayload({
        credentialRequirements: {
          digital: {
            requests: [{ protocol: "openid4vp-signed" as never, data: {} }],
          },
        },
        oauth: { token_endpoint: TOKEN_ENDPOINT },
      }),
    X401ValidationError,
  );
});

test("agent decodes the PROOF-REQUEST header and exposes the credential request", () => {
  const payload = buildRequirement();
  const detected = agent.detectProofRequirement({
    headers: { [HEADER.PROOF_REQUEST]: verifier.encodePayload(payload) },
  });
  assert.ok(detected);
  assert.equal(detected.source, "header");
  assert.deepEqual(
    agent.getCredentialRequestOptions(detected.payload),
    SIGNED_REQUEST,
  );
  assert.deepEqual(
    agent.getDigitalCredentialRequest(detected.payload),
    SIGNED_REQUEST.digital,
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

test("agent rejects an embedded <data> requirement without $schema", () => {
  const payload = buildRequirement();
  const html = verifier.embedHtmlData(payload);
  const inner = html.replace(/^<data[^>]*>/, "").replace(/<\/data>$/, "");
  const embedded = JSON.parse(inner) as Record<string, unknown>;
  delete embedded.$schema;

  assert.throws(
    () =>
      agent.detectProofRequirement({
        body: `<data value="application/json;x401=proof-required" hidden>${JSON.stringify(embedded)}</data>`,
      }),
    /embedded x401 payload "\$schema"/,
  );
});

test("addReturnUri attaches an https return_uri that survives a round-trip", () => {
  const payload = buildRequirement();
  assert.equal("return_uri" in payload, false);
  const relayed = agent.addReturnUri(
    payload,
    "https://mcp.example/x401/return/9f1c2a",
  );
  assert.equal(relayed.return_uri, "https://mcp.example/x401/return/9f1c2a");
  const decoded = agent.decodePayload(verifier.encodePayload(relayed));
  assert.equal(decoded.return_uri, "https://mcp.example/x401/return/9f1c2a");
});

test("addReturnUri rejects a non-https return_uri", () => {
  assert.throws(
    () => agent.addReturnUri(buildRequirement(), "http://mcp.example/return"),
    X401ValidationError,
  );
});

test("addReturnUri allows an http return_uri when allowInsecureUri is set", () => {
  const relayed = agent.addReturnUri(
    buildRequirement(),
    "http://localhost:3000/x401/return",
    { allowInsecureUri: true },
  );
  assert.equal(relayed.return_uri, "http://localhost:3000/x401/return");
  const decoded = agent.decodePayload(verifier.encodePayload(relayed), {
    allowInsecureUri: true,
  });
  assert.equal(decoded.return_uri, "http://localhost:3000/x401/return");
});

test("addReturnUri still rejects a non-string return_uri under allowInsecureUri", () => {
  assert.throws(
    () =>
      agent.addReturnUri(buildRequirement(), 42 as unknown as string, {
        allowInsecureUri: true,
      }),
    X401ValidationError,
  );
});

test("parseX401Payload rejects a non-https return_uri", () => {
  const bad = Buffer.from(
    JSON.stringify({
      scheme: "x401",
      version: "0.2.0",
      credential_requirements: {
        digital: {
          requests: [{ protocol: "openid4vp-v1-signed", data: {} }],
        },
      },
      oauth: { token_endpoint: "https://bank.example.com/oauth/token" },
      return_uri: "http://mcp.example/return",
    }),
  ).toString("base64url");
  assert.throws(() => agent.decodePayload(bad), X401ValidationError);
});

test("parseX401Payload rejects a leftover wrapper", () => {
  assert.throws(
    () =>
      agent.decodePayload(
        Buffer.from(
          JSON.stringify({
            scheme: "x401",
            version: "0.1.0",
            proof: { request_protocol: "openid4vp" },
          }),
        ).toString("base64url"),
      ),
    X401ValidationError,
  );
});

test("a comma-list proof header value is rejected as invalid", () => {
  assert.throws(() => agent.decodePayload("AAAA,BBBB"), X401ValidationError);
});

test("inline Result Artifact round-trips through PROOF-RESPONSE", () => {
  const payload = buildRequirement();
  const artifact = agent.buildResultArtifact({
    credentialResult: {
      protocol: "openid4vp-v1-signed",
      data: "<credential-manager-returned-result>",
    },
    requestId: payload.request_id,
  });
  const decoded = verifier.decodeResultArtifact(
    agent.encodeResultArtifact(artifact),
  );
  assert.equal(decoded.credential_result?.protocol, "openid4vp-v1-signed");
  assert.equal(decoded.credential_result_uri, undefined);
  assert.equal(decoded.request_id, "proof-template-age-over-21-v1");
});

test("by-reference Result Artifact round-trips through PROOF-RESPONSE", () => {
  const artifact = agent.buildResultArtifactReference({
    credentialResultUri:
      "https://research.example.com/.well-known/x401/results/abc",
    expiresAt: "2026-05-06T18:50:00Z",
    agentId: "did:web:agent.example",
  });
  const decoded = verifier.decodeResultArtifact(
    agent.encodeResultArtifact(artifact),
  );
  assert.equal(
    decoded.credential_result_uri,
    "https://research.example.com/.well-known/x401/results/abc",
  );
  assert.equal(decoded.credential_result, undefined);
  assert.equal(decoded.agent_id, "did:web:agent.example");
});

test("Result Artifact with neither result nor uri is rejected", () => {
  assert.throws(
    () =>
      verifier.decodeResultArtifact(
        Buffer.from(JSON.stringify({})).toString("base64url"),
      ),
    X401ValidationError,
  );
});

test("Result Artifact with a non-https result uri is rejected", () => {
  const insecure = Buffer.from(
    JSON.stringify({ credential_result_uri: "http://example.com/r/1" }),
  ).toString("base64url");
  assert.throws(
    () => verifier.decodeResultArtifact(insecure),
    X401ValidationError,
  );
});

test("Result Artifact with both result and uri is rejected", () => {
  const both = Buffer.from(
    JSON.stringify({
      credential_result: { protocol: "openid4vp-v1-signed", data: "x" },
      credential_result_uri: "https://example.com/r/1",
    }),
  ).toString("base64url");
  assert.throws(() => verifier.decodeResultArtifact(both), X401ValidationError);
});

test("token-exchange request build and verifier parse agree on fixed parameters", () => {
  const artifact = agent.buildResultArtifact({
    credentialResult: { protocol: "openid4vp-v1-signed", data: "opaque" },
  });
  const form = agent.buildTokenExchangeForm(artifact, { resource: RESOURCE });
  assert.equal(form.get("grant_type"), TOKEN_EXCHANGE_GRANT_TYPE);
  assert.equal(
    form.get("subject_token_type"),
    RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
  );

  const parsed = verifier.parseTokenExchange(form);
  assert.equal(parsed.resource, RESOURCE);
  const reDecoded = verifier.decodeResultArtifact(parsed.subject_token);
  assert.equal(reDecoded.credential_result?.data, "opaque");
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

test("token object round-trips through PROOF-RESPONSE", () => {
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

test("embedHtmlData content is directly parseable JSON", () => {
  const payload = buildRequirement();
  const html = verifier.embedHtmlData(payload);
  const inner = html.replace(/^<data[^>]*>/, "").replace(/<\/data>$/, "");
  assert.equal(inner.includes("&quot;"), false);
  const parsed = JSON.parse(inner);
  assert.equal(parsed.$schema, "https://x401.id/spec/schemas/request.json");
  assert.equal(parsed.scheme, "x401");
  assert.deepEqual(
    parsed.credential_requirements,
    payload.credential_requirements,
  );
});

test("error object round-trips through PROOF-RESULT without a challenge field", () => {
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
