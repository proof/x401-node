# @proof.com/x401-node

Node.js SDK for the [x401 protocol](https://x401.proof.com/spec/latest/) (v0.2.0).

x401 gates an HTTP resource behind an identity proof requirement. The server (Verifier) returns a
[`PROOF-REQUEST`](https://x401.proof.com/spec/latest/#proof-header-fields) header carrying a
composed [Digital Credentials API](https://www.w3.org/TR/digital-credentials/) request. The user
Agent obtains a credential result for that request and retries with a
[`PROOF-RESPONSE`](https://x401.proof.com/spec/latest/#route-retry-headers) header. The Verifier
reports x401-specific results and errors in
[`PROOF-RESULT`](https://x401.proof.com/spec/latest/#proof-header-fields).

This package implements data types and wire-object processing rules for both the Verifier and the
Agent. It does not verify credentials. Pair it with a credential verification library such as
[`@proof.com/proof-vc-common`](https://www.npmjs.com/package/@proof.com/proof-vc-common). It also
does not compose or sign the OpenID4VP request, nor invoke a wallet. The Verifier authors the
request, and this package carries it opaque in `credential_requirements`.

## Table of Contents

- [Installation](#installation)
- [Verifier](#verifier)
  - [Protect a resource (`PROOF-REQUEST`)](#protect-a-resource-proof-request)
  - [Verify a result (`PROOF-RESPONSE`)](#verify-a-result-proof-response)
- [Agent](#agent)
  - [Read a proof requirement (`PROOF-REQUEST`)](#read-a-proof-requirement-proof-request)
  - [Present a result (`PROOF-RESPONSE`)](#present-a-result-proof-response)
  - [Exchange a result for a token](#exchange-a-result-for-a-token)
- [Contributing](#contributing)

## Installation

```sh
npm install @proof.com/x401-node
```

## Verifier

### Protect a resource (`PROOF-REQUEST`)

The [x401 payload](https://x401.proof.com/spec/latest/#x401-payload) carries the
Verifier-composed credential request and the OAuth token endpoint used for
[token exchange](#exchange-a-result-for-a-token). You compose and, for the recommended signed mode,
sign the OpenID4VP request yourself. This package carries it opaque.

```ts
import { verifier } from "@proof.com/x401-node";

const payload = verifier.buildPayload({
  credentialRequirements: {
    digital: {
      requests: [
        {
          protocol: "openid4vp-v1-signed",
          data: { request: signedOpenId4vpRequestJwt },
        },
      ],
    },
  },
  oauth: { token_endpoint: "https://research.example.com/oauth/token" },
  requestId: "proof-template-basic-v1",
  satisfiedRequirements: ["urn:proof:x401:satisfaction:basic:v1"],
});
```

`protocol` is `openid4vp-v1-signed` or `openid4vp-v1-unsigned`, and its `data` carries the request
you composed and signed. `requestId` and `satisfiedRequirements` are optional hints.

Return it as a header:

```ts
response.setHeader("PROOF-REQUEST", verifier.encodePayload(payload));
```

For clients that read the body but not the headers, mirror the requirement as an
[embedded `<data>` element](https://x401.proof.com/spec/latest/#embedded-proof-requirements-in-html-content).
The `$schema` marker is added automatically. The header remains authoritative and must still be set.

```ts
const html = `<article>...</article>${verifier.embedHtmlData(payload)}`;
```

### Verify a result (`PROOF-RESPONSE`)

Decode the Result Artifact, then validate the credential result against the request you composed
with your credential library and route policy. The artifact may carry the result inline
(`credential_result`) or by reference (`credential_result_uri`, which you dereference). On failure,
return an [x401 Error Object](https://x401.proof.com/spec/latest/#x401-error-object) in
`PROOF-RESULT`. See the full
[Verifier processing rules](https://x401.proof.com/spec/latest/#verifier-processing-rules).

```ts
const artifact = verifier.decodeResultArtifact(
  request.headers["proof-response"],
);

const result = artifact.credential_result
  ? artifact.credential_result
  : await fetchCredentialResult(artifact.credential_result_uri!);

if (!validateCredentialResult(result)) {
  response.setHeader(
    "PROOF-RESULT",
    verifier.encodeErrorObject(
      verifier.buildErrorObject({ error: "invalid_presentation" }),
    ),
  );
  return;
}
```

## Agent

See the full [Agent processing rules](https://x401.proof.com/spec/latest/#agent-processing-rules).

### Read a proof requirement (`PROOF-REQUEST`)

`detectProofRequirement` reads the header, falling back to the embedded `<data>` element.
`getCredentialRequestOptions` returns the Verifier-composed credential request unmodified. Pass it
straight to the Credential Manager, or relay it. The Agent must not alter it.

```ts
import { agent } from "@proof.com/x401-node";

const res = await fetch(url);
const requirement = agent.detectProofRequirement({
  headers: res.headers,
  body: await res.text(),
});

if (requirement) {
  const credentialRequest = agent.getCredentialRequestOptions(
    requirement.payload,
  );
  const result = await navigator.credentials.get(credentialRequest);
}
```

If you are an intermediary relaying the request to a remote handler, add an `https` `return_uri` to
the forwarded payload with `agent.addReturnUri(payload, returnUri)`. Only a relaying intermediary
sets this. The Verifier never sets it.

### Present a result (`PROOF-RESPONSE`)

Wrap the `{ protocol, data }` credential result in a
[Result Artifact](https://x401.proof.com/spec/latest/#result-artifact) and retry the same route. Use
the by-reference form for results too large for a header.

```ts
const artifact = agent.buildResultArtifact({
  credentialResult: result,
  requestId: requirement.payload.request_id,
});

await fetch(url, {
  headers: { "PROOF-RESPONSE": agent.encodeResultArtifact(artifact) },
});
```

Or, by reference:

```ts
const artifact = agent.buildResultArtifactReference({
  credentialResultUri:
    "https://research.example.com/.well-known/x401/results/abc",
  expiresAt: "2026-05-06T18:50:00Z",
});
```

### Exchange a result for a token

Exchange the artifact for a reusable Verification Token via
[OAuth token exchange](https://x401.proof.com/spec/latest/#oauth-token-exchange), then present it as
an x401 Token Object.

```ts
const form = agent.buildTokenExchangeForm(artifact, { resource: url });
const res = await fetch(tokenEndpoint, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: form,
});
const { access_token } = agent.parseTokenExchangeResponse(await res.json());

const tokenHeader = agent.encodeTokenObject(
  agent.buildTokenObject(access_token),
);
await fetch(url, { headers: { "PROOF-RESPONSE": tokenHeader } });
```

## Contributing

[Contribution guidelines for this project](CONTRIBUTING.md)
