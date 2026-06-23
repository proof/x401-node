# @proof.com/x401-node

Node.js SDK for the [x401 protocol](https://x401.proof.com/spec) (v0.2.0).

x401 gates an HTTP resource behind an identity proof requirement. The server (_verifier_) returns a
[`PROOF-REQUIRED`](https://x401.proof.com/spec/#proof-header-fields) header carrying a composed
[Digital Credentials API](https://www.w3.org/TR/digital-credentials/) request; the user _agent_
obtains a presentation for that request and retries with a
[`PROOF-PRESENTATION`](https://x401.proof.com/spec/#route-retry-headers) header. This package
implements the data types and processing rules for both the _verifier_ and the user _agent_.

It does **not** verify credentials — the presentation result is opaque, so pair it with a credential
library such as [`@proof.com/proof-vc-common`](https://www.npmjs.com/package/@proof.com/proof-vc-common).
It also does **not** compose or sign the OpenID4VP request, nor invoke the wallet; the verifier
authors the request (out of scope here) and this package carries it opaque in `presentation_requirements`.

## Table of Contents

- [Installation](#installation)
- [Verifier](#verifier)
  - [Protect a resource (`PROOF-REQUIRED`)](#protect-a-resource-proof-required)
  - [Verify a Proof (`PROOF-PRESENTATION`)](#verify-a-proof-proof-presentation)
- [Agent](#agent)
  - [Read a Proof requirement (`PROOF-REQUIRED`)](#read-a-proof-requirement-proof-required)
  - [Present a Proof (`PROOF-PRESENTATION`)](#present-a-proof-proof-presentation)
  - [Exchange a Proof for a token](#exchange-a-proof-for-a-token)
- [Contributing](#contributing)

## Installation

```
npm install @proof.com/x401-node
```

## Verifier

### Protect a resource (`PROOF-REQUIRED`)

The [x401 payload](https://x401.proof.com/spec/#x401-payload) carries the Verifier-composed
[Digital Credentials request](https://x401.proof.com/spec/#presentation-requirements) and the OAuth
token endpoint used for [token exchange](#exchange-a-proof-for-a-token). You compose and (for the
RECOMMENDED signed mode) sign the OpenID4VP request yourself; this package carries it opaque.

```ts
import { verifier } from "@proof.com/x401-node";

const payload = verifier.buildPayload({
  presentationRequirements: {
    requests: [
      {
        protocol: "openid4vp-v1-signed", // or "openid4vp-v1-unsigned"
        data: { request: signedOpenId4vpRequestJwt }, // composed + signed by you
      },
    ],
  },
  oauth: { token_endpoint: "https://research.example.com/oauth/token" },
  // optional hints:
  trustEstablishment:
    "https://research.example.com/.well-known/x401/trust/basic-v1",
  requestId: "proof-template-basic-v1",
  satisfiedRequirements: ["urn:proof:x401:satisfaction:basic:v1"],
});
```

Return it as a header:

```ts
response.setHeader("PROOF-REQUIRED", verifier.encodePayload(payload));
```

For clients that read the body but not the headers, mirror the requirement as an
[embedded `<data>` element](https://x401.proof.com/spec/#embedded-proof-requirements-in-html-content)
(the `$schema` marker is added automatically). The header remains authoritative and must still be set.

```ts
const html = `<article>…</article>${verifier.embedHtmlData(payload)}`;
```

> **Stateless nonce (optional).** x401 0.2.0 has no Verifier Challenge; freshness/replay live in the
> OpenID4VP `nonce` inside your request. To operate statelessly you can seal route context into that
> `nonce` with `createEncryptor` (an AES-256-GCM + HKDF authenticated-state primitive) and recover it
> on retry. The same secret must be present wherever you validate.

### Verify a Proof (`PROOF-PRESENTATION`)

Decode the artifact, then validate the presentation against the request you composed (binding,
`nonce` freshness, credential query) with your credential library and route policy. The artifact may
carry the result inline (`response`) or by reference (`presentation_uri`, which you dereference). On
failure, return an [x401 Error Object](https://x401.proof.com/spec/#x401-error-object) in
`PROOF-RESPONSE`. See the full
[verifier processing rules](https://x401.proof.com/spec/#verifier-processing-rules).

```ts
const artifact = verifier.decodeVPArtifact(
  request.headers["proof-presentation"],
);

const result = artifact.response // inline { protocol, data }
  ? artifact.response
  : await fetchPresentation(artifact.presentation_uri!); // by reference

// validate `result` with your credential library + route policy, then:
if (!ok) {
  response.setHeader(
    "PROOF-RESPONSE",
    verifier.encodeErrorObject(
      verifier.buildErrorObject({ error: "invalid_presentation" }),
    ),
  );
  return;
}
```

## Agent

See the full [agent processing rules](https://x401.proof.com/spec/#agent-processing-rules).

### Read a Proof requirement (`PROOF-REQUIRED`)

`detectProofRequirement` reads the header, falling back to the embedded `<data>` element.
`getDigitalCredentialRequest` returns the Verifier-composed request unmodified — pass it straight to
the Digital Credentials API (or relay it). The agent MUST NOT alter it.

```ts
import { agent } from "@proof.com/x401-node";

const res = await fetch(url);
const requirement = agent.detectProofRequirement({
  headers: res.headers,
  body: await res.text(),
});

if (requirement) {
  const dcRequest = agent.getDigitalCredentialRequest(requirement.payload);
  // const result = await navigator.credentials.get({ digital: dcRequest });
}
```

### Present a Proof (`PROOF-PRESENTATION`)

Wrap the `{ protocol, data }` presentation result in a
[VP Artifact](https://x401.proof.com/spec/#vp-artifact) and retry the same route. Use the
by-reference form for results too large for a header.

```ts
const artifact = agent.buildVPArtifact({
  response: result, // { protocol, data } from the DC API
  requestId: requirement.payload.request_id,
});

// or, by reference:
// const artifact = agent.buildVPArtifactReference({
//   presentationUri: "https://research.example.com/.well-known/x401/presentations/abc",
//   expiresAt: "2026-05-06T18:50:00Z",
// });

await fetch(url, {
  headers: { "PROOF-PRESENTATION": agent.encodeVPArtifact(artifact) },
});
```

### Exchange a Proof for a token

Exchange the artifact for a reusable Verification Token via
[OAuth token exchange](https://x401.proof.com/spec/#oauth-token-exchange), then present it as an
x401 Token Object.

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
await fetch(url, { headers: { "PROOF-PRESENTATION": tokenHeader } });
```

## Contributing

[Contribution guidelines for this project](CONTRIBUTING.md)
