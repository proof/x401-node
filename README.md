# @proof.com/x401-node

Node.js SDK for the [x401 protocol](https://x401.proof.com/spec).

x401 gates an HTTP resource behind an identity proof requirement. The server (_verifier_) returns a
[`PROOF-REQUIRED`](https://x401.proof.com/spec/#proof-header-fields) header and the user _agent_ retries
with a [`PROOF-PRESENTATION`](https://x401.proof.com/spec/#route-retry-headers) header carrying a
Verifiable Credential Presentation. This package implements the data types and processing rules for both the _verifier_ and the user _agent_.

It does **not** verify credentials — the `vp_token` is opaque, so pair it with a credential library
such as [`@proof.com/proof-vc-common`](https://www.npmjs.com/package/@proof.com/proof-vc-common). It
also does **not** build the wallet-facing OpenID4VP request; that is the user agent's responsibility.

## Table of Contents

- [Installation](#installation)
- [Verifier](#verifier)
  - [Protect a resource (`PROOF-REQUIRED`)](#protect-a-resource-proof-required)
    - [Proof challenge](#proof-challenge)
    - [Proof requirement](#proof-requirement)
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

A protected route returns a [Proof requirement](#proof-requirement) built around a
[Proof challenge](#proof-challenge).

#### Proof challenge

The Proof challenge contains a nonce tied to the resource the agent wants to access. The agent
submits that nonce, inside a [VP Artifact](https://x401.proof.com/spec/#vp-artifact), to access the
protected resource. The challenge must follow the
[challenge format](https://x401.proof.com/spec/#verifier-challenge-format). Provide your own, or use
the built-in challenge encryptor to create one.

##### Built-in challenge encryptor

`createEncryptor` binds the route context into the nonce, so the verifier holds no per-challenge
state. The same secret must be present wherever challenges are verified.

```ts
import { createEncryptor, verifier } from "@proof.com/x401-node";

const encryptor = createEncryptor({ key: process.env.X401_KEY! });

const challenge = await verifier.createChallenge({
  verifierId: "https://research.example.com",
  resource: "https://research.example.com/papers/medical-study-123",
  method: "GET",
  encryptor,
  ttlSeconds: 600,
});
```

The nonce is an AES-256-GCM token (HKDF-derived key). [Verify a Proof](#verify-a-proof-proof-presentation)
rejects any value whose nonce was tampered with.

##### Supply your own challenge

You can construct a [`VerifierChallenge`](https://x401.proof.com/spec/#verifier-challenge-format) if you prefer storing
the challenge server side or prefer a different nonce generation algorithm.

```ts
const challenge = {
  value: `x401:${Buffer.from("https://research.example.com").toString("base64url")}:${myStoredNonce}`,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
};
```

#### Proof requirement

The [x401 payload](https://x401.proof.com/spec/#x401-payload) carries the challenge, the credential
query and the OAuth token endpoint used for [token exchange](#exchange-a-proof-for-a-token).

##### Create the payload

`buildPayload` requires exactly one credential query: `dcql_query` or `scope`. `oauth.token_endpoint`
is required.

```ts
const payload = verifier.buildPayload({
  proof: {
    challenge,
    oauth: { token_endpoint: "https://research.example.com/oauth/token" },
    scope: "urn:proof:params:scope:verifiable-credentials:basic",
  },
});
```

##### Payload in the header

Return the Proof requirement as a header:

```ts
response.setHeader("PROOF-REQUIRED", verifier.encodePayload(payload));
```

##### Payload in HTML

For clients that read the body but not the headers, mirror the requirement as an
[embedded `<data>` element](https://x401.proof.com/spec/#embedded-proof-requirements-in-html-content).
The header remains authoritative and must still be set.

```ts
const html = `<article>…</article>${verifier.embedHtmlData(payload)}`;
```

### Verify a Proof (`PROOF-PRESENTATION`)

Decode the artifact and authenticate the challenge. Then verify `vp_token` with your credential
library and apply route policy. On failure, return an
[x401 Error Object](https://x401.proof.com/spec/#x401-error-object) in `PROOF-RESPONSE`. See the full
[verifier processing rules](https://x401.proof.com/spec/#verifier-processing-rules).

```ts
const artifact = verifier.decodeVPArtifact(
  request.headers["proof-presentation"],
);

const check = await verifier.verifyChallenge({
  value: artifact.challenge,
  encryptor,
  expectedVerifierId: "https://research.example.com",
  expectedResource: "https://research.example.com/papers/medical-study-123",
  expectedMethod: "GET",
});

if (!check.ok) {
  response.setHeader(
    "PROOF-RESPONSE",
    verifier.encodeErrorObject(
      verifier.buildErrorObject({ error: "invalid_challenge" }),
    ),
  );
  return;
}

// verify artifact.vp_token with your credential library, then apply route policy
```

## Agent

See the full [agent processing rules](https://x401.proof.com/spec/#agent-processing-rules).

### Read a Proof requirement (`PROOF-REQUIRED`)

`detectProofRequirement` reads the header, falling back to the embedded `<data>` element. Take the
nonce and credential query to build your OpenID4VP request (out of scope for this package).

```ts
import { agent } from "@proof.com/x401-node";

const res = await fetch(url);
const requirement = agent.detectProofRequirement({
  headers: res.headers,
  body: await res.text(),
});

if (requirement) {
  const nonce = agent.getNonce(requirement.payload);
  const query = agent.getCredentialQuery(requirement.payload); // { scope } | { dcql_query }
}
```

### Present a Proof (`PROOF-PRESENTATION`)

Wrap the wallet's `vp_token` in a [VP Artifact](https://x401.proof.com/spec/#vp-artifact) and retry
the same route.

```ts
const artifact = agent.buildVPArtifact({
  payload: requirement.payload,
  agentId: "did:web:agent.example",
  vpToken,
});

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

[Contribution guidelines for this project](CONTRIBUTING.md)
