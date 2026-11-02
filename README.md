# x401-node

x401-node lets you add x401 to your server or client.

An endpoint that requires proof of identity answers with an [x401](https://x401.proof.com/spec/latest/)
proof request. The client gets a credential from the user and retries the request with that
credential. x401-node builds and reads these messages.

> [!NOTE]
> Proof supports x401 through Proof Digital IDs, see [Use Proof Digital IDs](#use-proof-digital-ids).

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Usage](#usage)
  - [Read a proof request from an endpoint](#read-a-proof-request-from-an-endpoint)
  - [Read a rejection](#read-a-rejection)
  - [Put the proof request in an HTML page](#put-the-proof-request-in-an-html-page)
  - [Send the credential by reference](#send-the-credential-by-reference)
  - [Relay a proof request to another device](#relay-a-proof-request-to-another-device)
  - [Exchange a proof for a token](#exchange-a-proof-for-a-token)
- [Use Proof Digital IDs](#use-proof-digital-ids)
  - [Request and verify a Proof Digital ID](#request-and-verify-a-proof-digital-id)
  - [Use a wallet](#use-a-wallet)
- [Reference](#reference)
- [Links](#links)
- [Contributing](#contributing)
- [License](#license)

## Installation

```sh
npm install @proof.com/x401-node
```

## Quickstart

This script starts an endpoint that requires an `over_18` credential, and calls it as a client with
a mock credential.

```js
import { createServer } from "node:http";
import { agent, HEADER, verifier } from "@proof.com/x401-node";

const credentialRequest = {
  protocol: "openid4vp-v1-unsigned",
  data: {
    response_type: "vp_token",
    response_mode: "dc_api",
    nonce: "n-0S6_WzA2Mj",
    dcql_query: { credentials: [{ id: "over_18", format: "dc+sd-jwt" }] },
  },
};

const server = createServer((req, res) => {
  const proofResponse = req.headers["proof-response"];
  if (!proofResponse) {
    const payload = verifier.buildPayload({
      credentialRequirements: { digital: { requests: [credentialRequest] } },
    });
    res.writeHead(401, {
      [HEADER.PROOF_REQUEST]: verifier.encodePayload(payload),
    });
    res.end();
    return;
  }

  const { credential_result } = verifier.decodeResultArtifact(proofResponse);
  if (credential_result?.data?.vp_token?.over_18?.[0] !== "mock-credential") {
    const error = verifier.buildErrorObject({ error: "invalid_presentation" });
    res.writeHead(401, {
      [HEADER.PROOF_RESULT]: verifier.encodeErrorObject(error),
    });
    res.end();
    return;
  }
  res.end("Welcome, verified visitor");
}).listen(3000);

const url = "http://localhost:3000/";

const challenge = await fetch(url);
const requirement = agent.detectProofRequirement({
  headers: challenge.headers,
});
const [entry] = agent.getDigitalCredentialRequest(requirement.payload).requests;

const credentialResult = {
  protocol: entry.protocol,
  data: { vp_token: { over_18: ["mock-credential"] } },
};
const artifact = agent.buildResultArtifact({ credentialResult });

const response = await fetch(url, {
  headers: { [HEADER.PROOF_RESPONSE]: agent.encodeResultArtifact(artifact) },
});
console.log(response.status, await response.text());
// => 200 Welcome, verified visitor

server.close();
```

## Usage

### Read a proof request from an endpoint

`detectProofRequirement` reads the `PROOF-REQUEST` header, or the proof request in the HTML page
when there is no header.

```js
import { agent } from "@proof.com/x401-node";

const response = await fetch(
  "https://try.proof.com/x401/protected?env=fairfax",
);
const requirement = agent.detectProofRequirement({
  headers: response.headers,
  body: await response.text(),
});

console.log(requirement.source);
// => header
console.log(
  agent.getDigitalCredentialRequest(requirement.payload).requests[0].protocol,
);
// => openid4vp-v1-signed
```

### Read a rejection

`response` is a retry that the endpoint answered with `401`.

```js
const error = agent.decodeErrorObject(
  response.headers.get(HEADER.PROOF_RESULT),
);
console.log(error);
// => { scheme: "x401", version: "0.2.0", error: "invalid_presentation" }
```

### Put the proof request in an HTML page

Some clients read the page and not the headers. Add the proof request to the page, and keep the
`PROOF-REQUEST` header. `payload` is the one from `verifier.buildPayload`.

```js
const html = `<main>Proof required</main>${verifier.embedHtmlData(payload)}`;
```

### Send the credential by reference

When the credential is too large for a header, store it at an HTTPS URL that the endpoint can
fetch, and send the URL.

```js
const artifact = agent.buildResultArtifactReference({
  credentialResultUri: "https://agent.example.com/results/7f3a",
  expiresAt: "2026-11-02T21:00:00Z",
});
```

### Relay a proof request to another device

When your client forwards the proof request to a wallet on another device, add the HTTPS URL where
that wallet sends the credential.

```js
const relayed = agent.addReturnUri(
  requirement.payload,
  "https://agent.example.com/x401/return",
);
```

### Exchange a proof for a token

You can give the client an access token for later requests, so that the user does not present their
credential for each request. Put your token endpoint in the proof request:

```js
const payload = verifier.buildPayload({
  credentialRequirements: { digital: { requests: [credentialRequest] } },
  oauth: { token_endpoint: "https://api.example.com/oauth/token" },
});
```

The client exchanges the proof for a token, and sends the token in place of a proof. `url`,
`requirement` and `artifact` are the ones in the quickstart.

```js
const tokenResponse = await fetch(requirement.payload.oauth.token_endpoint, {
  method: "POST",
  body: agent.buildTokenExchangeForm(artifact, { resource: url }),
});
const { access_token } = agent.parseTokenExchangeResponse(
  await tokenResponse.json(),
);

const response = await fetch(url, {
  headers: {
    [HEADER.PROOF_RESPONSE]: agent.encodeTokenObject(
      agent.buildTokenObject(access_token),
    ),
  },
});
```

Your token endpoint reads the proof from the form, and your endpoint reads the token from the
`PROOF-RESPONSE` header:

```js
const { subject_token } = verifier.parseTokenExchange(
  new URLSearchParams(body),
);
const artifact = verifier.decodeResultArtifact(subject_token);

const { access_token } = verifier.decodeTokenObject(
  req.headers["proof-response"],
);
```

## Use Proof Digital IDs

### Request and verify a Proof Digital ID

[proof-vc-server](https://github.com/proof/proof-vc-common) signs the request for a Proof Digital ID
and verifies the Digital ID that the user presents. It needs the client ID and signing key of an
[enrolled Verifier](https://github.com/proof/proof-vc-common#verifier-enrollment).

```sh
npm install @proof.com/proof-vc-server
```

Put the signed request in the proof request:

```js
import {
  agentsTrustListUrl,
  createClient,
  createVerifier,
} from "@proof.com/proof-vc-server";
import { DC_API_PROTOCOL, verifier } from "@proof.com/x401-node";

const config = {
  environment: "sandbox",
  clientId: "https://example.com/.well-known/proof-client.json",
  privateKeyFactory: () => JSON.parse(process.env.SIGNING_JWK),
};

const nonce = crypto.randomUUID();
const request = await createClient({
  ...config,
  useSecuredAuthorizationRequest: true,
}).signedDcApiRequest({
  scope: "urn:proof:params:scope:verifiable-credentials:basic",
  nonce,
  expectedOrigins: [agentsTrustListUrl("sandbox")],
});

const payload = verifier.buildPayload({
  credentialRequirements: {
    digital: {
      requests: [{ protocol: DC_API_PROTOCOL.SIGNED, data: { request } }],
    },
  },
});
```

Verify the Digital ID in the `PROOF-RESPONSE` header. Proof sends it by reference, so fetch
`credential_result_uri` when it is set:

```js
const artifact = verifier.decodeResultArtifact(proofResponse);
const credentialResult =
  artifact.credential_result ??
  (await (await fetch(artifact.credential_result_uri)).json());

const presentation = await createVerifier(config).verifyVPToken({
  encodedVPToken: credentialResult.data.vp_token,
  aud: config.clientId,
});
const credential = presentation.proof_id_default?.[0];
```

### Use a wallet

[x401-agent](https://github.com/proof/x401-agent) presents the user's Proof Digital ID from their
Proof Cloud Wallet and retries the request. In a browser, pass
`agent.getCredentialRequestOptions(requirement.payload)` to `navigator.credentials.get()` to use
the wallet on the user's device.

## Reference

| Name                                 | Description                                                         |
| ------------------------------------ | ------------------------------------------------------------------- |
| `verifier.buildPayload`              | Builds a proof request from your credential request                 |
| `verifier.encodePayload`             | Encodes a proof request for the `PROOF-REQUEST` header              |
| `verifier.embedHtmlData`             | Returns the proof request as a `<data>` element for an HTML page    |
| `verifier.decodeResultArtifact`      | Decodes the proof in a `PROOF-RESPONSE` header or token form        |
| `verifier.decodeTokenObject`         | Decodes the token in a `PROOF-RESPONSE` header                      |
| `verifier.parseTokenExchange`        | Reads a token exchange request                                      |
| `verifier.buildErrorObject`          | Builds a rejection                                                  |
| `verifier.encodeErrorObject`         | Encodes a rejection for the `PROOF-RESULT` header                   |
| `agent.detectProofRequirement`       | Reads the proof request from a response's headers or HTML           |
| `agent.decodePayload`                | Decodes a `PROOF-REQUEST` header                                    |
| `agent.getCredentialRequestOptions`  | Returns the argument for `navigator.credentials.get()`              |
| `agent.getDigitalCredentialRequest`  | Returns the credential requests in a proof request                  |
| `agent.addReturnUri`                 | Adds the URL where a relayed wallet sends the credential            |
| `agent.buildResultArtifact`          | Builds a proof that contains the credential                         |
| `agent.buildResultArtifactReference` | Builds a proof that contains the URL of the credential              |
| `agent.encodeResultArtifact`         | Encodes a proof for the `PROOF-RESPONSE` header                     |
| `agent.buildTokenExchangeForm`       | Builds the token exchange request for a proof                       |
| `agent.parseTokenExchangeResponse`   | Reads the token endpoint's response                                 |
| `agent.buildTokenObject`             | Builds a token for the `PROOF-RESPONSE` header                      |
| `agent.encodeTokenObject`            | Encodes a token for the `PROOF-RESPONSE` header                     |
| `agent.decodeErrorObject`            | Decodes a `PROOF-RESULT` header                                     |
| `HEADER`                             | The header names: `PROOF_REQUEST`, `PROOF_RESPONSE`, `PROOF_RESULT` |
| `DC_API_PROTOCOL`                    | The credential request protocols: `SIGNED`, `UNSIGNED`              |
| `X401ValidationError`                | Thrown when a message does not follow the x401 specification        |

## Links

- [Read the x401 specification](https://x401.proof.com/spec/latest/)
- [Request and verify Proof Digital IDs with proof-vc-server](https://github.com/proof/proof-vc-common)
- [Protect Cloudflare Worker endpoints with x401-workers](https://github.com/proof/x401-workers)
- [Call x401 endpoints for a user with x401-agent](https://github.com/proof/x401-agent)
- [Call x401 endpoints from a terminal with x401-cli](https://github.com/proof/x401-cli)

## Contributing

[Contribution guidelines for this project](CONTRIBUTING.md)

## License

[Apache-2.0](LICENSE)
