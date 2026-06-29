# x401 conformance map

Maps the spec's RFC 2119 normative statements to where this library enforces them, or records why
they are out of scope. The goal is to make "did we miss a MUST?" answerable.

- **Source of truth:** `spec/spec.md` at the ref in `spec/SPEC_SOURCE.json` (currently x401
  **0.2.0**, proof/x401 `main`).
- **Drift detection:** `spec/normative-ledger.json` snapshots every normative statement. After
  `node scripts/sync-spec-fixtures.ts`, run `node scripts/extract-normative.ts` to see what was
  added or removed since the ledger. Triage new statements here, then run
  `node scripts/extract-normative.ts --update`.
- **Scope of this library:** it produces, encodes, decodes, and structurally validates the x401 wire
  objects. It does not verify credentials, validate result bindings, sign or compose the OpenID4VP
  request, perform the Credential Manager call, or make HTTP transport decisions. Those statements
  are marked out of scope with the responsible layer.

## In scope: enforced or produced by this library

| Spec requirement                                                                                                                                                                                                      | Where                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scheme` MUST be `"x401"` (payload, error, token)                                                                                                                                                                     | `validate.ts` `parseX401Payload` / `parseX401ErrorObject` / `parseX401TokenObject`; builders in `verifier.ts`/`agent.ts` set the constant. Tests: `x401.test.ts`, `spec-fixtures.test.ts` |
| `version` REQUIRED                                                                                                                                                                                                    | `validate.ts` (all three parsers); `X401_VERSION` constant                                                                                                                                |
| `credential_requirements` REQUIRED; `digital.requests` a non-empty array; each `protocol` is `openid4vp-v1-signed` or `openid4vp-v1-unsigned`; each `data` an object                                                  | `validate.ts` `parseX401Payload`, `verifier.ts` `buildPayload`. Tests: `spec-schema.test.ts`, `x401.test.ts`                                                                              |
| `oauth` REQUIRED; `oauth.token_endpoint` REQUIRED                                                                                                                                                                     | `validate.ts` `parseX401Payload`. Tests: `spec-schema.test.ts`, `x401.test.ts`                                                                                                            |
| Payload encoded value MUST be base64url UTF-8 JSON (RFC 4648 section 5, no padding); decoded value MUST be a single JSON object                                                                                       | `encoding.ts` (`@owf/identity-common` base64url)                                                                                                                                          |
| MUST NOT combine multiple objects in one proof header through commas or lists; comma value MUST be treated as invalid                                                                                                 | `encoding.ts` `decodeProofHeader` comma guard. Test: `x401.test.ts`                                                                                                                       |
| Result Artifact MUST contain exactly one of `credential_result` or `credential_result_uri`                                                                                                                            | `validate.ts` `parseResultArtifact`. Tests: `x401.test.ts`, `spec-fixtures.test.ts`                                                                                                       |
| `credential_result` is the `{ protocol, data }` Credential Manager result                                                                                                                                             | `validate.ts` `parseResultArtifact`; `agent.ts` `buildResultArtifact`                                                                                                                     |
| `credential_result_uri` MUST be an `https` URL                                                                                                                                                                        | `validate.ts` `parseResultArtifact`. Test: `x401.test.ts`                                                                                                                                 |
| Token Object `token_type` MUST be `"Bearer"`; `access_token` REQUIRED                                                                                                                                                 | `validate.ts` `parseX401TokenObject`; `agent.ts` `buildTokenObject`                                                                                                                       |
| Error Object `error` REQUIRED                                                                                                                                                                                         | `validate.ts` `parseX401ErrorObject`                                                                                                                                                      |
| Token-exchange fixed params (`grant_type`, `subject_token_type`, Bearer) MUST NOT be repeated in the payload                                                                                                          | not present in the payload type; set only on the form by `agent.ts` `buildTokenExchangeForm`; verified by `verifier.ts` `parseTokenExchange`. Test: `x401.test.ts`                        |
| Embedded `<data>`: tag `data`, `value="application/json;x401=proof-required"`, `hidden`, single JSON object that is a valid payload and MUST include a `$schema` member = `https://x401.id/spec/schemas/request.json` | `verifier.ts` `embedHtmlData`; `agent.ts` `detectProofRequirement` plus `parseX401Payload`. Test: `x401.test.ts` (embedded round-trip, missing `$schema` rejection)                       |
| Embedded object subject to the same structural validation as a header payload                                                                                                                                         | `agent.ts` `detectProofRequirement` runs `parseX401Payload`. Test: `x401.test.ts`                                                                                                         |
| Agent MUST NOT modify any entry in `credential_requirements`                                                                                                                                                          | `agent.ts` `getCredentialRequestOptions` returns it unmodified; library never mutates it                                                                                                  |
| A relaying intermediary MUST add a `return_uri` member (an `https` URL) to the forwarded payload; the Verifier never sets it                                                                                          | `agent.ts` `addReturnUri` (https-validated); `buildPayload` never emits it; `validate.ts` `parseX401Payload` enforces https. Tests: `x401.test.ts`                                        |

## Out of scope: responsibility of another layer

These normative statements are real but fall outside an encode, decode, and validate library.

- **Remote handler processing** (matching `credential_requirements.digital.requests[]` against held
  credentials, satisfying `dcql_query` including `credential_sets` and `claim_sets`, holder
  selection, producing the credential result, posting it to `return_uri`): the remote wallet or
  handler. This SDK only adds and validates the `return_uri` member; it does not act as a handler.
- **Verifier proof validation and crypto** (Verifier Binding, nonce freshness and replay,
  dereferencing a `credential_result_uri`, unique URI issuance, issuer trust enforcement,
  `trusted_authorities`): the verifier application. This library does not verify credential results
  or sign requests.
- **Credential verification** (issuer trust, status, revocation, claim satisfaction):
  `@proof.com/proof-vc-common`. `vp_token` and `credential_result.data` are opaque here.
- **Agent runtime and transport** (obtaining a credential result through
  `navigator.credentials.get`, relaying, remote fulfillment, retrying the route): the Agent
  application.
- **OpenID4VP request composition and signing** (the JAR, `client_id`, `expected_origins`, `nonce`,
  `dcql_query`, `exp`): the Verifier; carried opaque in `data`.
- **HTTP semantics** (status-code independence, `WWW-Authenticate` non-use, `402` payment
  separation, `Cache-Control`/`Vary`, CORS exposure): the HTTP server or deployment.
- **Verification Token issuance, scope, binding, holder identity**, and **Agent binding**: the
  verifier or deployment.

## Known coverage gap

Only the `PROOF-REQUEST` payload has an official JSON Schema. The Result Artifact, Error Object, and
Token Object are checked against extracted spec examples plus these parsers, not a published schema.
If the spec later publishes schemas for those objects, add them to `spec/fixtures/` through
`sync-spec-fixtures.ts` and extend `spec-schema.test.ts`.
