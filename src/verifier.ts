import {
  EMBEDDED_DATA_VALUE,
  PRESENTATION_PROTOCOL,
  REQUEST_SCHEMA_URL,
  TOKEN_EXCHANGE_GRANT_TYPE,
  VP_ARTIFACT_SUBJECT_TOKEN_TYPE,
  X401_SCHEME,
  X401_VERSION,
} from "./constants.ts";
import { decodeProofHeader, encodeJson } from "./encoding.ts";
import {
  parseVPArtifact,
  parseX401TokenObject,
  X401ValidationError,
} from "./validate.ts";
import type {
  DCQLQuery,
  IssuersRef,
  OAuthMetadata,
  PaymentObject,
  VerifierChallenge,
  VPArtifact,
  X401ErrorObject,
  X401Payload,
  X401TokenObject,
} from "./types.ts";

export { createChallenge, verifyChallenge } from "./challenge.ts";
export type { VerifyChallengeResult } from "./challenge.ts";

interface BuildPayloadProof {
  /** Verifier Challenge, typically from {@link createChallenge}. */
  challenge: VerifierChallenge;
  /** OAuth token-exchange metadata for the Agent. */
  oauth: OAuthMetadata;
  /** DCQL Credential Query Requirement. Provide exactly one of `dcql_query` or `scope`. */
  dcql_query?: DCQLQuery;
  /** OpenID4VP scope Credential Query Requirement. Provide exactly one of `dcql_query` or `scope`. */
  scope?: string;
  /** Reference to an Issuer Trust List (DIF Credential Trust Establishment document). */
  issuers?: IssuersRef;
  /** Stable verifier-defined identifier for the proof template. */
  request_id?: string;
  /** Reusable proof-requirement identifiers marked satisfied if this proof is fulfilled. */
  satisfied_requirements?: string[];
}

interface BuildPayloadInput {
  proof: BuildPayloadProof;
  /** Informational payment hint. Does not replace 402 Payment Required. */
  payment?: PaymentObject;
}

export function buildPayload(input: BuildPayloadInput): X401Payload {
  const { proof } = input;
  const hasDcql = proof.dcql_query !== undefined;
  const hasScope = proof.scope !== undefined;
  if (hasDcql === hasScope) {
    throw new X401ValidationError(
      "proof must contain exactly one of dcql_query or scope.",
    );
  }
  return {
    scheme: X401_SCHEME,
    version: X401_VERSION,
    proof: {
      presentation_protocol: PRESENTATION_PROTOCOL,
      challenge: proof.challenge,
      oauth: proof.oauth,
      ...(proof.dcql_query !== undefined && { dcql_query: proof.dcql_query }),
      ...(proof.scope !== undefined && { scope: proof.scope }),
      ...(proof.issuers !== undefined && { issuers: proof.issuers }),
      ...(proof.request_id !== undefined && { request_id: proof.request_id }),
      ...(proof.satisfied_requirements !== undefined && {
        satisfied_requirements: proof.satisfied_requirements,
      }),
    },
    ...(input.payment !== undefined && { payment: input.payment }),
  };
}

export function encodePayload(payload: X401Payload): string {
  return encodeJson(payload);
}

export function embedHtmlData(payload: X401Payload): string {
  const json = JSON.stringify(
    { $schema: REQUEST_SCHEMA_URL, ...payload },
    null,
    2,
  );
  return `<data value="${EMBEDDED_DATA_VALUE}" hidden>${escapeHtml(json)}</data>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function decodeVPArtifact(headerValue: string): VPArtifact {
  return parseVPArtifact(decodeProofHeader(headerValue));
}

export function decodeTokenObject(headerValue: string): X401TokenObject {
  return parseX401TokenObject(decodeProofHeader(headerValue));
}

export interface ParsedTokenExchange {
  subject_token: string;
  resource?: string;
  audience?: string;
}

export function parseTokenExchange(
  form: URLSearchParams | Record<string, string | undefined>,
): ParsedTokenExchange {
  const get = (key: string): string | undefined =>
    form instanceof URLSearchParams ? (form.get(key) ?? undefined) : form[key];
  if (get("grant_type") !== TOKEN_EXCHANGE_GRANT_TYPE) {
    throw new X401ValidationError(
      "unsupported grant_type for x401 token exchange.",
    );
  }
  if (get("subject_token_type") !== VP_ARTIFACT_SUBJECT_TOKEN_TYPE) {
    throw new X401ValidationError(
      "unsupported subject_token_type for x401 token exchange.",
    );
  }
  const subjectToken = get("subject_token");
  if (subjectToken === undefined) {
    throw new X401ValidationError("subject_token is required.");
  }
  const resource = get("resource");
  const audience = get("audience");
  return {
    subject_token: subjectToken,
    ...(resource !== undefined && { resource }),
    ...(audience !== undefined && { audience }),
  };
}

interface BuildErrorInput {
  /** Short ASCII error code suitable for logs and programmatic handling. */
  error: string;
  /** Human-readable diagnostic text. */
  error_description?: string;
  /** HTTPS URL identifying documentation for the error. */
  error_uri?: string;
  /** The proof.request_id, when the error correlates to a proof template. */
  request_id?: string;
  /** The Verifier Challenge value, when the error can be safely correlated to a challenge. */
  challenge?: string;
}

export function buildErrorObject(input: BuildErrorInput): X401ErrorObject {
  return {
    scheme: X401_SCHEME,
    version: X401_VERSION,
    error: input.error,
    ...(input.error_description !== undefined && {
      error_description: input.error_description,
    }),
    ...(input.error_uri !== undefined && { error_uri: input.error_uri }),
    ...(input.request_id !== undefined && { request_id: input.request_id }),
    ...(input.challenge !== undefined && { challenge: input.challenge }),
  };
}

export function encodeErrorObject(error: X401ErrorObject): string {
  return encodeJson(error);
}
