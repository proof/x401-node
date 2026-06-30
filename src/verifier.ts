import {
  DC_API_PROTOCOL,
  EMBEDDED_DATA_VALUE,
  REQUEST_SCHEMA_URL,
  RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  X401_SCHEME,
  X401_VERSION,
} from "./constants.ts";
import { decodeProofHeader, encodeJson } from "./encoding.ts";
import {
  parseResultArtifact,
  parseX401TokenObject,
  X401ValidationError,
} from "./validate.ts";
import type {
  CredentialRequestOptions,
  OAuthMetadata,
  PaymentObject,
  ResultArtifact,
  X401ErrorObject,
  X401Payload,
  X401TokenObject,
} from "./types.ts";

const DC_API_PROTOCOLS: readonly string[] = Object.values(DC_API_PROTOCOL);

interface BuildPayloadInput {
  /**
   * The Verifier-composed credential request, usable directly as the argument
   * to `navigator.credentials.get()`. This version of x401 specifies its
   * `digital` member.
   */
  credentialRequirements: CredentialRequestOptions;
  /** OAuth token-exchange metadata for the Agent. */
  oauth: OAuthMetadata;
  /** Stable verifier-defined identifier for the proof template. Optional hint. */
  requestId?: string;
  /** Reusable proof-requirement identifiers this proof would satisfy. Optional hint. */
  satisfiedRequirements?: string[];
  /** Informational payment hint. Does not replace 402 Payment Required. */
  payment?: PaymentObject;
}

export function buildPayload(input: BuildPayloadInput): X401Payload {
  const requests = input.credentialRequirements.digital.requests;
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new X401ValidationError(
      "credential_requirements.digital.requests must be a non-empty array.",
    );
  }
  for (const entry of requests) {
    if (!DC_API_PROTOCOLS.includes(entry.protocol)) {
      throw new X401ValidationError(
        `request protocol must be one of ${DC_API_PROTOCOLS.join(", ")}.`,
      );
    }
  }
  return {
    scheme: X401_SCHEME,
    version: X401_VERSION,
    credential_requirements: input.credentialRequirements,
    oauth: input.oauth,
    ...(input.requestId !== undefined && { request_id: input.requestId }),
    ...(input.satisfiedRequirements !== undefined && {
      satisfied_requirements: input.satisfiedRequirements,
    }),
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

// Escape only `&` and `<`; leaving quotes and `>` keeps the embedded text directly
// readable as JSON, which the spec requires of the `<data>` content.
function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;");
}

export function decodeResultArtifact(headerValue: string): ResultArtifact {
  return parseResultArtifact(decodeProofHeader(headerValue));
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
  if (get("subject_token_type") !== RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE) {
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
  /** The request_id, when the error correlates to a proof template. */
  request_id?: string;
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
  };
}

export function encodeErrorObject(error: X401ErrorObject): string {
  return encodeJson(error);
}
