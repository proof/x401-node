import {
  EMBEDDED_DATA_VALUE,
  HEADER,
  REQUEST_SCHEMA_URL,
  RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  X401_SCHEME,
  X401_VERSION,
} from "./constants.ts";
import { decodeProofHeader, encodeJson } from "./encoding.ts";
import {
  parseX401ErrorObject,
  parseX401Payload,
  X401ValidationError,
} from "./validate.ts";
import type {
  CredentialRequestOptions,
  CredentialResult,
  DigitalCredentialRequest,
  ResultArtifact,
  TokenExchangeRequest,
  TokenExchangeResponse,
  X401ErrorObject,
  X401Payload,
  X401TokenObject,
} from "./types.ts";

type HeadersInput =
  | Headers
  | Record<string, string | string[] | undefined>
  | ReadonlyArray<readonly [string, string]>;

function getHeader(headers: HeadersInput, name: string): string | undefined {
  const lower = name.toLowerCase();
  if (typeof Headers !== "undefined" && headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }
  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (entry[0]?.toLowerCase() === lower) {
        return entry[1];
      }
    }
    return undefined;
  }
  for (const [key, value] of Object.entries(
    headers as Record<string, string | string[] | undefined>,
  )) {
    if (key.toLowerCase() === lower) {
      return Array.isArray(value) ? value[0] : (value ?? undefined);
    }
  }
  return undefined;
}

export function decodePayload(headerValue: string): X401Payload {
  return parseX401Payload(decodeProofHeader(headerValue));
}

export function decodeErrorObject(headerValue: string): X401ErrorObject {
  return parseX401ErrorObject(decodeProofHeader(headerValue));
}

interface DetectInput {
  /** Response headers (Headers, plain object, or entry list). */
  headers?: HeadersInput;
  /** Response body, scanned for the embedded `<data>` requirement when the header is absent. */
  body?: string;
}

export interface ProofRequirement {
  source: "header" | "embedded";
  payload: X401Payload;
}

const EMBEDDED_RE = new RegExp(
  `<data[^>]*value="${EMBEDDED_DATA_VALUE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"[^>]*>([\\s\\S]*?)</data>`,
  "i",
);

export function detectProofRequirement(
  input: DetectInput,
): ProofRequirement | null {
  if (input.headers !== undefined) {
    const headerValue = getHeader(input.headers, HEADER.PROOF_REQUEST);
    if (headerValue) {
      return { source: "header", payload: decodePayload(headerValue) };
    }
  }
  if (input.body) {
    const match = input.body.match(EMBEDDED_RE);
    if (match && match[1] !== undefined) {
      const json = decodeHtmlEntities(match[1].trim());
      const parsed: unknown = JSON.parse(json);
      if (!hasEmbeddedRequestSchema(parsed)) {
        throw new X401ValidationError(
          `embedded x401 payload "$schema" must be "${REQUEST_SCHEMA_URL}".`,
        );
      }
      return {
        source: "embedded",
        payload: parseX401Payload(parsed),
      };
    }
  }
  return null;
}

function hasEmbeddedRequestSchema(
  value: unknown,
): value is { $schema: typeof REQUEST_SCHEMA_URL } {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as { $schema?: unknown }).$schema === REQUEST_SCHEMA_URL
  );
}

function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&amp;/g, "&");
}

/**
 * Returns the Verifier-composed credential request, usable directly as the
 * argument to `navigator.credentials.get()`. x401 treats it as opaque; the
 * Agent MUST NOT modify it.
 */
export function getCredentialRequestOptions(
  payload: X401Payload,
): CredentialRequestOptions {
  return payload.credential_requirements;
}

/**
 * Returns the `digital` member of the Verifier-composed credential request.
 */
export function getDigitalCredentialRequest(
  payload: X401Payload,
): DigitalCredentialRequest {
  return payload.credential_requirements.digital;
}

/**
 * Returns a copy of the payload with `return_uri` added, for an intermediary relaying the
 * request to a remote handler that POSTs the credential result back. Only a relaying
 * intermediary sets this; never the Verifier. The URL must be https.
 */
export function addReturnUri(
  payload: X401Payload,
  returnUri: string,
): X401Payload {
  if (!returnUri.startsWith("https://")) {
    throw new X401ValidationError("return_uri must be an https URL.");
  }
  return { ...payload, return_uri: returnUri };
}

interface BuildResultArtifactInput {
  /** The `{ protocol, data }` credential result returned by the Credential Manager. */
  credentialResult: CredentialResult;
  /** Stable verifier-defined identifier for the proof template, when correlating. */
  requestId?: string;
  /** Agent Identifier, when the deployment binds the Agent to the retry. */
  agentId?: string;
}

/** Packages an inline credential result as a Result Artifact for protected-route retry. */
export function buildResultArtifact(
  input: BuildResultArtifactInput,
): ResultArtifact {
  return {
    credential_result: input.credentialResult,
    ...(input.requestId !== undefined && { request_id: input.requestId }),
    ...(input.agentId !== undefined && { agent_id: input.agentId }),
  };
}

interface BuildResultArtifactReferenceInput {
  /** HTTPS URL the Verifier dereferences to fetch the credential result. */
  credentialResultUri: string;
  /** RFC 3339 time after which the reference is no longer valid. */
  expiresAt?: string;
  /** Stable verifier-defined identifier for the proof template, when correlating. */
  requestId?: string;
  /** Agent Identifier, when the deployment binds the Agent to the retry. */
  agentId?: string;
}

/** Packages a by-reference credential result as a Result Artifact for protected-route retry. */
export function buildResultArtifactReference(
  input: BuildResultArtifactReferenceInput,
): ResultArtifact {
  return {
    credential_result_uri: input.credentialResultUri,
    ...(input.expiresAt !== undefined && { expires_at: input.expiresAt }),
    ...(input.requestId !== undefined && { request_id: input.requestId }),
    ...(input.agentId !== undefined && { agent_id: input.agentId }),
  };
}

export function encodeResultArtifact(artifact: ResultArtifact): string {
  return encodeJson(artifact);
}

export function buildTokenObject(accessToken: string): X401TokenObject {
  return {
    scheme: X401_SCHEME,
    version: X401_VERSION,
    token_type: "Bearer",
    access_token: accessToken,
  };
}

export function encodeTokenObject(token: X401TokenObject): string {
  return encodeJson(token);
}

interface TokenExchangeOptions {
  /** OAuth `resource` value to request (from oauth.resource or the protected URL). */
  resource?: string;
  /** OAuth `audience` value to request (from oauth.audience). */
  audience?: string;
}

export function buildTokenExchangeForm(
  artifact: ResultArtifact,
  options: TokenExchangeOptions = {},
): URLSearchParams {
  const request: TokenExchangeRequest = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token_type: RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
    subject_token: encodeResultArtifact(artifact),
    ...(options.resource !== undefined && { resource: options.resource }),
    ...(options.audience !== undefined && { audience: options.audience }),
  };
  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(request)) {
    form.set(key, value);
  }
  return form;
}

export function parseTokenExchangeResponse(
  value: unknown,
): TokenExchangeResponse {
  if (typeof value !== "object" || value === null) {
    throw new Error("x401: token response must be a JSON object.");
  }
  const record = value as Record<string, unknown>;
  if (typeof record.access_token !== "string") {
    throw new Error("x401: token response is missing access_token.");
  }
  if (typeof record.token_type !== "string") {
    throw new Error("x401: token response is missing token_type.");
  }
  return value as TokenExchangeResponse;
}
