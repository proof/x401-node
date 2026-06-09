import {
  EMBEDDED_DATA_VALUE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  VP_ARTIFACT_SUBJECT_TOKEN_TYPE,
  X401_SCHEME,
  X401_VERSION,
} from "./constants.ts";
import { decodeProofHeader, encodeJson } from "./encoding.ts";
import { parseX401ErrorObject, parseX401Payload } from "./validate.ts";
import type {
  DCQLQuery,
  JsonObject,
  JsonValue,
  TokenExchangeResponse,
  VPArtifact,
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
    const headerValue = getHeader(input.headers, "PROOF-REQUIRED");
    if (headerValue) {
      return { source: "header", payload: decodePayload(headerValue) };
    }
  }
  if (input.body) {
    const match = input.body.match(EMBEDDED_RE);
    if (match && match[1] !== undefined) {
      const json = decodeHtmlEntities(match[1].trim());
      return {
        source: "embedded",
        payload: parseX401Payload(JSON.parse(json)),
      };
    }
  }
  return null;
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

export function getNonce(payload: X401Payload): string {
  return payload.proof.challenge.value;
}

export function getCredentialQuery(
  payload: X401Payload,
): { scope: string } | { dcql_query: DCQLQuery } {
  if (payload.proof.scope !== undefined) {
    return { scope: payload.proof.scope };
  }
  return { dcql_query: payload.proof.dcql_query as DCQLQuery };
}

interface BuildVPArtifactInput {
  /** The decoded x401 payload that produced this presentation. */
  payload: X401Payload;
  /** Agent Identifier (the OpenID4VP client_id used with the wallet). */
  agentId: string;
  /** Wallet-returned presentation material. Opaque to x401 (string or object). */
  vpToken: JsonValue;
  /** OpenID4VP presentation submission metadata returned by the wallet, when applicable. */
  presentationSubmission?: JsonObject;
  /** Agent-generated correlation state returned by the wallet, when applicable. */
  state?: string;
}

export function buildVPArtifact(input: BuildVPArtifactInput): VPArtifact {
  return {
    agent_id: input.agentId,
    challenge: input.payload.proof.challenge.value,
    vp_token: input.vpToken,
    ...(input.payload.proof.request_id !== undefined && {
      request_id: input.payload.proof.request_id,
    }),
    ...(input.presentationSubmission !== undefined && {
      presentation_submission: input.presentationSubmission,
    }),
    ...(input.state !== undefined && { state: input.state }),
  };
}

export function encodeVPArtifact(artifact: VPArtifact): string {
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
  /** OAuth `resource` value to request (from proof.oauth.resource or the protected URL). */
  resource?: string;
  /** OAuth `audience` value to request (from proof.oauth.audience). */
  audience?: string;
}

export function buildTokenExchangeForm(
  artifact: VPArtifact,
  options: TokenExchangeOptions = {},
): URLSearchParams {
  const form = new URLSearchParams();
  form.set("grant_type", TOKEN_EXCHANGE_GRANT_TYPE);
  form.set("subject_token_type", VP_ARTIFACT_SUBJECT_TOKEN_TYPE);
  form.set("subject_token", encodeVPArtifact(artifact));
  if (options.resource !== undefined) {
    form.set("resource", options.resource);
  }
  if (options.audience !== undefined) {
    form.set("audience", options.audience);
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
