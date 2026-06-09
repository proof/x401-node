import { PRESENTATION_PROTOCOL, X401_SCHEME } from "./constants.ts";
import type {
  JsonObject,
  VPArtifact,
  X401ErrorObject,
  X401Payload,
  X401TokenObject,
} from "./types.ts";

export class X401ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "X401ValidationError";
  }
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function parseX401Payload(value: unknown): X401Payload {
  if (!isObject(value)) {
    throw new X401ValidationError("x401 payload must be a JSON object.");
  }
  if (value.scheme !== X401_SCHEME) {
    throw new X401ValidationError('x401 payload "scheme" must be "x401".');
  }
  if (!isString(value.version)) {
    throw new X401ValidationError('x401 payload "version" is required.');
  }
  const proof = value.proof;
  if (!isObject(proof)) {
    throw new X401ValidationError('x401 payload "proof" object is required.');
  }
  if (proof.presentation_protocol !== PRESENTATION_PROTOCOL) {
    throw new X401ValidationError(
      'proof.presentation_protocol must be "openid4vp".',
    );
  }
  const hasDcql = proof.dcql_query !== undefined;
  const hasScope = proof.scope !== undefined;
  if (hasDcql === hasScope) {
    throw new X401ValidationError(
      "proof must contain exactly one of dcql_query or scope.",
    );
  }
  if (hasScope && !isString(proof.scope)) {
    throw new X401ValidationError("proof.scope must be a string.");
  }
  if (hasDcql && !isObject(proof.dcql_query)) {
    throw new X401ValidationError("proof.dcql_query must be an object.");
  }
  const challenge = proof.challenge;
  if (
    !isObject(challenge) ||
    !isString(challenge.value) ||
    !isString(challenge.expires_at)
  ) {
    throw new X401ValidationError(
      "proof.challenge.value and proof.challenge.expires_at are required.",
    );
  }
  const oauth = proof.oauth;
  if (!isObject(oauth) || !isString(oauth.token_endpoint)) {
    throw new X401ValidationError("proof.oauth.token_endpoint is required.");
  }
  return value as unknown as X401Payload;
}

export function parseVPArtifact(value: unknown): VPArtifact {
  if (!isObject(value)) {
    throw new X401ValidationError("VP Artifact must be a JSON object.");
  }
  if (!isString(value.agent_id)) {
    throw new X401ValidationError("VP Artifact agent_id is required.");
  }
  if (!isString(value.challenge)) {
    throw new X401ValidationError("VP Artifact challenge is required.");
  }
  if (value.vp_token === undefined || value.vp_token === null) {
    throw new X401ValidationError("VP Artifact vp_token is required.");
  }
  return value as unknown as VPArtifact;
}

export function parseX401TokenObject(value: unknown): X401TokenObject {
  if (!isObject(value)) {
    throw new X401ValidationError("x401 Token Object must be a JSON object.");
  }
  if (value.scheme !== X401_SCHEME) {
    throw new X401ValidationError('x401 Token Object "scheme" must be "x401".');
  }
  if (value.token_type !== "Bearer") {
    throw new X401ValidationError(
      'x401 Token Object "token_type" must be "Bearer".',
    );
  }
  if (!isString(value.access_token)) {
    throw new X401ValidationError(
      "x401 Token Object access_token is required.",
    );
  }
  return value as unknown as X401TokenObject;
}

export function parseX401ErrorObject(value: unknown): X401ErrorObject {
  if (!isObject(value)) {
    throw new X401ValidationError("x401 Error Object must be a JSON object.");
  }
  if (value.scheme !== X401_SCHEME) {
    throw new X401ValidationError('x401 Error Object "scheme" must be "x401".');
  }
  if (!isString(value.error)) {
    throw new X401ValidationError("x401 Error Object error code is required.");
  }
  return value as unknown as X401ErrorObject;
}
