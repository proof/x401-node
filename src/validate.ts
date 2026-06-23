import { DC_API_PROTOCOL, X401_SCHEME } from "./constants.ts";
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

const DC_API_PROTOCOLS: readonly string[] = Object.values(DC_API_PROTOCOL);

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
  const pr = value.presentation_requirements;
  if (
    !isObject(pr) ||
    !Array.isArray(pr.requests) ||
    pr.requests.length === 0
  ) {
    throw new X401ValidationError(
      "presentation_requirements.requests must be a non-empty array.",
    );
  }
  for (const entry of pr.requests) {
    if (!isObject(entry)) {
      throw new X401ValidationError(
        "each presentation_requirements.requests entry must be an object.",
      );
    }
    if (
      !isString(entry.protocol) ||
      !DC_API_PROTOCOLS.includes(entry.protocol)
    ) {
      throw new X401ValidationError(
        `request protocol must be one of ${DC_API_PROTOCOLS.join(", ")}.`,
      );
    }
    if (!isObject(entry.data)) {
      throw new X401ValidationError("request data must be an object.");
    }
  }
  const oauth = value.oauth;
  if (!isObject(oauth) || !isString(oauth.token_endpoint)) {
    throw new X401ValidationError("oauth.token_endpoint is required.");
  }
  return value as unknown as X401Payload;
}

export function parseVPArtifact(value: unknown): VPArtifact {
  if (!isObject(value)) {
    throw new X401ValidationError("VP Artifact must be a JSON object.");
  }
  const hasResponse = value.response !== undefined;
  const hasUri = value.presentation_uri !== undefined;
  if (hasResponse === hasUri) {
    throw new X401ValidationError(
      "VP Artifact must contain exactly one of response or presentation_uri.",
    );
  }
  if (hasResponse) {
    const response = value.response;
    if (
      !isObject(response) ||
      !isString(response.protocol) ||
      response.data === undefined
    ) {
      throw new X401ValidationError(
        "VP Artifact response must be a { protocol, data } object.",
      );
    }
  }
  if (
    hasUri &&
    (!isString(value.presentation_uri) ||
      !value.presentation_uri.startsWith("https://"))
  ) {
    throw new X401ValidationError(
      "VP Artifact presentation_uri must be an https URL.",
    );
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
  if (!isString(value.version)) {
    throw new X401ValidationError('x401 Token Object "version" is required.');
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
  if (!isString(value.version)) {
    throw new X401ValidationError('x401 Error Object "version" is required.');
  }
  if (!isString(value.error)) {
    throw new X401ValidationError("x401 Error Object error code is required.");
  }
  return value as unknown as X401ErrorObject;
}
