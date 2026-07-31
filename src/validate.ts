import { DC_API_PROTOCOL, X401_SCHEME } from "./constants.ts";
import type {
  JsonObject,
  ResultArtifact,
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

export interface ReturnUriOptions {
  /**
   * Skip the https requirement on `return_uri`, permitting an http URL (e.g. a
   * `http://localhost` dev transport). Defaults to false.
   */
  allowInsecureUri?: boolean;
}

/**
 * Asserts `return_uri` is a string and, unless `allowInsecureUri` is set, an
 * https URL. Shared by the intermediary that adds it and the recipient that
 * decodes it so both sides apply the same rule.
 */
export function assertReturnUri(
  returnUri: unknown,
  options?: ReturnUriOptions,
): void {
  if (
    !isString(returnUri) ||
    (!options?.allowInsecureUri && !returnUri.startsWith("https://"))
  ) {
    throw new X401ValidationError("return_uri must be an https URL.");
  }
}

export function parseX401Payload(
  value: unknown,
  options?: ReturnUriOptions,
): X401Payload {
  if (!isObject(value)) {
    throw new X401ValidationError("x401 payload must be a JSON object.");
  }
  if (value.scheme !== X401_SCHEME) {
    throw new X401ValidationError('x401 payload "scheme" must be "x401".');
  }
  if (!isString(value.version)) {
    throw new X401ValidationError('x401 payload "version" is required.');
  }
  const credentialRequirements = value.credential_requirements;
  const digital = isObject(credentialRequirements)
    ? credentialRequirements.digital
    : undefined;
  if (
    !isObject(digital) ||
    !Array.isArray(digital.requests) ||
    digital.requests.length === 0
  ) {
    throw new X401ValidationError(
      "credential_requirements.digital.requests must be a non-empty array.",
    );
  }
  for (const entry of digital.requests) {
    if (!isObject(entry)) {
      throw new X401ValidationError(
        "each credential_requirements.digital.requests entry must be an object.",
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
  if (value.return_uri !== undefined) {
    assertReturnUri(value.return_uri, options);
  }
  return value as unknown as X401Payload;
}

export function parseResultArtifact(value: unknown): ResultArtifact {
  if (!isObject(value)) {
    throw new X401ValidationError("Result Artifact must be a JSON object.");
  }
  const hasResult = value.credential_result !== undefined;
  const hasUri = value.credential_result_uri !== undefined;
  if (hasResult === hasUri) {
    throw new X401ValidationError(
      "Result Artifact must contain exactly one of credential_result or credential_result_uri.",
    );
  }
  if (hasResult) {
    const result = value.credential_result;
    if (
      !isObject(result) ||
      !isString(result.protocol) ||
      result.data === undefined
    ) {
      throw new X401ValidationError(
        "Result Artifact credential_result must be a { protocol, data } object.",
      );
    }
  }
  if (
    hasUri &&
    (!isString(value.credential_result_uri) ||
      !value.credential_result_uri.startsWith("https://"))
  ) {
    throw new X401ValidationError(
      "Result Artifact credential_result_uri must be an https URL.",
    );
  }
  return value as unknown as ResultArtifact;
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
