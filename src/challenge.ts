import {
  base64urlDecode,
  base64urlEncode,
  uint8ArrayToBase64Url,
} from "@owf/identity-common";

import type { Encryptor } from "./encryptor.ts";
import type { JsonObject, VerifierChallenge } from "./types.ts";

const PREFIX = "x401";
const RANDOM_BYTES = 16;

export interface CreateChallengeInput {
  /** Verifier identifier (e.g. HTTPS origin or DID). Encoded into the challenge value and sealed into the nonce. */
  verifierId: string;
  /** Route/resource the challenge is bound to. */
  resource: string;
  /** HTTP method the challenge is bound to. */
  method: string;
  /** Encryptor used to encrypt the challenge state into the nonce segment. */
  encryptor: Encryptor;
  /** Challenge lifetime in seconds. */
  ttlSeconds: number;
  /** Override the current time (testing). */
  now?: Date;
  /** Additional verifier-defined context bound into the challenge (policy id, agent rules, retry mechanisms, etc.). */
  context?: JsonObject;
}

export async function createChallenge(
  input: CreateChallengeInput,
): Promise<VerifierChallenge> {
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000);
  const rnd = uint8ArrayToBase64Url(
    crypto.getRandomValues(new Uint8Array(RANDOM_BYTES)),
  );
  const claims: JsonObject = {
    vid: input.verifierId,
    rnd,
    resource: input.resource,
    method: input.method.toUpperCase(),
    exp: Math.floor(expiresAt.getTime() / 1000),
    ...(input.context !== undefined && { context: input.context }),
  };
  const nonce = await input.encryptor.encrypt(claims);
  return {
    value: `${PREFIX}:${base64urlEncode(input.verifierId)}:${nonce}`,
    expires_at: expiresAt.toISOString(),
  };
}

function parseChallengeValue(value: string): {
  verifierId: string;
  nonce: string;
} {
  const first = value.indexOf(":");
  const second = value.indexOf(":", first + 1);
  if (first < 0 || second < 0 || value.slice(0, first) !== PREFIX) {
    throw new Error("x401: malformed Verifier Challenge value.");
  }
  return {
    verifierId: base64urlDecode(value.slice(first + 1, second)),
    nonce: value.slice(second + 1),
  };
}

export type VerifyChallengeResult =
  | {
      ok: true;
      verifierId: string;
      resource: string;
      method: string;
      expiresAt: string;
      claims: JsonObject;
    }
  | { ok: false; reason: string };

export interface VerifyChallengeInput {
  /** The returned challenge value (from the VP Artifact or token-exchange request). */
  value: string;
  /** The same encryptor used to create the challenge. */
  encryptor: Encryptor;
  /** Reject the challenge unless its sealed verifier identifier equals this value. */
  expectedVerifierId?: string;
  /** Reject the challenge unless its sealed resource equals this value. */
  expectedResource?: string;
  /** Reject the challenge unless its sealed method equals this value (case-insensitive). */
  expectedMethod?: string;
  /** Override the current time (testing). */
  now?: Date;
}

export async function verifyChallenge(
  input: VerifyChallengeInput,
): Promise<VerifyChallengeResult> {
  let parsed: { verifierId: string; nonce: string };
  try {
    parsed = parseChallengeValue(input.value);
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }

  let claims: JsonObject;
  try {
    claims = await input.encryptor.decrypt(parsed.nonce);
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }

  const vid = typeof claims.vid === "string" ? claims.vid : undefined;
  const resource =
    typeof claims.resource === "string" ? claims.resource : undefined;
  const method = typeof claims.method === "string" ? claims.method : undefined;
  const exp = typeof claims.exp === "number" ? claims.exp : undefined;
  if (
    vid === undefined ||
    resource === undefined ||
    method === undefined ||
    exp === undefined
  ) {
    return { ok: false, reason: "protected challenge state is incomplete" };
  }
  if (vid !== parsed.verifierId) {
    return { ok: false, reason: "verifier identifier mismatch" };
  }
  if (
    input.expectedVerifierId !== undefined &&
    vid !== input.expectedVerifierId
  ) {
    return { ok: false, reason: "verifier identifier mismatch" };
  }

  const now = input.now ?? new Date();
  if (now.getTime() / 1000 > exp) {
    return { ok: false, reason: "challenge expired" };
  }
  if (
    input.expectedResource !== undefined &&
    resource !== input.expectedResource
  ) {
    return { ok: false, reason: "resource mismatch" };
  }
  if (
    input.expectedMethod !== undefined &&
    method !== input.expectedMethod.toUpperCase()
  ) {
    return { ok: false, reason: "method mismatch" };
  }

  return {
    ok: true,
    verifierId: vid,
    resource,
    method,
    expiresAt: new Date(exp * 1000).toISOString(),
    claims,
  };
}
