export const X401_SCHEME = "x401" as const;

export const X401_VERSION = "0.2.0" as const;

/**
 * W3C Digital Credentials API protocol identifiers for an entry in
 * `credential_requirements.digital.requests`. `SIGNED` is RECOMMENDED.
 */
export const DC_API_PROTOCOL = {
  SIGNED: "openid4vp-v1-signed",
  UNSIGNED: "openid4vp-v1-unsigned",
} as const;

export const HEADER = {
  PROOF_REQUEST: "PROOF-REQUEST",
  PROOF_RESPONSE: "PROOF-RESPONSE",
  PROOF_RESULT: "PROOF-RESULT",
} as const;

export const REQUEST_SCHEMA_URL = "https://x401.id/spec/schemas/request.json";

export const EMBEDDED_DATA_VALUE = "application/json;x401=proof-required";

export const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";

export const RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE =
  "urn:x401:params:oauth:token-type:result_artifact";

/** RECOMMENDED `issued_token_type` value for a Bearer Verification Token (RFC 8693). */
export const ACCESS_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:access_token";
