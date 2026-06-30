import type {
  DC_API_PROTOCOL,
  RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  X401_SCHEME,
} from "./constants.ts";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/** Digital Credentials API protocol identifier for a request entry. */
export type DCApiProtocol =
  (typeof DC_API_PROTOCOL)[keyof typeof DC_API_PROTOCOL];

/**
 * One entry of a composed Digital Credentials request. `data` carries the
 * protocol-specific request (the signed JAR for `openid4vp-v1-signed`, or the
 * OpenID4VP parameters directly for `openid4vp-v1-unsigned`); x401 treats it as opaque.
 */
export interface DigitalCredentialRequestEntry {
  protocol: DCApiProtocol;
  data: JsonObject;
}

/**
 * The Verifier-composed Digital Credentials request carried in
 * `credential_requirements.digital`. It is the value for the `digital` member
 * of `navigator.credentials.get()`.
 */
export interface DigitalCredentialRequest {
  requests: DigitalCredentialRequestEntry[];
}

/**
 * The CredentialRequestOptions object carried in `credential_requirements`.
 * This version of x401 specifies the `digital` member.
 */
export interface CredentialRequestOptions {
  digital: DigitalCredentialRequest;
}

/** The `{ protocol, data }` result a Credential Manager returns. */
export interface CredentialResult {
  protocol: string;
  /** Credential Manager-returned result material. Opaque to x401. */
  data: JsonValue;
}

/** OAuth token-exchange metadata carried in `oauth`. */
export interface OAuthMetadata {
  token_endpoint: string;
  audience?: string;
  resource?: string;
}

/** Informational payment hint. Does not replace 402 Payment Required semantics. */
export interface PaymentObject {
  required?: boolean;
  scheme_hint?: string;
  notes?: string;
}

/** The flat x401 payload carried in the PROOF-REQUEST header. */
export interface X401Payload {
  scheme: typeof X401_SCHEME;
  version: string;
  /** The composed credential request. Required. */
  credential_requirements: CredentialRequestOptions;
  /** OAuth token-exchange metadata. Required. */
  oauth: OAuthMetadata;
  /** Stable verifier-defined identifier for the proof template. Optional hint. */
  request_id?: string;
  /** Stable identifiers for reusable proof requirements this proof would satisfy. Optional hint. */
  satisfied_requirements?: string[];
  /**
   * HTTPS URL a remote handler POSTs the credential result to. Added by a relaying
   * intermediary, never by the Verifier, when relaying to a remote handler.
   */
  return_uri?: string;
  payment?: PaymentObject;
}

/**
 * The Result Artifact carried in PROOF-RESPONSE for a direct retry. Carries the
 * credential result inline (`credential_result`) or by reference
 * (`credential_result_uri`); exactly one MUST be present.
 */
export interface ResultArtifact {
  /** Inline credential result. Mutually exclusive with `credential_result_uri`. */
  credential_result?: CredentialResult;
  /** HTTPS URL the Verifier dereferences to fetch the credential result. */
  credential_result_uri?: string;
  /** RFC 3339 time after which `credential_result_uri` is no longer valid. */
  expires_at?: string;
  request_id?: string;
  /** Optional Agent Identifier, when the deployment binds the Agent to the retry. */
  agent_id?: string;
}

/** A reusable proof-satisfaction token carried in PROOF-RESPONSE. */
export interface X401TokenObject {
  scheme: typeof X401_SCHEME;
  version: string;
  token_type: "Bearer";
  access_token: string;
}

/** The x401 Error Object carried in the PROOF-RESULT header. */
export interface X401ErrorObject {
  scheme: typeof X401_SCHEME;
  version: string;
  error: string;
  error_description?: string;
  error_uri?: string;
  request_id?: string;
}

/** OAuth 2.0 Token Exchange response that returns an x401 Verification Token. */
export interface TokenExchangeResponse {
  access_token: string;
  issued_token_type?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
  x401?: JsonObject;
}

/** The fixed parameters of an x401 OAuth Token Exchange request. */
export interface TokenExchangeRequest {
  grant_type: typeof TOKEN_EXCHANGE_GRANT_TYPE;
  subject_token_type: typeof RESULT_ARTIFACT_SUBJECT_TOKEN_TYPE;
  subject_token: string;
  resource?: string;
  audience?: string;
}
