import type {
  DC_API_PROTOCOL,
  TOKEN_EXCHANGE_GRANT_TYPE,
  VP_ARTIFACT_SUBJECT_TOKEN_TYPE,
  X401_SCHEME,
} from "./constants.ts";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/** A DCQL query. x401 treats it as an opaque OpenID4VP credential query object. */
export type DCQLQuery = JsonObject;

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
 * The Verifier-composed Digital Credentials request carried in `presentation_requirements`.
 * A `DigitalCredentialRequestOptions` value, usable directly as the `digital` member of
 * `navigator.credentials.get()`.
 */
export interface DigitalCredentialRequest {
  requests: DigitalCredentialRequestEntry[];
}

/** The `{ protocol, data }` result a Wallet returns through the Digital Credentials API. */
export interface PresentationResult {
  protocol: string;
  /** Wallet-returned presentation material. Opaque to x401. */
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

/** The flat x401 payload carried (base64url-encoded) in the PROOF-REQUIRED header. */
export interface X401Payload {
  scheme: typeof X401_SCHEME;
  version: string;
  /** The composed Digital Credentials request. Load-bearing. */
  presentation_requirements: DigitalCredentialRequest;
  /** OAuth token-exchange metadata. Load-bearing. */
  oauth: OAuthMetadata;
  /** HTTPS URL of a DIF Credential Trust Establishment document. Optional hint. */
  trust_establishment?: string;
  /** Stable verifier-defined identifier for the proof template. Optional hint. */
  request_id?: string;
  /** Stable identifiers for reusable proof requirements this proof would satisfy. Optional hint. */
  satisfied_requirements?: string[];
  payment?: PaymentObject;
}

/**
 * The VP Artifact carried (base64url-encoded) in PROOF-PRESENTATION for a direct retry.
 * Carries the presentation result inline (`response`) or by reference (`presentation_uri`);
 * exactly one MUST be present.
 */
export interface VPArtifact {
  /** Inline presentation result. Mutually exclusive with `presentation_uri`. */
  response?: PresentationResult;
  /** HTTPS URL the Verifier dereferences to fetch the presentation result. */
  presentation_uri?: string;
  /** RFC 3339 time after which `presentation_uri` is no longer valid. */
  expires_at?: string;
  request_id?: string;
  /** Optional Agent Identifier, when the deployment binds the Agent to the retry. */
  agent_id?: string;
}

/** A reusable proof-satisfaction token carried in PROOF-PRESENTATION. */
export interface X401TokenObject {
  scheme: typeof X401_SCHEME;
  version: string;
  token_type: "Bearer";
  access_token: string;
}

/** The x401 Error Object carried (base64url-encoded) in the PROOF-RESPONSE header. */
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
  subject_token_type: typeof VP_ARTIFACT_SUBJECT_TOKEN_TYPE;
  subject_token: string;
  resource?: string;
  audience?: string;
}
