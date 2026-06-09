import type {
  PRESENTATION_PROTOCOL,
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

/** The Verifier Challenge object carried in `proof.challenge`. */
export interface VerifierChallenge {
  /** The exact value the Agent MUST use as the OpenID4VP `nonce`. */
  value: string;
  /** RFC 3339 timestamp after which the Verifier rejects the challenge. */
  expires_at: string;
}

/** OAuth token-exchange metadata carried in `proof.oauth`. */
export interface OAuthMetadata {
  token_endpoint: string;
  audience?: string;
  resource?: string;
}

/** Reference to a DIF Credential Trust Establishment document. */
export interface IssuersRef {
  trust_establishment_url: string;
}

/** The `proof` object of an x401 payload. Contains exactly one of `dcql_query` or `scope`. */
export interface ProofObject {
  presentation_protocol: typeof PRESENTATION_PROTOCOL;
  dcql_query?: DCQLQuery;
  scope?: string;
  challenge: VerifierChallenge;
  oauth: OAuthMetadata;
  issuers?: IssuersRef;
  request_id?: string;
  satisfied_requirements?: string[];
}

/** Informational payment hint. Does not replace 402 Payment Required semantics. */
export interface PaymentObject {
  required?: boolean;
  scheme_hint?: string;
  notes?: string;
}

/** The x401 payload carried (base64url-encoded) in the PROOF-REQUIRED header. */
export interface X401Payload {
  scheme: typeof X401_SCHEME;
  version: string;
  proof: ProofObject;
  payment?: PaymentObject;
}

/** The VP Artifact carried (base64url-encoded) in PROOF-PRESENTATION for a direct retry. */
export interface VPArtifact {
  agent_id: string;
  challenge: string;
  request_id?: string;
  /** Verifiable presentation material returned by the Wallet. Opaque to x401. */
  vp_token: JsonValue;
  presentation_submission?: JsonObject;
  state?: string;
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
  challenge?: string;
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
