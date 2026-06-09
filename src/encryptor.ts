import {
  base64UrlToUint8Array,
  concatBytes,
  stringToBytes,
  uint8ArrayToBase64Url,
} from "@owf/identity-common";

import type { JsonObject } from "./types.ts";

const VERSION = 1;
const IV_BYTES = 12;

export interface EncryptorOptions {
  /** Secret key material. A string is UTF-8 encoded before key derivation. */
  key: string | Uint8Array;
  /** Domain-separation label mixed into key derivation and bound as additional authenticated data. */
  purpose?: string;
}

export interface Encryptor {
  /** Encrypt and authenticate a claims object into a single base64url token. */
  encrypt(claims: JsonObject): Promise<string>;
  /** Authenticate and decrypt a token back into its claims. Throws if authentication fails. */
  decrypt(token: string): Promise<JsonObject>;
}

function bytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(value);
}

async function deriveKey(
  material: Uint8Array<ArrayBuffer>,
  purpose: string,
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", material, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: bytes(stringToBytes("x401-encryptor")),
      info: bytes(stringToBytes(purpose)),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function createEncryptor(options: EncryptorOptions): Encryptor {
  const purpose = options.purpose ?? "x401";
  const material = bytes(
    typeof options.key === "string" ? stringToBytes(options.key) : options.key,
  );
  const aad = bytes(stringToBytes(`x401-encryptor.v${VERSION}.${purpose}`));
  let keyPromise: Promise<CryptoKey> | null = null;
  const getKey = (): Promise<CryptoKey> =>
    (keyPromise ??= deriveKey(material, purpose));

  return {
    async encrypt(claims: JsonObject): Promise<string> {
      const key = await getKey();
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          key,
          bytes(stringToBytes(JSON.stringify(claims))),
        ),
      );
      return uint8ArrayToBase64Url(
        concatBytes(new Uint8Array([VERSION]), iv, ciphertext),
      );
    },

    async decrypt(token: string): Promise<JsonObject> {
      const raw = base64UrlToUint8Array(token);
      if (raw.length < 1 + IV_BYTES + 1 || raw[0] !== VERSION) {
        throw new Error("x401 encryptor: malformed token.");
      }
      const key = await getKey();
      const iv = bytes(raw.subarray(1, 1 + IV_BYTES));
      const ciphertext = bytes(raw.subarray(1 + IV_BYTES));
      let plaintext: ArrayBuffer;
      try {
        plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          key,
          ciphertext,
        );
      } catch {
        throw new Error("x401 encryptor: authentication failed.");
      }
      return JSON.parse(
        new TextDecoder().decode(new Uint8Array(plaintext)),
      ) as JsonObject;
    },
  };
}
