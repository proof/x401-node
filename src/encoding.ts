import { base64urlDecode, base64urlEncode } from "@owf/identity-common";

import { X401ValidationError } from "./validate.ts";

export function encodeJson(value: unknown): string {
  return base64urlEncode(JSON.stringify(value));
}

export function decodeProofHeader(value: string): unknown {
  if (value.includes(",")) {
    throw new X401ValidationError(
      "x401 proof header MUST carry a single object; comma-separated lists are invalid.",
    );
  }
  return JSON.parse(base64urlDecode(value));
}
