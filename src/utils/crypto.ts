// AES_ENCRYPT_KEY は base64 エンコードされた 32 バイトのランダム値

import { env } from "cloudflare:workers";
import { HTTPException } from "hono/http-exception";
import { b64decode } from "./string";

// 例: openssl rand -base64 32 | npx wrangler secret put AES_ENCRYPT_KEY
let keyPromise: Promise<CryptoKey> | undefined;
export const getCryptoKey = () => {
  if (!env.AES_ENCRYPT_KEY) {
    throw new HTTPException(500, { message: "Encryption key is not configured" });
  }
  return (keyPromise ??= crypto.subtle
    .importKey("raw", b64decode(env.AES_ENCRYPT_KEY), "AES-GCM", false, ["encrypt", "decrypt"])
    .catch((err) => {
      keyPromise = undefined;
      throw err;
    }));
};
