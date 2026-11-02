import { Hono } from "hono";
import { env } from "cloudflare:workers";
import { authMiddleware } from "./auth";
import { logger } from "hono/logger";
import { HTTPException } from "hono/http-exception";
import { b64decode, b64encode } from "./utils/string";
import { getCryptoKey } from "./utils/crypto";
import { hValidator } from "./utils/validator";
import * as v from "valibot";

const generateKey = (key: string) => `secrets/${key}`;
const idValidatorSchema = v.object({
  id: v.pipe(v.string(), v.minLength(1), v.maxLength(64)),
});

const app = new Hono()
  .use(logger())
  .get("/", (c) => {
    return c.text("Hello World!");
  })
  .use(authMiddleware)
  .get("/check", (c) => {
    return c.json({
      success: true,
    });
  })
  .get("/secrets/:id", hValidator("param", idValidatorSchema), async (c) => {
    const id = c.req.param("id");

    // 暗号文(バイナリ)とIVをKVから取得
    const { value, metadata } = await env.KV.getWithMetadata<{ iv: string; v: number }>(
      generateKey(id),
      "arrayBuffer",
    );
    if (!value || !metadata?.iv) {
      return c.json({ message: "Not Found" }, 404);
    }

    // AES-GCMで復号化 (idをAADにして別キーへのすり替えを検出)
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64decode(metadata.iv), additionalData: new TextEncoder().encode(id) },
      await getCryptoKey(),
      value,
    );

    return c.text(new TextDecoder().decode(decrypted));
  })
  .post("/secrets/:id", hValidator("param", idValidatorSchema), async (c) => {
    const id = c.req.param("id");
    const body = await c.req.text();
    if (!body) {
      return c.json({ message: "Bad Request" }, 400);
    }

    // 既存の値がある場合は上書きしない
    const existing = await env.KV.get(generateKey(id), "stream");
    if (existing) {
      void existing.cancel(); // ストリームを閉じる
      return c.json({ message: "Conflict" }, 409);
    }

    // AES-GCMで暗号化
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(id) },
      await getCryptoKey(),
      new TextEncoder().encode(body),
    );

    // 暗号文はバイナリのまま、IVはbase64にしてmetadataへ保存
    await env.KV.put(generateKey(id), encrypted, {
      metadata: { iv: b64encode(iv), v: 1 },
    });

    return c.json({ success: true }, 201);
  })
  .delete("/secrets/:id", hValidator("param", idValidatorSchema), async (c) => {
    const id = c.req.param("id");
    await env.KV.delete(generateKey(id));
    return c.json({ success: true });
  })
  .onError((err, c) => {
    console.error(err);
    if (err instanceof HTTPException) {
      return c.json({ message: err.message, issues: err.cause }, err.status);
    }
    return c.json({ message: "internal error" }, 500);
  });

export default app;
