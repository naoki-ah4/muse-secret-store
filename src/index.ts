import { Hono } from 'hono'
import { env } from 'cloudflare:workers'
import { authMiddleware } from './auth'
import { logger } from 'hono/logger'
import { HTTPException } from 'hono/http-exception'

declare module 'hono' {
  interface ContextVariableMap {
  }
}

const app = new Hono().get('/', (c) => {
  return c.text('Hello World!')
}).use(logger()).use(authMiddleware).get('/health', (c) => {
  return c.json({
    success: true,
  })
}).get("/:id", async (c) => {
  // 値をKVから取得
  const { value: cryptedValue, metadata } = await env.KV.getWithMetadata<{
    iv: string
  }>(c.req.param("id"))
  if (!cryptedValue || !metadata?.iv) {
    return c.json({ message: "Not Found" }, 404)
  }

  // キーをsecretから取得
  const key = env.AES_ENCRYPT_KEY;
  if (!key) {
    return c.json({ message: "Internal Server Error" }, 503)
  }

  // AES-GCMで復号化
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  )

  const iv = new TextEncoder().encode(metadata.iv)
  const decryptedValue = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new Uint8Array(new TextEncoder().encode(cryptedValue))
  )

  // 復号化した値を文字列に変換
  const decryptedText = new TextDecoder().decode(decryptedValue);
  return c.text(decryptedText)
}).post("/:id", async (c) => {
  const body = await c.req.text()
  if (!body) {
    return c.json({ message: "Bad Request" }, 400)
  }

  // キーをsecretから取得
  const key = env.AES_ENCRYPT_KEY;
  if (!key) {
    return c.json({ message: "Internal Server Error" }, 503)
  }

  // AES-GCMで暗号化
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encryptedValue = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new TextEncoder().encode(body)
  )

  // 暗号化した値を文字列に変換
  const encryptedText = new TextDecoder().decode(encryptedValue);

  // KVに保存
  await env.KV.put(c.req.param("id"), encryptedText, {
    metadata: {
      iv: new TextDecoder().decode(iv)
    }
  })

  return c.json({ success: true })
}).onError((err, c) => {
  if (err instanceof HTTPException) {
    return c.json({ message: err.message, issues: err.cause }, err.status)
  }
  return c.json({ message: 'internal error' }, 500)
})

export default app
