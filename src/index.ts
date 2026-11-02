import { Hono } from 'hono'
import { env } from 'cloudflare:workers'
import { authMiddleware } from './auth'
import { logger } from 'hono/logger'
import { HTTPException } from 'hono/http-exception'

const b64encode = (u8: Uint8Array) => btoa(String.fromCharCode(...u8))
const b64decode = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

// AES_ENCRYPT_KEY は base64 エンコードされた 32 バイトのランダム値
// 例: openssl rand -base64 32 | npx wrangler secret put AES_ENCRYPT_KEY
let keyPromise: Promise<CryptoKey> | undefined
const getCryptoKey = () => {
  if (!env.AES_ENCRYPT_KEY) {
    throw new HTTPException(500, { message: 'Encryption key is not configured' })
  }
  return (keyPromise ??= crypto.subtle.importKey(
    'raw',
    b64decode(env.AES_ENCRYPT_KEY),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  ))
}

const app = new Hono().get('/', (c) => {
  return c.text('Hello World!')
})
  .use(logger())
  .use(authMiddleware)
  .get('/check', (c) => {
    return c.json({
      success: true,
    })
  }).get('/:id', async (c) => {
    const id = c.req.param('id')

    // 暗号文(バイナリ)とIVをKVから取得
    const { value, metadata } = await env.KV.getWithMetadata<{ iv: string }>(id, 'arrayBuffer')
    if (!value || !metadata?.iv) {
      return c.json({ message: 'Not Found' }, 404)
    }

    // AES-GCMで復号化 (idをAADにして別キーへのすり替えを検出)
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(metadata.iv), additionalData: new TextEncoder().encode(id) },
      await getCryptoKey(),
      value,
    )

    return c.text(new TextDecoder().decode(decrypted))
  }).post('/:id', async (c) => {
    const id = c.req.param('id')
    const body = await c.req.text()
    if (!body) {
      return c.json({ message: 'Bad Request' }, 400)
    }

    // AES-GCMで暗号化
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(id) },
      await getCryptoKey(),
      new TextEncoder().encode(body),
    )

    // 暗号文はバイナリのまま、IVはbase64にしてmetadataへ保存
    await env.KV.put(id, encrypted, {
      metadata: { iv: b64encode(iv) },
    })

    return c.json({ success: true })
  }).onError((err, c) => {
    if (err instanceof HTTPException) {
      return c.json({ message: err.message, issues: err.cause }, err.status)
    }
    return c.json({ message: 'internal error' }, 500)
  })

export default app
