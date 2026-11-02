import { Hono } from 'hono'
import { env } from 'cloudflare:workers'
import { authMiddleware } from './auth'
import { logger } from 'hono/logger'
import { HTTPException } from 'hono/http-exception'
import { b64decode, b64encode } from './utils/string'
import { getCryptoKey } from './utils/crypto'


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
