import { createMiddleware } from "hono/factory";
import * as v from "valibot"
import { every } from 'hono/combine'
import { vValidator } from "@hono/valibot-validator";
import { HTTPException } from "hono/http-exception";
import { env } from "cloudflare:workers";

const BEARER_PREFIX = "Bearer "

const tokenSchema = v.object({
    Authorization: v.pipe(
        v.string(),
        v.minLength(16),
        v.startsWith(BEARER_PREFIX)
    )
})

type ValidatedInput = {
    out: {
        header: v.InferOutput<typeof tokenSchema>
    }
}

const tokens = new Set<string>(
    env.AUTH_TOKENS?.split(",").map((t) => t.trim()).filter(Boolean) ?? []
)

const authMiddlewareHandler = createMiddleware<{}, string, ValidatedInput>(async (c, next) => {
    const token = c.req.valid("header").Authorization.slice(BEARER_PREFIX.length)
    if (!tokens.has(token)) {
        return c.text("Unauthorized", 401)
    }
    await next()
})

export const authMiddleware = every(vValidator("header", tokenSchema, (r) => {
    if (!r.success) throw new HTTPException(401, { message: "Unauthorized" })
}), authMiddlewareHandler)