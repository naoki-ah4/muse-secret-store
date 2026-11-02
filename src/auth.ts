import { createMiddleware } from "hono/factory";
import * as v from "valibot"
import { every } from 'hono/combine'
import { validator } from "hono/validator";
import { hValidator } from "./utils/validator";
import { vValidator } from "@hono/valibot-validator";
import { HTTPException } from "hono/http-exception";

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

const authMiddlewareHandler = createMiddleware<{}, string, ValidatedInput>(async (c, next) => {
    const token = c.req.valid("header").Authorization.slice(BEARER_PREFIX.length)
    if (token !== "my-secret-token") {
        return c.text("Unauthorized", 401)
    }
    await next()
})

export const authMiddleware = every(vValidator("header", tokenSchema, (r) => {
    if (!r.success) throw new HTTPException(401, { message: "Unauthorized" })
}), authMiddlewareHandler)