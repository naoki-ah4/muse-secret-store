import { createMiddleware } from "hono/factory";
import * as v from "valibot";
import { every } from "hono/combine";
import { vValidator } from "@hono/valibot-validator";
import { HTTPException } from "hono/http-exception";
import { env } from "cloudflare:workers";
import { equalTimeCompare } from "./utils/string";

const BEARER_PREFIX = "Bearer ";

const tokenSchema = v.object({
  authorization: v.pipe(v.string(), v.minLength(16), v.startsWith(BEARER_PREFIX)),
});

type ValidatedInput = {
  out: {
    header: v.InferOutput<typeof tokenSchema>;
  };
};

const checkTokens = async (token: string) => {
  const tokens =
    (await env.KV.get<string[]>("auth_tokens", {
      type: "json",
      cacheTtl: 60,
    }).then((v) => v?.map((t) => t.trim()).filter(Boolean))) ?? [];

  for (const t of tokens) {
    if (equalTimeCompare(t, token)) {
      return true;
    }
  }

  return false;
};

const authMiddlewareHandler = createMiddleware<{}, string, ValidatedInput>(async (c, next) => {
  const token = c.req.valid("header").authorization.slice(BEARER_PREFIX.length);
  if (!(await checkTokens(token))) {
    return c.text("Unauthorized", 401);
  }
  c.header("Cache-Control", "no-store");
  await next();
});

export const authMiddleware = every(
  vValidator("header", tokenSchema, (r) => {
    if (!r.success) throw new HTTPException(401, { message: "Unauthorized" });
  }),
  authMiddlewareHandler,
);
