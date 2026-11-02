import { vValidator } from '@hono/valibot-validator'
import { HTTPException } from 'hono/http-exception'
import type { ValidationTargets } from 'hono'
import type { GenericSchema, GenericSchemaAsync } from 'valibot'

export const hValidator = <
    T extends GenericSchema | GenericSchemaAsync,
    Target extends keyof ValidationTargets
>(target: Target, schema: T) =>
    vValidator(target, schema, (r) => {
        if (!r.success) throw new HTTPException(400, { message: "Bad Request", cause: r.issues })
    })