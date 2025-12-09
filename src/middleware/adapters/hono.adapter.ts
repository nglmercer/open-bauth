// src/middleware/adapters/hono.adapter.ts
// Hono-specific middleware adapter

import type { Context, Next } from "hono";
import type { AuthContext, PermissionOptions } from "../../types/auth";
import type {
    AuthServices,
    AuthRequest,
    MiddlewareAdapter,
    AuthOptions,
    ContextExtractor,
} from "../core/types";
import {
    authenticateRequest,
    authorizePermissions,
    authorizeRoles,
} from "../core/auth.core";

/**
 * Context extractor for Hono framework
 */
export class HonoContextExtractor implements ContextExtractor<Context> {
    extractAuthRequest(ctx: Context): AuthRequest {
        // Extract headers from Hono context
        const headers: Record<string, string | undefined> = {};

        // Get all headers from Hono request
        const honoHeaders = ctx.req.header();
        for (const key in honoHeaders) {
            headers[key.toLowerCase()] = honoHeaders[key];
        }

        return {
            headers,
            method: ctx.req.method,
            url: ctx.req.url,
        };
    }

    setAuthContext(ctx: Context, authContext: AuthContext): void {
        ctx.set("auth", authContext);
    }

    getAuthContext(ctx: Context): AuthContext | undefined {
        return ctx.get("auth");
    }
}

/**
 * Hono middleware adapter implementation
 */
export class HonoMiddlewareAdapter
    implements MiddlewareAdapter<Context, Next, Promise<Response | void>> {
    private services: AuthServices;
    private extractor: HonoContextExtractor;

    constructor(services: AuthServices) {
        this.services = services;
        this.extractor = new HonoContextExtractor();
    }

    /**
     * Require authentication middleware
     */
    requireAuth(options: AuthOptions = { required: true }): (ctx: Context, next: Next) => Promise<Response | void> {
        return async (ctx: Context, next: Next) => {
            const request = this.extractor.extractAuthRequest(ctx);

            // Check if authentication is required
            const required = options.required !== false;

            // If optional and no authorization header, continue with empty context
            if (!required && !request.headers["authorization"]) {
                this.extractor.setAuthContext(ctx, {
                    user: undefined,
                    isAuthenticated: false,
                    permissions: [],
                });
                await next();
                return;
            }

            // Authenticate the request
            const result = await authenticateRequest(request, this.services, required);

            if (result.success && result.context) {
                // Set auth context in Hono context
                this.extractor.setAuthContext(ctx, result.context);
                await next();
                return;
            }

            // Authentication failed
            if (required) {
                return ctx.json(
                    { error: result.error },
                    (result.statusCode as 401) || 401
                );
            } else {
                // Optional auth failed, continue with empty context
                this.extractor.setAuthContext(ctx, {
                    user: undefined,
                    isAuthenticated: false,
                    permissions: [],
                });
                await next();
            }
        };
    }

    /**
     * Optional authentication middleware
     */
    optionalAuth(): (ctx: Context, next: Next) => Promise<Response | void> {
        return this.requireAuth({ required: false });
    }

    /**
     * Require specific roles middleware
     */
    requireRole(roles: string[]): (ctx: Context, next: Next) => Promise<Response | void> {
        return async (ctx: Context, next: Next) => {
            const authContext = this.extractor.getAuthContext(ctx);

            const result = await authorizeRoles(authContext, roles);

            if (result.allowed) {
                await next();
                return;
            }

            return ctx.json(
                { error: result.error },
                (result.statusCode as 401 | 403) || 403
            );
        };
    }

    /**
     * Require specific permissions middleware
     */
    requirePermission(
        permissions: string[],
        options: PermissionOptions = { requireAll: false }
    ): (ctx: Context, next: Next) => Promise<Response | void> {
        return async (ctx: Context, next: Next) => {
            const authContext = this.extractor.getAuthContext(ctx);

            const result = await authorizePermissions(authContext, permissions, options);

            if (result.allowed) {
                await next();
                return;
            }

            return ctx.json(
                { error: result.error },
                (result.statusCode as 401 | 403) || 403
            );
        };
    }
}

/**
 * Factory function to create Hono middleware adapter
 */
export function createHonoMiddleware(services: AuthServices): HonoMiddlewareAdapter {
    return new HonoMiddlewareAdapter(services);
}

/**
 * Legacy compatibility - factory functions for individual middleware
 */
export function createAuthMiddlewareForHono(
    services: AuthServices,
    required: boolean = true
): (ctx: Context, next: Next) => Promise<Response | void> {
    const adapter = new HonoMiddlewareAdapter(services);
    return adapter.requireAuth({ required });
}

export function createPermissionMiddlewareForHono(
    requiredPermissions: string[],
    options: PermissionOptions = { requireAll: false }
): (ctx: Context, next: Next) => Promise<Response | void> {
    return async (ctx: Context, next: Next) => {
        const authContext: AuthContext | undefined = ctx.get("auth");
        const result = await authorizePermissions(authContext, requiredPermissions, options);

        if (result.allowed) {
            await next();
            return;
        }

        return ctx.json(
            { error: result.error },
            (result.statusCode as 401 | 403) || 403
        );
    };
}

export function createRoleMiddlewareForHono(
    requiredRoles: string[]
): (ctx: Context, next: Next) => Promise<Response | void> {
    return async (ctx: Context, next: Next) => {
        const authContext: AuthContext | undefined = ctx.get("auth");
        const result = await authorizeRoles(authContext, requiredRoles);

        if (result.allowed) {
            await next();
            return;
        }

        return ctx.json(
            { error: result.error },
            (result.statusCode as 401 | 403) || 403
        );
    };
}
