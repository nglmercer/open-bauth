// src/middleware/adapters/bun.adapter.ts
// Bun native HTTP server middleware adapter

import type { Server, ServerWebSocket } from "bun";
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
 * Extended Request type with auth context for Bun
 */
export interface BunAuthRequest extends Request {
    auth?: AuthContext;
}

/**
 * Bun handler type
 */
export type BunHandler = (request: BunAuthRequest) => Response | Promise<Response>;

/**
 * Middleware function type for Bun - always returns Promise for consistency
 */
export type BunMiddleware = (
    request: BunAuthRequest,
    next: BunHandler
) => Promise<Response>;

/**
 * Context extractor for Bun native HTTP
 */
export class BunContextExtractor implements ContextExtractor<BunAuthRequest> {
    extractAuthRequest(request: BunAuthRequest): AuthRequest {
        const headers: Record<string, string | undefined> = {};

        // Extract all headers from Bun Request
        request.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });

        return {
            headers,
            method: request.method,
            url: request.url,
        };
    }

    setAuthContext(request: BunAuthRequest, authContext: AuthContext): void {
        request.auth = authContext;
    }

    getAuthContext(request: BunAuthRequest): AuthContext | undefined {
        return request.auth;
    }
}

/**
 * Bun middleware adapter implementation
 */
export class BunMiddlewareAdapter
    implements MiddlewareAdapter<BunAuthRequest, BunHandler, Promise<Response>> {
    private services: AuthServices;
    private extractor: BunContextExtractor;

    constructor(services: AuthServices) {
        this.services = services;
        this.extractor = new BunContextExtractor();
    }

    /**
     * Require authentication middleware
     */
    requireAuth(options: AuthOptions = { required: true }): BunMiddleware {
        return async (request: BunAuthRequest, next: BunHandler) => {
            const authRequest = this.extractor.extractAuthRequest(request);
            const required = options.required !== false;

            // If optional and no authorization header, continue with empty context
            if (!required && !authRequest.headers["authorization"]) {
                this.extractor.setAuthContext(request, {
                    user: undefined,
                    isAuthenticated: false,
                    permissions: [],
                });
                return next(request);
            }

            // Authenticate the request
            const result = await authenticateRequest(authRequest, this.services, required);

            if (result.success && result.context) {
                // Set auth context in request
                this.extractor.setAuthContext(request, result.context);
                return next(request);
            }

            // Authentication failed
            if (required) {
                return new Response(
                    JSON.stringify({ error: result.error }),
                    {
                        status: result.statusCode || 401,
                        headers: { "Content-Type": "application/json" },
                    }
                );
            } else {
                // Optional auth failed, continue with empty context
                this.extractor.setAuthContext(request, {
                    user: undefined,
                    isAuthenticated: false,
                    permissions: [],
                });
                return next(request);
            }
        };
    }

    /**
     * Optional authentication middleware
     */
    optionalAuth(): BunMiddleware {
        return this.requireAuth({ required: false });
    }

    /**
     * Require specific roles middleware
     */
    requireRole(roles: string[]): BunMiddleware {
        return async (request: BunAuthRequest, next: BunHandler) => {
            const authContext = this.extractor.getAuthContext(request);
            const result = await authorizeRoles(authContext, roles);

            if (result.allowed) {
                return next(request);
            }

            return new Response(
                JSON.stringify({ error: result.error }),
                {
                    status: result.statusCode || 403,
                    headers: { "Content-Type": "application/json" },
                }
            );
        };
    }

    /**
     * Require specific permissions middleware
     */
    requirePermission(
        permissions: string[],
        options: PermissionOptions = { requireAll: false }
    ): BunMiddleware {
        return async (request: BunAuthRequest, next: BunHandler) => {
            const authContext = this.extractor.getAuthContext(request);
            const result = await authorizePermissions(authContext, permissions, options);

            if (result.allowed) {
                return next(request);
            }

            return new Response(
                JSON.stringify({ error: result.error }),
                {
                    status: result.statusCode || 403,
                    headers: { "Content-Type": "application/json" },
                }
            );
        };
    }
}

/**
 * Factory function to create Bun middleware adapter
 */
export function createBunMiddleware(services: AuthServices): BunMiddlewareAdapter {
    return new BunMiddlewareAdapter(services);
}

/**
 * Helper to compose multiple Bun middleware
 */
export function composeBunMiddleware(
    ...middlewares: BunMiddleware[]
): BunMiddleware {
    return async (request: BunAuthRequest, finalHandler: BunHandler) => {
        let index = 0;

        const next: BunHandler = async (req: BunAuthRequest) => {
            if (index >= middlewares.length) {
                return finalHandler(req);
            }

            const middleware = middlewares[index++];
            return middleware(req, next);
        };

        return next(request);
    };
}

/**
 * Helper to create a Bun server with middleware support
 */
export interface BunServerWithMiddleware {
    /**
     * Add global middleware to all routes
     */
    use(...middlewares: BunMiddleware[]): void;

    /**
     * Get the composed handler for Bun.serve
     */
    getHandler(): (request: Request) => Response | Promise<Response>;

    /**
     * Get the Bun server instance (after calling serve)
     */
    getServer(): Server<unknown> | undefined;

    /**
     * Start the server
     */
    serve(options: {
        port?: number;
        hostname?: string;
        development?: boolean;
    }): Server<unknown>;
}

export function createBunServer(
    handler: BunHandler
): BunServerWithMiddleware {
    const middlewares: BunMiddleware[] = [];
    let server: Server<unknown> | undefined;

    return {
        use(...mws: BunMiddleware[]) {
            middlewares.push(...mws);
        },

        getHandler() {
            const composedMiddleware = composeBunMiddleware(...middlewares);
            return (request: Request) => {
                const bunRequest = request as BunAuthRequest;
                return composedMiddleware(bunRequest, handler);
            };
        },

        getServer() {
            return server;
        },

        serve(options = {}) {
            const composedHandler = this.getHandler();
            server = Bun.serve({
                port: options.port || 3000,
                hostname: options.hostname || "localhost",
                development: options.development !== false,
                fetch: composedHandler,
            });
            return server;
        },
    };
}
