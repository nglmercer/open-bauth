// tests/middleware/bun.adapter.test.ts
// Tests for Bun native HTTP middleware adapter

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
    createBunMiddleware,
    composeBunMiddleware,
    createBunServer,
    type BunAuthRequest,
    type BunHandler,
} from "../../src/middleware/adapters/bun.adapter";
import type { AuthServices } from "../../src/middleware/core/types";
import {
    setupMiddlewareTest,
    teardownMiddlewareTest,
    type MiddlewareTestContext,
} from "./setup";

describe("Bun Adapter - Middleware", () => {
    let context: MiddlewareTestContext | undefined;
    let services: AuthServices;
    let testToken: string;
    let testUserId: number | string;

    beforeAll(async () => {
        context = await setupMiddlewareTest();
        services = context.services;
        testUserId = context.testUsers.moderator.id;
        testToken = context.testUsers.moderator.token;
    });

    afterAll(() => {
        teardownMiddlewareTest(context);
    });

    // Helper to simulate a request
    const createRequest = (
        path: string,
        options: { headers?: Record<string, string> } = {}
    ): BunAuthRequest => {
        const headers = new Headers(options.headers || {});
        return new Request(`http://localhost${path}`, {
            headers,
        }) as BunAuthRequest;
    };

    test("requireAuth - should allow authenticated request", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(
                JSON.stringify({
                    message: "success",
                    userId: req.auth?.user?.id,
                }),
                { headers: { "Content-Type": "application/json" } }
            );
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            return await middleware.requireAuth()(req, handler);
        };

        const request = createRequest("/protected", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.userId).toBe(testUserId);
    });

    test("requireAuth - should reject request without token", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "success" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            return await middleware.requireAuth()(req, handler);
        };

        const request = createRequest("/protected");
        const response = await wrappedHandler(request);

        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("Authorization header is missing");
    });

    test("requireAuth - should reject request with invalid token", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "success" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            return await middleware.requireAuth()(req, handler);
        };

        const request = createRequest("/protected", {
            headers: {
                Authorization: "Bearer invalid-token",
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(401);

        const body = await response.json();
        expect(body.error).toBe("Invalid or expired token");
    });

    test("optionalAuth - should allow request without token", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(
                JSON.stringify({
                    message: "success",
                    isAuthenticated: req.auth?.isAuthenticated || false,
                }),
                { headers: { "Content-Type": "application/json" } }
            );
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            return await middleware.optionalAuth()(req, handler);
        };

        const request = createRequest("/public");
        const response = await wrappedHandler(request);

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.isAuthenticated).toBe(false);
    });

    test("optionalAuth - should authenticate when token is present", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(
                JSON.stringify({
                    message: "success",
                    isAuthenticated: req.auth?.isAuthenticated || false,
                    userId: req.auth?.user?.id,
                }),
                { headers: { "Content-Type": "application/json" } }
            );
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            return await middleware.optionalAuth()(req, handler);
        };

        const request = createRequest("/public", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.isAuthenticated).toBe(true);
        expect(body.userId).toBe(testUserId);
    });

    test("requireRole - should allow user with required role", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "moderator access" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            const authMiddleware = middleware.requireAuth();
            const roleMiddleware = middleware.requireRole(["moderator"]);
            return await authMiddleware(req, async (r) => roleMiddleware(r, handler));
        };

        const request = createRequest("/moderate", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("moderator access");
    });

    test("requireRole - should deny user without required role", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "admin access" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            const authMiddleware = middleware.requireAuth();
            const roleMiddleware = middleware.requireRole(["admin"]);
            return await authMiddleware(req, async (r) => roleMiddleware(r, handler));
        };

        const request = createRequest("/admin", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(403);

        const body = await response.json();
        expect(body.error).toBe("Access denied. Required role not found.");
    });

    test("requirePermission - should allow user with required permission", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "moderate posts" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            const authMiddleware = middleware.requireAuth();
            const permMiddleware = middleware.requirePermission(["posts:moderate"]);
            return await authMiddleware(req, async (r) => permMiddleware(r, handler));
        };

        const request = createRequest("/posts/moderate", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("moderate posts");
    });

    test("requirePermission - should deny user without required permission", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "delete posts" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const wrappedHandler = async (req: BunAuthRequest) => {
            const authMiddleware = middleware.requireAuth();
            const permMiddleware = middleware.requirePermission(["posts:delete"]);
            return await authMiddleware(req, async (r) => permMiddleware(r, handler));
        };

        const request = createRequest("/posts/delete", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await wrappedHandler(request);
        expect(response.status).toBe(403);

        const body = await response.json();
        expect(body.error).toBe("Insufficient permissions");
    });

    test("composeBunMiddleware - should compose multiple middleware", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(JSON.stringify({ message: "fully secured" }), {
                headers: { "Content-Type": "application/json" },
            });
        };

        const composed = composeBunMiddleware(
            middleware.requireAuth(),
            middleware.requireRole(["moderator"]),
            middleware.requirePermission(["posts:moderate"])
        );

        const request = createRequest("/secure", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await composed(request, handler);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("fully secured");
    });

    test("createBunServer - should create server with middleware", async () => {
        const middleware = createBunMiddleware(services);

        const handler: BunHandler = async (req) => {
            return new Response(
                JSON.stringify({
                    message: "hello",
                    user: req.auth?.user?.id,
                }),
                { headers: { "Content-Type": "application/json" } }
            );
        };

        const server = createBunServer(handler);
        server.use(middleware.requireAuth());

        const composedHandler = server.getHandler();

        const request = createRequest("/test", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        const response = await composedHandler(request);
        expect(response.status).toBe(200);

        const body = await response.json();
        expect(body.message).toBe("hello");
        expect(body.user).toBe(testUserId);
    });
});
