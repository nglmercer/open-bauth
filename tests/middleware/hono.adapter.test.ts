// tests/middleware/hono.adapter.test.ts
// Tests for Hono middleware adapter

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Hono } from "hono";
import { createHonoMiddleware } from "../../src/middleware/adapters/hono.adapter";
import type { AuthServices } from "../../src/middleware/core/types";
import {
    setupMiddlewareTest,
    teardownMiddlewareTest,
    type MiddlewareTestContext,
} from "./setup";

describe("Hono Adapter - Middleware", () => {
    let context: MiddlewareTestContext | undefined;
    let services: AuthServices;
    let testToken: string;
    let testUserId: number | string;

    beforeAll(async () => {
        context = await setupMiddlewareTest();
        services = context.services;
        testUserId = context.testUsers.admin.id;
        testToken = context.testUsers.admin.token;
    });

    afterAll(() => {
        teardownMiddlewareTest(context);
    });

    test("requireAuth - should allow authenticated request", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/protected",
            middleware.requireAuth(),
            (c) => c.json({ message: "success", userId: c.get("auth")?.user?.id })
        );

        const response = await app.request("/protected", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.userId).toBe(testUserId);
    });

    test("requireAuth - should reject request without token", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get("/protected", middleware.requireAuth(), (c) =>
            c.json({ message: "success" })
        );

        const response = await app.request("/protected");

        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("Authorization header is missing");
    });

    test("requireAuth - should reject request with invalid token", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get("/protected", middleware.requireAuth(), (c) =>
            c.json({ message: "success" })
        );

        const response = await app.request("/protected", {
            headers: {
                Authorization: "Bearer invalid-token",
            },
        });

        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("Invalid or expired token");
    });

    test("optionalAuth - should allow request without token", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get("/public", middleware.optionalAuth(), (c) => {
            const auth = c.get("auth");
            return c.json({
                message: "success",
                isAuthenticated: auth?.isAuthenticated || false,
            });
        });

        const response = await app.request("/public");

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.isAuthenticated).toBe(false);
    });

    test("optionalAuth - should authenticate when token is present", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get("/public", middleware.optionalAuth(), (c) => {
            const auth = c.get("auth");
            return c.json({
                message: "success",
                isAuthenticated: auth?.isAuthenticated || false,
                userId: auth?.user?.id,
            });
        });

        const response = await app.request("/public", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("success");
        expect(body.isAuthenticated).toBe(true);
        expect(body.userId).toBe(testUserId);
    });

    test("requireRole - should allow user with required role", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/admin",
            middleware.requireAuth(),
            middleware.requireRole(["admin"]),
            (c) => c.json({ message: "admin access" })
        );

        const response = await app.request("/admin", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("admin access");
    });

    test("requireRole - should deny user without required role", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/superadmin",
            middleware.requireAuth(),
            middleware.requireRole(["superadmin"]),
            (c) => c.json({ message: "superadmin access" })
        );

        const response = await app.request("/superadmin", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(403);
        const body = await response.json();
        expect(body.error).toBe("Access denied. Required role not found.");
    });

    test("requirePermission - should allow user with required permission", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/manage",
            middleware.requireAuth(),
            middleware.requirePermission(["admin:manage"]),
            (c) => c.json({ message: "manage access" })
        );

        const response = await app.request("/manage", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("manage access");
    });

    test("requirePermission - should deny user without required permission", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/delete",
            middleware.requireAuth(),
            middleware.requirePermission(["admin:delete"]),
            (c) => c.json({ message: "delete access" })
        );

        const response = await app.request("/delete", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(403);
        const body = await response.json();
        expect(body.error).toBe("Insufficient permissions");
    });

    test("requirePermission - should allow with any permission (requireAll: false)", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/any-perm",
            middleware.requireAuth(),
            middleware.requirePermission(["admin:manage", "admin:delete"], {
                requireAll: false,
            }),
            (c) => c.json({ message: "access granted" })
        );

        const response = await app.request("/any-perm", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
    });

    test("requirePermission - should require all permissions (requireAll: true)", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/all-perms",
            middleware.requireAuth(),
            middleware.requirePermission(["admin:manage", "admin:delete"], {
                requireAll: true,
            }),
            (c) => c.json({ message: "access granted" })
        );

        const response = await app.request("/all-perms", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(403);
        const body = await response.json();
        expect(body.error).toBe("Insufficient permissions");
    });

    test("chained middleware - auth + role + permission", async () => {
        const app = new Hono();
        const middleware = createHonoMiddleware(services);

        app.get(
            "/secure",
            middleware.requireAuth(),
            middleware.requireRole(["admin"]),
            middleware.requirePermission(["admin:manage"]),
            (c) => c.json({ message: "fully secured" })
        );

        const response = await app.request("/secure", {
            headers: {
                Authorization: `Bearer ${testToken}`,
            },
        });

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.message).toBe("fully secured");
    });
});
