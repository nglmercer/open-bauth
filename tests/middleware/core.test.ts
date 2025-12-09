// tests/middleware/core.test.ts
// Tests for core middleware logic

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
    authenticateRequest,
    authorizePermissions,
    authorizeRoles,
} from "../../src/middleware/core/auth.core";
import type { AuthRequest, AuthServices } from "../../src/middleware/core/types";
import type { AuthContext } from "../../src/types/auth";
import {
    setupMiddlewareTest,
    teardownMiddlewareTest,
    deactivateUser,
    reactivateUser,
    type MiddlewareTestContext,
} from "./setup";

describe("Middleware Core - Authentication", () => {
    let context: MiddlewareTestContext | undefined;
    let services: AuthServices;
    let testUserId: number | string;
    let testToken: string;

    beforeAll(async () => {
        context = await setupMiddlewareTest();
        services = context.services;
        testUserId = context.testUsers.user.id;
        testToken = context.testUsers.user.token;
    });

    afterAll(() => {
        teardownMiddlewareTest(context);
    });

    test("should authenticate valid request with token", async () => {
        const request: AuthRequest = {
            headers: {
                authorization: `Bearer ${testToken}`,
            },
        };

        const result = await authenticateRequest(request, services, true);

        expect(result.success).toBe(true);
        expect(result.context).toBeDefined();
        expect(result.context?.isAuthenticated).toBe(true);
        expect(result.context?.user?.id).toBe(testUserId);
        expect(result.context?.permissions).toContain("users:read");
    });

    test("should fail authentication with missing header", async () => {
        const request: AuthRequest = {
            headers: {},
        };

        const result = await authenticateRequest(request, services, true);

        expect(result.success).toBe(false);
        expect(result.error).toBe("Authorization header is missing");
        expect(result.statusCode).toBe(401);
    });

    test("should fail authentication with invalid token", async () => {
        const request: AuthRequest = {
            headers: {
                authorization: "Bearer invalid-token",
            },
        };

        const result = await authenticateRequest(request, services, true);

        expect(result.success).toBe(false);
        expect(result.error).toBe("Invalid or expired token");
        expect(result.statusCode).toBe(401);
    });

    test("should fail authentication with malformed header", async () => {
        const request: AuthRequest = {
            headers: {
                authorization: "InvalidFormat",
            },
        };

        const result = await authenticateRequest(request, services, true);

        expect(result.success).toBe(false);
        expect(result.error).toBe("Bearer token is missing or malformed");
        expect(result.statusCode).toBe(401);
    });

    test("should allow optional authentication with no token", async () => {
        const request: AuthRequest = {
            headers: {},
        };

        const result = await authenticateRequest(request, services, false);

        expect(result.success).toBe(true);
        expect(result.context?.isAuthenticated).toBe(false);
        expect(result.context?.user).toBeUndefined();
    });

    test("should authenticate optional request with valid token", async () => {
        const request: AuthRequest = {
            headers: {
                authorization: `Bearer ${testToken}`,
            },
        };

        const result = await authenticateRequest(request, services, false);

        expect(result.success).toBe(true);
        expect(result.context?.isAuthenticated).toBe(true);
        expect(result.context?.user?.id).toBe(testUserId);
    });

    test("should fail authentication for inactive user", async () => {
        // Deactivate user
        deactivateUser(context, testUserId);

        const request: AuthRequest = {
            headers: {
                authorization: `Bearer ${testToken}`,
            },
        };

        const result = await authenticateRequest(request, services, true);

        expect(result.success).toBe(false);
        expect(result.error).toBe("User not found or is inactive");
        expect(result.statusCode).toBe(401);

        // Reactivate user for other tests
        reactivateUser(context, testUserId);
    });
});

describe("Middleware Core - Authorization (Permissions)", () => {
    test("should authorize user with required permission", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: ["users:read", "users:write"],
        };

        const result = await authorizePermissions(authContext, ["users:read"]);

        expect(result.allowed).toBe(true);
    });

    test("should authorize user with any of required permissions", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: ["users:read"],
        };

        const result = await authorizePermissions(
            authContext,
            ["users:read", "users:write"],
            { requireAll: false }
        );

        expect(result.allowed).toBe(true);
    });

    test("should require all permissions when requireAll is true", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: ["users:read"],
        };

        const result = await authorizePermissions(
            authContext,
            ["users:read", "users:write"],
            { requireAll: true }
        );

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Insufficient permissions");
        expect(result.statusCode).toBe(403);
    });

    test("should deny user without required permission", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: ["users:read"],
        };

        const result = await authorizePermissions(authContext, ["admin:write"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Insufficient permissions");
        expect(result.statusCode).toBe(403);
    });

    test("should deny unauthenticated user", async () => {
        const authContext: AuthContext = {
            user: undefined,
            isAuthenticated: false,
            permissions: [],
        };

        const result = await authorizePermissions(authContext, ["users:read"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Authentication required");
        expect(result.statusCode).toBe(401);
    });

    test("should deny undefined context", async () => {
        const result = await authorizePermissions(undefined, ["users:read"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Authentication required");
        expect(result.statusCode).toBe(401);
    });
});

describe("Middleware Core - Authorization (Roles)", () => {
    test("should authorize user with required role", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [
                    { id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true },
                    { id: 2, name: "admin", created_at: new Date(), updated_at: new Date(), is_active: true },
                ],
            },
            isAuthenticated: true,
            permissions: [],
        };

        const result = await authorizeRoles(authContext, ["admin"]);

        expect(result.allowed).toBe(true);
    });

    test("should authorize user with any of required roles", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: [],
        };

        const result = await authorizeRoles(authContext, ["admin", "user"]);

        expect(result.allowed).toBe(true);
    });

    test("should deny user without required role", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: [{ id: 1, name: "user", created_at: new Date(), updated_at: new Date(), is_active: true }],
            },
            isAuthenticated: true,
            permissions: [],
        };

        const result = await authorizeRoles(authContext, ["admin"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Access denied. Required role not found.");
        expect(result.statusCode).toBe(403);
    });

    test("should deny unauthenticated user", async () => {
        const authContext: AuthContext = {
            user: undefined,
            isAuthenticated: false,
            permissions: [],
        };

        const result = await authorizeRoles(authContext, ["user"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Authentication required");
        expect(result.statusCode).toBe(401);
    });

    test("should deny user without roles", async () => {
        const authContext: AuthContext = {
            user: {
                id: 1,
                email: "test@example.com",
                first_name: "Test",
                last_name: "User",
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                roles: undefined,
            },
            isAuthenticated: true,
            permissions: [],
        };

        const result = await authorizeRoles(authContext, ["user"]);

        expect(result.allowed).toBe(false);
        expect(result.error).toBe("Authentication required");
        expect(result.statusCode).toBe(401);
    });
});
