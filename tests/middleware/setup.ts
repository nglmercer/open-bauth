// tests/middleware/setup.ts
// Shared setup utilities for middleware tests

import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { JWTService } from "../../src/services/jwt";
import { AuthService } from "../../src/services/auth";
import { PermissionService } from "../../src/services/permissions";
import type { AuthServices } from "../../src/middleware/core/types";
import { TEST_JWT_SECRET } from "../setup";

export interface MiddlewareTestContext {
    db: Database;
    dbInitializer: DatabaseInitializer;
    services: AuthServices;
    testUsers: {
        user: TestUser;
        admin: TestUser;
        moderator: TestUser;
    };
}

export interface TestUser {
    id: number | string;
    username: string;
    email: string;
    token: string;
    roleName: string;
}

/**
 * Creates and initializes a complete test environment for middleware tests
 * @returns MiddlewareTestContext with database, services, and test users
 */
export async function setupMiddlewareTest(): Promise<MiddlewareTestContext> {
    // Create in-memory database
    const db = new Database(":memory:");
    const dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize();
    await dbInitializer.seedDefaults();

    // Initialize services
    const jwtService = new JWTService(TEST_JWT_SECRET);
    const authService = new AuthService(dbInitializer, jwtService);
    const permissionService = new PermissionService(dbInitializer);

    const services: AuthServices = {
        jwtService,
        authService,
        permissionService,
    };

    // Create test users with different roles
    const testUsers = {
        user: await createTestUser(
            authService,
            permissionService,
            dbInitializer,
            {
                first_name: "Test",
                last_name: "User",
                username: "testuser_middleware",
                email: "testmiddleware@example.com",
                password: "TestPassword123!",
            },
            "user",
            [
                {
                    name: "users:read",
                    resource: "users",
                    action: "read",
                    description: "Read users",
                },
            ]
        ),
        admin: await createTestUser(
            authService,
            permissionService,
            dbInitializer,
            {
                first_name: "Admin",
                last_name: "User",
                username: "adminuser_middleware",
                email: "adminmiddleware@example.com",
                password: "AdminPassword123!",
            },
            "admin",
            [
                {
                    name: "admin:manage",
                    resource: "admin",
                    action: "manage",
                    description: "Admin management",
                },
            ]
        ),
        moderator: await createTestUser(
            authService,
            permissionService,
            dbInitializer,
            {
                first_name: "Moderator",
                last_name: "User",
                username: "moderatoruser_middleware",
                email: "moderatormiddleware@example.com",
                password: "ModeratorPassword123!",
            },
            "moderator",
            [
                {
                    name: "posts:moderate",
                    resource: "posts",
                    action: "moderate",
                    description: "Moderate posts",
                },
            ]
        ),
    };

    return {
        db,
        dbInitializer,
        services,
        testUsers,
    };
}

/**
 * Cleans up test environment
 * @param context MiddlewareTestContext to clean up
 */
export function teardownMiddlewareTest(context: MiddlewareTestContext | undefined): void {
    if (context?.db) {
        context.db.close();
    }
}

/**
 * Helper to create a test user with a specific role and permissions
 */
async function createTestUser(
    authService: AuthService,
    permissionService: PermissionService,
    dbInitializer: DatabaseInitializer,
    userData: {
        first_name: string;
        last_name: string;
        username: string;
        email: string;
        password: string;
    },
    roleName: string,
    permissions: Array<{
        name: string;
        resource: string;
        action: string;
        description: string;
    }>
): Promise<TestUser> {
    // Register user
    const registerResult = await authService.register(userData);
    if (!registerResult.success || !registerResult.user || !registerResult.token) {
        throw new Error(`Failed to create test user: ${userData.username}`);
    }

    const userId = registerResult.user.id;
    const token = registerResult.token;

    // Get or create role
    let role = await permissionService.findRoleByName(roleName);
    if (!role) {
        const roleResult = await permissionService.createRole({
            name: roleName,
            description: `${roleName} role`,
        });
        if (!roleResult.success || !roleResult.data) {
            throw new Error(`Failed to create role: ${roleName}`);
        }
        role = roleResult.data;
    }

    // Assign role to user
    await dbInitializer
        .createController("user_roles")
        .create({ user_id: userId, role_id: role.id });

    // Create and assign permissions
    for (const perm of permissions) {
        // Check if permission already exists
        const existingPermResult = await dbInitializer
            .createController("permissions")
            .findFirst({ name: perm.name });

        let permissionId: number | string;

        if (existingPermResult.success && existingPermResult.data) {
            permissionId = existingPermResult.data.id as number;
        } else {
            const permResult = await permissionService.createPermission(perm);
            if (!permResult.success || !permResult.data) {
                throw new Error(`Failed to create permission: ${perm.name}`);
            }
            permissionId = permResult.data.id;
        }

        // Assign permission to role (check if already exists)
        const existingRolePermResult = await dbInitializer
            .createController("role_permissions")
            .findFirst({ role_id: role.id, permission_id: permissionId });

        if (!existingRolePermResult.success || !existingRolePermResult.data) {
            await dbInitializer
                .createController("role_permissions")
                .create({ role_id: role.id, permission_id: permissionId });
        }
    }

    return {
        id: userId,
        username: userData.username,
        email: userData.email,
        token,
        roleName,
    };
}

/**
 * Helper to create a custom permission for testing
 */
export async function createTestPermission(
    context: MiddlewareTestContext,
    permission: {
        name: string;
        resource: string;
        action: string;
        description: string;
    }
): Promise<{ id: number | string; name: string }> {
    const { services } = context;
    const permResult = await services.permissionService.createPermission(permission);

    if (!permResult.success || !permResult.data) {
        throw new Error(`Failed to create test permission: ${permission.name}`);
    }

    return permResult.data;
}

/**
 * Helper to assign a permission to a user's role
 */
export async function assignPermissionToUserRole(
    context: MiddlewareTestContext,
    userId: number | string,
    permissionId: number
): Promise<void> {
    const { dbInitializer } = context;

    // Get user's roles
    const userRolesResult = await dbInitializer
        .createController("user_roles")
        .findAll({ where: { user_id: userId } });

    if (!userRolesResult.success || !userRolesResult.data || userRolesResult.data.length === 0) {
        throw new Error(`User ${userId} has no roles`);
    }

    // Assign permission to first role
    const roleId = userRolesResult.data[0].role_id;
    await dbInitializer
        .createController("role_permissions")
        .create({ role_id: roleId, permission_id: permissionId });
}

/**
 * Helper to deactivate a user (useful for testing inactive user scenarios)
 * Uses typed controller for better type safety and autocompletion
 */
export async function deactivateUser(context: MiddlewareTestContext, userId: number | string): Promise<void> {
    const { dbInitializer } = context;
    
    // Use the typed controller for better type safety
    const result = await dbInitializer
        .createController("users")
        .update(userId, { is_active: 0 });
    
    if (!result.success) {
        throw new Error(`Failed to deactivate user ${userId}: ${result.error}`);
    }
}

/**
 * Helper to reactivate a user
 * Uses typed controller for better type safety and autocompletion
 */
export async function reactivateUser(context: MiddlewareTestContext, userId: number | string): Promise<void> {
    const { dbInitializer } = context;
    
    // Use the typed controller for better type safety
    const result = await dbInitializer
        .createController("users")
        .update(userId, { is_active: 1 });
    
    if (!result.success) {
        throw new Error(`Failed to reactivate user ${userId}: ${result.error}`);
    }
}
