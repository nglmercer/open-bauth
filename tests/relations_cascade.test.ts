
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../src/database/database-initializer";

describe("Database Cascade Deletes", () => {
    let db: Database;
    let initializer: DatabaseInitializer;

    beforeEach(async () => {
        // Use in-memory database for fresh state
        db = new Database(":memory:");
        initializer = new DatabaseInitializer({
            database: db,
            enableForeignKeys: true,
            enableWAL: false // WAL doesn't work well with :memory: sometimes
        });

        // Initialize schema
        const result = await initializer.initialize();
        if (!result.success) {
            console.error("Initialization Failed:", result.errors);
        }
    });

    afterEach(() => {
        db.close();
    });

    it("should cascade delete user roles and sessions when user is deleted", async () => {
        const userController = initializer.createController("users");
        const roleController = initializer.createController("roles");
        // Use correct table name "user_roles"
        const userRoleController = initializer.createController("user_roles");
        const sessionController = initializer.createController("sessions");

        // 1. Create User
        const userResult = await userController.create({
            email: "cascade.test@example.com",
            username: "cascadetest",
            password_hash: "hashedpassword",
            first_name: "Cascade",
            last_name: "Test",
            is_active: true
        });
        expect(userResult.success).toBe(true);
        const userId = (userResult.data as any).id;

        // 2. Create Role
        const roleResult = await roleController.create({
            name: "test_cascade_role",
            description: "Role for testing cascade",
            is_active: true
        });
        expect(roleResult.success).toBe(true);
        const roleId = (roleResult.data as any).id;

        // 3. Assign Role to User
        const userRoleResult = await userRoleController.create({
            user_id: userId,
            role_id: roleId
        });
        if (!userRoleResult.success) {
            console.error("UserRole Create Error:", userRoleResult.error);
        }
        expect(userRoleResult.success).toBe(true);

        // 4. Create Session for User
        const sessionResult = await sessionController.create({
            user_id: userId,
            token: "test-token-123",
            expires_at: new Date(Date.now() + 3600000)
        });
        expect(sessionResult.success).toBe(true);

        // Verify records exist
        const userRoles = await userRoleController.findAll({ where: { user_id: userId } });
        expect(userRoles.data).toHaveLength(1);

        const sessions = await sessionController.findAll({ where: { user_id: userId } });
        expect(sessions.data).toHaveLength(1);

        // 5. Delete User
        const deleteResult = await userController.delete(userId);
        expect(deleteResult.success).toBe(true);

        // 6. Verify Cascade

        // User should be gone
        const userCheck = await userController.findById(userId);
        expect(userCheck.success).toBe(false);

        // User Roles should be gone (Cascade)
        // We expect 0 records. If cascade didn't work, we'd still have 1.
        const userRolesCheck = await userRoleController.findAll({ where: { user_id: userId } });
        expect(userRolesCheck.data).toHaveLength(0);

        // Sessions should be gone (Cascade)
        const sessionsCheck = await sessionController.findAll({ where: { user_id: userId } });
        expect(sessionsCheck.data).toHaveLength(0);

        // Role should still exist (No Cascade from User->Role)
        const roleCheck = await roleController.findById(roleId);
        expect(roleCheck.success).toBe(true);
    });

    it("should cascade delete role permissions when role is deleted", async () => {
        const roleController = initializer.createController("roles");
        const permissionController = initializer.createController("permissions");
        // Use correct table name "role_permissions"
        const rolePermissionController = initializer.createController("role_permissions");

        // 1. Create Role
        const roleResult = await roleController.create({
            name: "test_cascade_perm_role",
            description: "Role for testing permission cascade",
            is_active: true
        });
        expect(roleResult.success).toBe(true);
        const roleId = (roleResult.data as any).id;

        // 2. Create Permission
        const permResult = await permissionController.create({
            name: "test:cascade_action",
            resource: "test",
            action: "cascade_action"
        });
        expect(permResult.success).toBe(true);
        const permId = (permResult.data as any).id;

        // 3. Assign Permission to Role
        const linkResult = await rolePermissionController.create({
            role_id: roleId,
            permission_id: permId
        });
        expect(linkResult.success).toBe(true);

        // Verify existing link
        const links = await rolePermissionController.findAll({ where: { role_id: roleId } });
        expect(links.data).toHaveLength(1);

        // 4. Delete Role
        await roleController.delete(roleId);

        // 5. Verify Cascade
        const linksCheck = await rolePermissionController.findAll({ where: { role_id: roleId } });
        expect(linksCheck.data).toHaveLength(0);

        // Permission should still exist
        const permCheck = await permissionController.findById(permId);
        expect(permCheck.success).toBe(true);
    });
});
