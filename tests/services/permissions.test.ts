// src/services/permission.service.test.ts

import { test, expect, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { PermissionService } from "../../src/services/permissions";
import { AuthService } from "../../src/services/auth"; // Necesario para crear un usuario de prueba
import { JWTService } from "../../src/services/jwt"; // Dependencia de AuthService

describe("PermissionService", () => {
  let permissionService: PermissionService;
  let authService: AuthService; // Usaremos AuthService para manejar la creación de usuarios
  let dbInitializer: DatabaseInitializer;

  // Se ejecuta antes de cada test para asegurar un estado limpio y fresco
  beforeEach(async () => {
    const db = new Database(":memory:");
    dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize();

    permissionService = new PermissionService(dbInitializer);

    // Necesitamos AuthService para crear usuarios a los que asignar roles
    const jwtService = new JWTService("test-secret", "1h");
    authService = new AuthService(dbInitializer, jwtService);
  });

  // Test para el flujo completo: Crear Rol -> Crear Permiso -> Asignar -> Verificar
  test("should handle the full RBAC flow correctly", async () => {
    // 1. Crear un Rol
    const roleResult = await permissionService.createRole({
      name: "editor",
      description: "Can edit content",
    });
    expect(roleResult.success).toBe(true);
    const editorRole = roleResult.data!;
    expect(editorRole.name).toBe("editor");

    // 2. Crear un Permiso
    const permResult = await permissionService.createPermission({
      name: "edit-article",
      resource: "article",
      action: "edit",
      description: "Allows editing articles",
    });
    expect(permResult.success).toBe(true);
    const editPerm = permResult.data!;
    expect(editPerm.name).toBe("edit-article");

    // 3. Asignar Permiso al Rol
    const assignResult = await permissionService.assignPermissionToRole(
      editorRole.id,
      editPerm.id,
    );
    expect(assignResult.success).toBe(true);

    // 4. Crear un Usuario
    const userReg = await authService.register({
      email: "editor@test.com",
      password: "password",
    });
    const testUser = userReg.user!;

    // 5. Asignar Rol al Usuario
    const assignUserRoleResult = await authService.assignRole(
      testUser.id,
      "editor",
    );
    expect(assignUserRoleResult.success).toBe(true);

    // 6. Verificar permisos (la prueba de fuego)
    const hasPerm = await permissionService.userHasPermission(
      testUser.id,
      "edit-article",
    );
    expect(hasPerm).toBe(true);

    const canAccess = await permissionService.userCanAccessResource(
      testUser.id,
      "article",
      "edit",
    );
    expect(canAccess).toBe(true);

    // 7. Verificar un permiso que NO tiene
    const hasWrongPerm = await permissionService.userHasPermission(
      testUser.id,
      "delete-article",
    );
    expect(hasWrongPerm).toBe(false);
  });

  test("should create and find a role by name", async () => {
    const roleName = "admin";
    await permissionService.createRole({ name: roleName });

    const foundRole = await permissionService.findRoleByName(roleName);

    expect(foundRole).not.toBeNull();
    expect(foundRole?.name).toBe(roleName);
  });

  test("should delete a role and its assignments", async () => {
    // Setup: Crear rol, permiso, usuario y asignarlos todos
    const role = (
      await permissionService.createRole({ name: "temporary-role" })
    ).data!;
    const user = (
      await authService.register({ email: "temp@user.com", password: "pw" })
    ).user!;
    await authService.assignRole(user.id, role.name);

    // Acción: Eliminar el rol
    const deleteResult = await permissionService.deleteRole(role.id);
    expect(deleteResult.success).toBe(true);

    // Verificación: El rol ya no existe
    const findDeletedRole =
      await permissionService.findRoleByName("temporary-role");
    expect(findDeletedRole).toBeNull();

    // Verificación: El usuario ya no tiene ese rol
    const userHasRole = await permissionService.userHasRole(
      user.id,
      "temporary-role",
    );
    expect(userHasRole).toBe(false);
  });

  test("userHasRole should return false for a non-existent role", async () => {
    const user = (
      await authService.register({ email: "user@test.com", password: "pw" })
    ).user!;

    const hasRole = await permissionService.userHasRole(
      user.id,
      "non-existent-role",
    );
    expect(hasRole).toBe(false);
  });
  test("should get unique permissions for multiple roles using getRolesPermissions", async () => {
    // 1. Setup Roles
    const role1 = (await permissionService.createRole({ name: "role1" })).data!;
    const role2 = (await permissionService.createRole({ name: "role2" })).data!;

    // 2. Setup Permissions
    const permA = (
      await permissionService.createPermission({
        name: "permA",
        resource: "resA",
        action: "read",
      })
    ).data!;
    const permB = (
      await permissionService.createPermission({
        name: "permB",
        resource: "resB",
        action: "write",
      })
    ).data!;
    // permC will be shared
    const permC = (
      await permissionService.createPermission({
        name: "permC",
        resource: "resC",
        action: "delete",
      })
    ).data!;

    // 3. Assign Permissions
    // role1 gets permA and permC
    await permissionService.assignPermissionToRole(role1.id, permA.id);
    await permissionService.assignPermissionToRole(role1.id, permC.id);

    // role2 gets permB and permC
    await permissionService.assignPermissionToRole(role2.id, permB.id);
    await permissionService.assignPermissionToRole(role2.id, permC.id);

    // 4. Test getRolesPermissions with both roles
    const permissions = await permissionService.getRolesPermissions([
      role1.id,
      role2.id,
    ]);

    // 5. Verify results
    expect(permissions.length).toBe(3); // Should be unique (A, B, C)
    const permissionNames = permissions.map((p) => p.name).sort();
    expect(permissionNames).toEqual(["permA", "permB", "permC"]);

    // 6. Test with single role
    const role1Permissions = await permissionService.getRolesPermissions([
      role1.id,
    ]);
    expect(role1Permissions.length).toBe(2);
    expect(role1Permissions.map((p) => p.name).sort()).toEqual([
      "permA",
      "permC",
    ]);

    // 7. Test with empty array
    const emptyPermissions = await permissionService.getRolesPermissions([]);
    expect(emptyPermissions).toEqual([]);
  });
});
