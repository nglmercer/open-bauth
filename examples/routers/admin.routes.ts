import { Hono } from "hono";
import type { Context, Next } from "hono";
import type { AuthContext } from "../../dist/index";
import type { AuthService, PermissionService } from "../../dist/index";

export type AppContext = {
  Variables: {
    auth: AuthContext;
  };
};

async function getAllPermissions(
  permissionService: PermissionService,
  array: any[]
): Promise<any[]> {
  let Result: any[] = [];
  await Promise.all(
    array.map(async (item) => {
      const permissions = await permissionService.getRolePermissions(item.id);
      Result.push({
        ...item,
        permissions: permissions,
      });
    })
  );
  return Result;
}
async function assignPermissionsToRole(
  id: string,
  permissions: string | string[],
  permissionService: PermissionService
) {
  return await permissionService.updateRolePermissions(
    id,
    Array.isArray(permissions) ? permissions : [permissions]
  );
}
export function createAdminRoutes(
  deps: { authService: AuthService; permissionService: PermissionService },
  middlewares: {
    requireAuth: (c: Context, next: Next) => Promise<Response | void>;
    requireAdminRole: (c: Context, next: Next) => Promise<Response | void>;
  }
) {
  const { authService, permissionService } = deps;
  const { requireAuth, requireAdminRole } = middlewares;

  const router = new Hono<AppContext>();

  router.use("*", requireAuth, requireAdminRole);

  router.get("/users", async (c) => {
    const { users, total } = await authService.getUsers();
    return c.json({ users });
  });
  router.put("/users/:id", async (c) => {
    const id = c.req.param("id");
    const UserData = await c.req.json();
    const transaccion = await authService.updateUser(id, UserData);
    const { user, error, success } = transaccion;
    return c.json({ user, data: user, success: success || false, error });
  });
  // Endpoint para obtener roles CON sus permisos mapeados
  router.get("/roles", async (c) => {
    const roles = await permissionService.getAllRoles();
    // Mapear permisos a cada rol usando la función auxiliar
    const rolesWithPermissions = await getAllPermissions(
      permissionService,
      roles
    );
    return c.json({
      roles: rolesWithPermissions,
      data: rolesWithPermissions,
    });
  });

  // Endpoint SIN getRolePermissions
  router.get("/roles/basic", async (c) => {
    const roles = await permissionService.getAllRoles();
    return c.json({ roles: roles, data: roles });
  });

  router.get("/permissions", async (c) => {
    const permissions = await permissionService.getAllPermissions();
    return c.json({
      permissions: permissions,
      data: permissions,
    });
  });

  // Endpoint adicional para obtener permisos de un rol específico
  router.get("/roles/:roleId/permissions", async (c) => {
    const roleId = c.req.param("roleId");
    try {
      const permissions = await permissionService.getRolePermissions(roleId);
      return c.json({
        roleId,
        permissions,
        data: permissions,
      });
    } catch (error) {
      return c.json(
        { error: "Role not found or error fetching permissions" },
        404
      );
    }
  });
  router.post("/roles", async (c) => {
    const { name, description, permissions } = await c.req.json();
    try {
      const transaccion = await permissionService.createRole({
        name,
        description,
      });
      const { role, data, success } = transaccion;
      const result = await assignPermissionsToRole(
        role?.id || data.id,
        permissions,
        permissionService
      );

      return c.json({ role, data: role, success: success || false, result });
    } catch (error: any) {
      return c.json(
        { error: "Error creating role", message: error?.message || "" },
        400
      );
    }
  });
  router.put("/roles/:id", async (c) => {
    try {
      const id = c.req.param("id");
      const { name, description, permissions } = await c.req.json();
      const transaccion = await permissionService.updateRole(id, {
        name,
        description,
      });
      const { role, data, success } = transaccion;
      const result = await assignPermissionsToRole(
        role?.id || data.id,
        permissions,
        permissionService
      );
      return c.json({ role, data: role, success: success || false, result });
    } catch (error: any) {
      return c.json(
        { error: "Error updating role", message: error?.message || "" },
        400
      );
    }
  });
  router.get("/stats", async (c) => {
    const { users, total } = await authService.getUsers();
    /*{
        totalUsers: response.data?.totalUsers || 0,
        activeUsers: response.data?.activeUsers || 0,
        inactiveUsers: response.data?.inactiveUsers || 0,
        totalPosts: response.data?.totalPosts || 0,
        publishedPosts: response.data?.publishedPosts || 0,
        unpublishedPosts: response.data?.unpublishedPosts || 0
      }*/
    return c.json({ success: true, users, totalUsers: total });
  });
  router.put("/users/:id", async (c) => {
    const id = c.req.param("id");
    const UserData = await c.req.json();
    const transaccion = await authService.updateUser(id, UserData);
    const { user, error, success } = transaccion;
    return c.json({ user, data: user, success: success || false, error });
  });
  router.put("/users/:id/deactivate", async (c) => {
    const id = c.req.param("id");
    const data = await authService.getUserRoles(id);
    // verify is account is ['moderator', 'admin'] to make a required confirmation
    const verifyRoles = ["moderator", "admin"];
    const isRestrictedRole = data.some((role) =>
      verifyRoles.includes(role.name)
    );
    if (isRestrictedRole) {
      return c.json(
        {
          error: "can not deactivate user with role " + verifyRoles.join(", "),
          success: false,
        },
        403
      );
    }
    const transaccion = await authService.deactivateUser(id);
    const { error, success } = transaccion;
    return c.json({ id, data: id, success: success || false, error });
  });

  router.put("/users/:id/activate", async (c) => {
    const id = c.req.param("id");
    const transaccion = await authService.activateUser(id);
    const { error, success } = transaccion;
    return c.json({ id, data: id, success: success || false, error });
  });
  return router;
}
