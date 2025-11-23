// src/middleware/auth.ts (FUNCIONES DE MIDDLEWARE CORREGIDAS PARA HONO)

import { JWTService } from "../../src/index";
import { AuthService } from "../../src/index";
import { PermissionService } from "../../src/index";
import type {
  AuthContext,
  PermissionOptions,
  AuthRequest,
  User,
} from "../../src/index";
import type { Context, Next } from "hono"; // <-- Importar tipos de Hono

async function authenticateRequest(
  request: AuthRequest,
  services: {
    jwtService: JWTService;
    authService: AuthService;
    permissionService: PermissionService;
  },
  required: boolean = true,
): Promise<{
  success: boolean;
  context?: AuthContext;
  error?: string;
  statusCode?: number;
}> {
  // ... (lógica sin cambios)
  const tokenHeader = request.headers["authorization"];
  if (!tokenHeader) {
    return {
      success: false,
      error: "Authorization header is missing",
      statusCode: 401,
    };
  }
  const token = services.jwtService.extractTokenFromHeader(tokenHeader);
  if (!token) {
    return {
      success: false,
      error: "Bearer token is missing or malformed",
      statusCode: 401,
    };
  }
  try {
    const payload = await services.jwtService.verifyToken(token);
    const user = await services.authService.findUserById(payload.userId, {
      includeRoles: true,
    });
    if (!user || !user.is_active) {
      return {
        success: false,
        error: "User not found or is inactive",
        statusCode: 401,
      };
    }
    const userRoles = await services.authService.getUserRoles(user.id);
    let userPermissions: string[] = [];
    for (const role of userRoles) {
      const rolePermissions =
        await services.permissionService.getRolePermissions(role.id);
      userPermissions.push(...rolePermissions.map((p) => p.name));
    }
    userPermissions = [...new Set(userPermissions)];
    const context: AuthContext = {
      user: user,
      token: token,
      permissions: userPermissions,
      isAuthenticated: true,
    };
    return { success: true, context: context };
  } catch (error: any) {
    return {
      success: false,
      error: "Invalid or expired token",
      statusCode: 401,
    };
  }
}

/**
 * Factory para crear un middleware de autenticación para Hono.
 */
export function createAuthMiddlewareForHono(
  services: {
    jwtService: JWTService;
    authService: AuthService;
    permissionService: PermissionService;
  },
  required: boolean = true,
) {
  // La función devuelta es el middleware real de Hono
  return async (c: Context, next: Next) => {
    const request: AuthRequest = { headers: c.req.header() };

    // For optional auth, check if authorization header exists first
    if (!required && !request.headers["authorization"]) {
      c.set("auth", {
        user: undefined,
        isAuthenticated: false,
        permissions: [],
      });
      await next();
      return;
    }

    const result = await authenticateRequest(request, services, required);
    if (result.success && result.context) {
      c.set("auth", result.context); // Adjuntar el contexto a la petición de Hono
      await next(); // Éxito: continuar con el siguiente handler
      return;
    }

    // Si la autenticación falla...
    if (required) {
      return c.json({ error: result.error }, (result.statusCode as 401) || 401);
    } else {
      c.set("auth", {
        user: undefined,
        isAuthenticated: false,
        permissions: [],
      });
      await next();
    }
  };
}

/**
 * Factory para crear un middleware de autorización basado en permisos para Hono.
 */
export function createPermissionMiddlewareForHono(
  requiredPermissions: string[],
  options: PermissionOptions = { requireAll: false },
) {
  return async (c: Context, next: Next) => {
    const authContext: AuthContext | undefined = c.get("auth");

    if (!authContext?.isAuthenticated) {
      return c.json({ error: "Authentication required" }, 401);
    }

    const userPermissions = authContext.permissions || [];
    let hasPermission: boolean;

    if (options.requireAll) {
      hasPermission = requiredPermissions.every((p) =>
        userPermissions.includes(p),
      );
    } else {
      hasPermission = requiredPermissions.some((p) =>
        userPermissions.includes(p),
      );
    }

    if (!hasPermission) {
      return c.json({ error: "Insufficient permissions" }, 403);
    }

    await next(); // Éxito: continuar
  };
}

/**
 * Factory para crear un middleware de autorización basado en roles para Hono.
 */
export function createRoleMiddlewareForHono(requiredRoles: string[]) {
  return async (c: Context, next: Next) => {
    const authContext: AuthContext | undefined = c.get("auth");

    if (!authContext?.isAuthenticated || !authContext.user?.roles) {
      return c.json({ error: "Authentication required" }, 401);
    }

    const userRoleNames = authContext.user.roles.map((r) => r.name);
    const hasRole = requiredRoles.some((requiredRole) =>
      userRoleNames.includes(requiredRole),
    );

    if (!hasRole) {
      return c.json({ error: "Access denied. Required role not found." }, 403);
    }

    await next(); // Éxito: continuar
  };
}
