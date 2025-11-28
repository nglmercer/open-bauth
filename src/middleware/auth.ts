// src/middleware/auth.ts

import { JWTService } from "../services/jwt";
import { AuthService } from "../services/auth";
import { PermissionService } from "../services/permissions";
import type {
  AuthContext,
  PermissionOptions,
  AuthRequest,
  User,
} from "../types/auth";

// --- Dependencias (Singleton Pattern) ---
// En una aplicación real, usarías inyección de dependencias.
// Para este ejemplo, asumiremos que los servicios se pueden instanciar aquí.
// ESTO REQUIERE QUE EXPORTES TUS CLASES DE SERVICIO.

// Esta es una simplificación. En una app real, inicializarías esto en tu index.ts
// y lo pasarías a los middlewares. Para mantenerlo simple, lo instanciamos aquí.
// ¡ASEGÚRATE DE QUE LAS DEPENDENCIAS (dbInitializer) ESTÉN DISPONIBLES!
// let jwtService: JWTService;
// let authService: AuthService;
// let permissionService: PermissionService;

// export function initMiddlewareServices(dbInitializer: any) {
//   jwtService = new JWTService(process.env.JWT_SECRET || 'dev-secret');
//   authService = new AuthService(dbInitializer, jwtService);
//   permissionService = new PermissionService(dbInitializer);
// }

/**
 * Función de middleware central para autenticar una petición.
 * Es agnóstica al framework.
 *
 * @param request Objeto que representa la petición entrante.
 * @param services Instancias de los servicios necesarios para el testeo o inyección.
 * @returns Un objeto con el resultado de la autenticación.
 */
export async function authenticateRequest(
  request: AuthRequest,
  services: {
    jwtService: JWTService;
    authService: AuthService;
    permissionService: PermissionService;
  },
): Promise<{
  success: boolean;
  context?: AuthContext;
  error?: string;
  statusCode?: number;
}> {
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

    // Obtener todos los permisos del usuario a través de sus roles
    const userRoles = await services.authService.getUserRoles(user.id);
    let userPermissions: string[] = [];
    for (const role of userRoles) {
      const rolePermissions =
        await services.permissionService.getRolePermissions(role.id);
      userPermissions.push(...rolePermissions.map((p) => p.name));
    }
    // Eliminar duplicados
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
 * Factory para crear un middleware de autenticación para un framework específico (ej. Elysia, Hono).
 *
 * @param services - Instancias de los servicios.
 * @param required - Si es `true`, la autenticación es obligatoria y fallará si no hay token.
 *                   Si es `false`, intentará autenticar pero continuará si no hay token.
 */
export function createAuthMiddleware(
  services: {
    jwtService: JWTService;
    authService: AuthService;
    permissionService: PermissionService;
  },
  required: boolean = true,
) {
  return async (context: any) => {
    // 'context' es 'c' en Hono, o el objeto de contexto en Elysia
    const request: AuthRequest = { headers: context.request.headers };

    const result = await authenticateRequest(request, services);

    if (result.success) {
      context.auth = result.context; // Adjuntar el contexto de autenticación a la petición
      return; // Continuar con el siguiente handler
    }

    if (required) {
      context.set.status = result.statusCode || 401;
      return { success: false, error: result.error };
    } else {
      // Autenticación opcional: si falla, simplemente crea un contexto de invitado y continúa
      context.auth = {
        user: undefined,
        isAuthenticated: false,
        permissions: [],
      };
      return;
    }
  };
}

/**
 * Factory para crear un middleware de autorización basado en permisos.
 * DEBE usarse DESPUÉS del middleware de autenticación.
 *
 * @param services - Instancias de los servicios.
 * @param requiredPermissions - Array de nombres de permisos requeridos.
 * @param options - Opciones como `requireAll`.
 */
export function createPermissionMiddleware(
  services: { permissionService: PermissionService },
  requiredPermissions: string[],
  options: PermissionOptions = { requireAll: false },
) {
  return async (context: any) => {
    const authContext: AuthContext | undefined = context.auth;

    if (!authContext?.isAuthenticated || !authContext.user) {
      context.set.status = 401;
      return { success: false, error: "Authentication required" };
    }

    let hasPermission = false;
    if (options.requireAll) {
      // El usuario debe tener TODOS los permisos de la lista
      hasPermission = requiredPermissions.every((p) =>
        authContext.permissions.includes(p),
      );
    } else {
      // El usuario debe tener AL MENOS UNO de los permisos de la lista
      hasPermission = requiredPermissions.some((p) =>
        authContext.permissions.includes(p),
      );
    }

    if (!hasPermission) {
      context.set.status = 403; // Forbidden
      return { success: false, error: "Insufficient permissions" };
    }

    return; // El usuario tiene permiso, continuar
  };
}

/**
 * Factory para crear un middleware de autorización basado en roles.
 * DEBE usarse DESPUÉS del middleware de autenticación.
 *
 * @param requiredRoles - Array de nombres de roles requeridos.
 */
export function createRoleMiddleware(requiredRoles: string[]) {
  return async (context: any) => {
    const authContext: AuthContext | undefined = context.auth;

    if (!authContext?.isAuthenticated || !authContext.user?.roles) {
      context.set.status = 401;
      return { success: false, error: "Authentication required" };
    }

    const userRoleNames = authContext.user.roles.map((r) => r.name);
    const hasRole = requiredRoles.some((requiredRole) =>
      userRoleNames.includes(requiredRole),
    );

    if (!hasRole) {
      context.set.status = 403;
      return {
        success: false,
        error: "Access denied. Required role not found.",
      };
    }

    return; // El usuario tiene el rol, continuar
  };
}
