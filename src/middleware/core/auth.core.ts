// src/middleware/core/auth.core.ts
// Framework-agnostic authentication logic

import type {
    AuthServices,
    AuthRequest,
    AuthResult,
    AuthorizationResult,
} from "./types";
import type { AuthContext, PermissionOptions } from "../../types/auth";

/**
 * Core authentication function - framework agnostic
 * Validates JWT token and constructs auth context with user, roles, and permissions
 */
export async function authenticateRequest(
    request: AuthRequest,
    services: AuthServices,
    required: boolean = true
): Promise<AuthResult> {
    // Extract authorization header
    const tokenHeader = request.headers["authorization"];

    // If not required and no token, return success with empty context
    if (!required && !tokenHeader) {
        return {
            success: true,
            context: {
                user: undefined,
                isAuthenticated: false,
                permissions: [],
            },
        };
    }

    // Token is required or present
    if (!tokenHeader) {
        return {
            success: false,
            error: "Authorization header is missing",
            statusCode: 401,
        };
    }

    // Extract token from header
    const token = services.jwtService.extractTokenFromHeader(tokenHeader);
    if (!token) {
        return {
            success: false,
            error: "Bearer token is missing or malformed",
            statusCode: 401,
        };
    }

    try {
        // Verify JWT token
        const payload = await services.jwtService.verifyToken(token);

        // Find user by ID from token payload
        const user = await services.authService.findUserById(payload.userId, {
            includeRoles: true,
        });

        // Validate user exists and is active
        if (!user || !user.is_active) {
            return {
                success: false,
                error: "User not found or is inactive",
                statusCode: 401,
            };
        }

        // Get user roles
        const userRoles = await services.authService.getUserRoles(user.id);

        // Aggregate permissions from all roles
        // Aggregate permissions from all roles
        const roleIds = userRoles.map((role) => role.id);
        const permissions = await services.permissionService.getRolesPermissions(
            roleIds
        );
        let userPermissions = permissions.map((p) => p.name);

        // Remove duplicates
        userPermissions = [...new Set(userPermissions)];

        // Construct auth context
        const context: AuthContext = {
            user: user,
            token: token,
            permissions: userPermissions,
            isAuthenticated: true,
        };

        return { success: true, context };
    } catch (error: any) {
        return {
            success: false,
            error: "Invalid or expired token",
            statusCode: 401,
        };
    }
}

/**
 * Core authorization check for permissions
 * Validates that the authenticated user has required permissions
 */
export async function authorizePermissions(
    authContext: AuthContext | undefined,
    requiredPermissions: string[],
    options: PermissionOptions = { requireAll: false }
): Promise<AuthorizationResult> {
    // Check if user is authenticated
    if (!authContext?.isAuthenticated || !authContext.user) {
        return {
            allowed: false,
            error: "Authentication required",
            statusCode: 401,
        };
    }

    const userPermissions = authContext.permissions || [];

    // Check permissions based on options
    let hasPermission = false;
    if (options.requireAll) {
        // User must have ALL required permissions
        hasPermission = requiredPermissions.every((p) =>
            userPermissions.includes(p)
        );
    } else {
        // User must have AT LEAST ONE required permission
        hasPermission = requiredPermissions.some((p) =>
            userPermissions.includes(p)
        );
    }

    if (!hasPermission) {
        return {
            allowed: false,
            error: "Insufficient permissions",
            statusCode: 403,
        };
    }

    return { allowed: true };
}

/**
 * Core authorization check for roles
 * Validates that the authenticated user has at least one required role
 */
export async function authorizeRoles(
    authContext: AuthContext | undefined,
    requiredRoles: string[]
): Promise<AuthorizationResult> {
    // Check if user is authenticated
    if (!authContext?.isAuthenticated || !authContext.user?.roles) {
        return {
            allowed: false,
            error: "Authentication required",
            statusCode: 401,
        };
    }

    // Extract user role names
    const userRoleNames = authContext.user.roles.map((r) => r.name);

    // Check if user has at least one required role
    const hasRole = requiredRoles.some((requiredRole) =>
        userRoleNames.includes(requiredRole)
    );

    if (!hasRole) {
        return {
            allowed: false,
            error: "Access denied. Required role not found.",
            statusCode: 403,
        };
    }

    return { allowed: true };
}
