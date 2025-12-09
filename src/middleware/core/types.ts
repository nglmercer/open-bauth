// src/middleware/core/types.ts
// Core types for framework-agnostic middleware

import type { User, AuthContext, PermissionOptions } from "../../types/auth";
import type { JWTService } from "../../services/jwt";
import type { AuthService } from "../../services/auth";
import type { PermissionService } from "../../services/permissions";

/**
 * Services required for authentication middleware
 */
export interface AuthServices {
    jwtService: JWTService;
    authService: AuthService;
    permissionService: PermissionService;
}

/**
 * Authentication request - framework agnostic
 */
export interface AuthRequest {
    headers: Record<string, string | undefined>;
    method?: string;
    url?: string;
}

/**
 * Authentication result
 */
export interface AuthResult {
    success: boolean;
    context?: AuthContext;
    error?: string;
    statusCode?: number;
}

/**
 * Authorization result
 */
export interface AuthorizationResult {
    allowed: boolean;
    error?: string;
    statusCode?: number;
}

/**
 * Middleware adapter interface for different frameworks
 */
export interface MiddlewareAdapter<TContext, TNext, TResponse> {
    /**
     * Require authentication (returns 401 if not authenticated)
     */
    requireAuth(options?: AuthOptions): (ctx: TContext, next: TNext) => TResponse;

    /**
     * Optional authentication (continues even if not authenticated)
     */
    optionalAuth(): (ctx: TContext, next: TNext) => TResponse;

    /**
     * Require specific roles
     */
    requireRole(roles: string[]): (ctx: TContext, next: TNext) => TResponse;

    /**
     * Require specific permissions
     */
    requirePermission(
        permissions: string[],
        options?: PermissionOptions
    ): (ctx: TContext, next: TNext) => TResponse;
}

/**
 * Options for authentication middleware
 */
export interface AuthOptions {
    required?: boolean;
    skipInactive?: boolean;
}

/**
 * Framework context extractor - converts framework-specific context to AuthRequest
 */
export interface ContextExtractor<TContext> {
    extractAuthRequest(ctx: TContext): AuthRequest;
    setAuthContext(ctx: TContext, authContext: AuthContext): void;
    getAuthContext(ctx: TContext): AuthContext | undefined;
}
