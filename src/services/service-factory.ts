import type { DatabaseInitializer } from "../database/database-initializer";
import { AuthService } from "./auth";
import { PermissionService } from "./permissions";
import { JWTService } from "./jwt";
import { getTableName, getAllTableNames } from "../database/config";

/**
 * Factory class for creating service instances with configured table names
 * This ensures all services use the custom table names from the global configuration
 */
export class ServiceFactory {
  private dbInitializer: DatabaseInitializer;
  private jwtService?: JWTService;
  private authService?: AuthService;
  private permissionService?: PermissionService;

  constructor(dbInitializer: DatabaseInitializer) {
    this.dbInitializer = dbInitializer;
  }

  /**
   * Get or create JWT service instance
   */
  getJWTService(secret?: string): JWTService {
    if (!this.jwtService) {
      this.jwtService = new JWTService(
        secret || process.env.JWT_SECRET || "dev-secret",
      );
    }
    return this.jwtService;
  }

  /**
   * Get or create Auth service instance with configured table names
   */
  getAuthService(): AuthService {
    if (!this.authService) {
      this.authService = new AuthService(
        this.dbInitializer,
        this.getJWTService(),
      );
    }
    return this.authService;
  }

  /**
   * Get or create Permission service instance with configured table names
   */
  getPermissionService(): PermissionService {
    if (!this.permissionService) {
      this.permissionService = new PermissionService(this.dbInitializer);
    }
    return this.permissionService;
  }

  /**
   * Get all service instances
   */
  getServices() {
    return {
      jwtService: this.getJWTService(),
      authService: this.getAuthService(),
      permissionService: this.getPermissionService(),
    };
  }

  /**
   * Create a controller with a configured table name
   */
  createControllerWithCustomName<T = Record<string, unknown>>(
    tableKey: keyof ReturnType<typeof getAllTableNames>,
  ) {
    const tableName = getTableName(tableKey);
    return this.dbInitializer.createController<T>(tableName);
  }

  /**
   * Get current table names for debugging/logging
   */
  getCurrentTableNames() {
    return getAllTableNames();
  }

  /**
   * Reset all service instances (useful for testing or configuration changes)
   */
  reset(): void {
    this.jwtService = undefined;
    this.authService = undefined;
    this.permissionService = undefined;
  }
}

/**
 * Global service factory instance
 * This should be initialized once when the application starts
 */
let globalServiceFactory: ServiceFactory | null = null;

/**
 * Initialize the global service factory
 * Call this once during application startup
 */
export function initializeServices(
  dbInitializer: DatabaseInitializer,
): ServiceFactory {
  globalServiceFactory = new ServiceFactory(dbInitializer);
  return globalServiceFactory;
}

/**
 * Get the global service factory instance
 * Throws error if not initialized
 */
export function getServiceFactory(): ServiceFactory {
  if (!globalServiceFactory) {
    throw new Error(
      "Service factory not initialized. Call initializeServices() first.",
    );
  }
  return globalServiceFactory;
}

/**
 * Convenience function to get all services
 */
export function getServices() {
  return getServiceFactory().getServices();
}

/**
 * Convenience function to get auth service
 */
export function getAuthService(): AuthService {
  return getServiceFactory().getAuthService();
}

/**
 * Convenience function to get permission service
 */
export function getPermissionService(): PermissionService {
  return getServiceFactory().getPermissionService();
}

/**
 * Convenience function to get JWT service
 */
export function getJWTService(): JWTService {
  return getServiceFactory().getJWTService();
}
