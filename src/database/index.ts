// Export base-controller everything except DatabaseConfig to avoid naming conflict
export * from "./base-controller";

// Export specific items from database-initializer, renaming DatabaseConfig to avoid conflict
export {
  DatabaseInitializer,
  SchemaRegistry,
  getCurrentSchemas,
  DATABASE_SCHEMAS,
  // New exports for modular schema system
  registerSchemas,
  hasSchemas,
  loadDefaultSchemas,
  getDefaultAuthSchemas,
} from "./database-initializer";

// Export types from database-initializer using export type for isolatedModules
export type {
  MigrationResult,
  IntegrityCheckResult,
  DatabaseConfig as DatabaseInitializerConfig,
} from "./database-initializer";

// Export DatabaseLogger interface
export type { DatabaseLogger } from "./database-initializer";

// Re-export the DatabaseConfig from config as the main one
export type { DatabaseConfig } from "./config";
