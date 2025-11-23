import type { TableSchema, ColumnDefinition } from "./base-controller";

/**
 * Configuration interface for custom table names and schema extensions
 */
export interface DatabaseTableConfig {
  /** Custom table name (default: 'users') */
  users?: string;
  /** Custom table name (default: 'roles') */
  roles?: string;
  /** Custom table name (default: 'permissions') */
  permissions?: string;
  /** Custom table name (default: 'user_roles') */
  userRoles?: string;
  /** Custom table name (default: 'role_permissions') */
  rolePermissions?: string;
  /** Custom table name (default: 'sessions') */
  sessions?: string;
  /** Custom table name (default: 'oauth_clients') */
  oauthClients?: string;
  /** Custom table name (default: 'authorization_codes') */
  authorizationCodes?: string;
  /** Custom table name (default: 'refresh_tokens') */
  refreshTokens?: string;
  /** Custom table name (default: 'device_secrets') */
  deviceSecrets?: string;
  /** Custom table name (default: 'biometric_credentials') */
  biometricCredentials?: string;
  /** Custom table name (default: 'anonymous_users') */
  anonymousUsers?: string;
  /** Custom table name (default: 'user_devices') */
  userDevices?: string;
  /** Custom table name (default: 'mfa_configurations') */
  mfaConfigurations?: string;
  /** Custom table name (default: 'security_challenges') */
  securityChallenges?: string;
  /** Custom table name (default: 'oauth_sessions') */
  oauthSessions?: string;
}

/**
 * Interface for extending table schemas with additional columns
 */
export interface SchemaExtension {
  /** Additional columns to add to the table */
  additionalColumns?: ColumnDefinition[];
  /** Columns to modify (will override existing columns) */
  modifiedColumns?: ColumnDefinition[];
  /** Columns to remove from the table */
  removedColumns?: string[];
}

/**
 * Configuration for extending table schemas
 */
export interface DatabaseSchemaExtensions {
  /** Extensions for users table */
  users?: SchemaExtension;
  /** Extensions for roles table */
  roles?: SchemaExtension;
  /** Extensions for permissions table */
  permissions?: SchemaExtension;
  /** Extensions for user_roles table */
  userRoles?: SchemaExtension;
  /** Extensions for role_permissions table */
  rolePermissions?: SchemaExtension;
  /** Extensions for sessions table */
  sessions?: SchemaExtension;
  /** Extensions for oauth_clients table */
  oauthClients?: SchemaExtension;
  /** Extensions for authorization_codes table */
  authorizationCodes?: SchemaExtension;
  /** Extensions for refresh_tokens table */
  refreshTokens?: SchemaExtension;
  /** Extensions for device_secrets table */
  deviceSecrets?: SchemaExtension;
  /** Extensions for biometric_credentials table */
  biometricCredentials?: SchemaExtension;
  /** Extensions for anonymous_users table */
  anonymousUsers?: SchemaExtension;
  /** Extensions for user_devices table */
  userDevices?: SchemaExtension;
  /** Extensions for mfa_configurations table */
  mfaConfigurations?: SchemaExtension;
  /** Extensions for security_challenges table */
  securityChallenges?: SchemaExtension;
  /** Extensions for oauth_sessions table */
  oauthSessions?: SchemaExtension;
}

/**
 * Main database configuration interface
 */
export interface DatabaseConfig {
  /** Custom table names */
  tableNames?: DatabaseTableConfig;
  /** Schema extensions */
  schemaExtensions?: DatabaseSchemaExtensions;
  /** Whether to enable automatic migrations */
  enableMigrations?: boolean;
  /** Whether to enable foreign key constraints */
  enableForeignKeys?: boolean;
}

/**
 * Default table names
 */
export const DEFAULT_TABLE_NAMES: Required<DatabaseTableConfig> = {
  users: "users",
  roles: "roles",
  permissions: "permissions",
  userRoles: "user_roles",
  rolePermissions: "role_permissions",
  sessions: "sessions",
  oauthClients: "oauth_clients",
  authorizationCodes: "authorization_codes",
  refreshTokens: "refresh_tokens",
  deviceSecrets: "device_secrets",
  biometricCredentials: "biometric_credentials",
  anonymousUsers: "anonymous_users",
  userDevices: "user_devices",
  mfaConfigurations: "mfa_configurations",
  securityChallenges: "security_challenges",
  oauthSessions: "oauth_sessions",
};

/**
 * Default configuration
 */
export const DEFAULT_DATABASE_CONFIG: DatabaseConfig = {
  tableNames: DEFAULT_TABLE_NAMES,
  schemaExtensions: {},
  enableMigrations: true,
  enableForeignKeys: true,
};

/**
 * Global database configuration instance
 * This can be modified at runtime to customize table names and schemas
 */
let globalDatabaseConfig: DatabaseConfig = { ...DEFAULT_DATABASE_CONFIG };

/**
 * Set the global database configuration
 * Call this before initializing the database
 */
export function setDatabaseConfig(
  config: DatabaseConfig,
  reset: boolean = false,
): void {
  // If config is empty or reset is true, reset to defaults
  if (
    reset ||
    (!config.tableNames &&
      !config.schemaExtensions &&
      !config.enableMigrations &&
      !config.enableForeignKeys)
  ) {
    globalDatabaseConfig = { ...DEFAULT_DATABASE_CONFIG };
  } else {
    const baseConfig = reset ? DEFAULT_DATABASE_CONFIG : globalDatabaseConfig;

    globalDatabaseConfig = {
      ...baseConfig,
      ...config,
      tableNames: {
        ...baseConfig.tableNames,
        ...config.tableNames,
      },
      schemaExtensions: {
        ...baseConfig.schemaExtensions,
        ...config.schemaExtensions,
      },
    };
  }

  // Clear any cached schemas to force regeneration with new configuration
  clearSchemaCache();
}

/**
 * Get the current global database configuration
 */
export function getDatabaseConfig(): DatabaseConfig {
  return globalDatabaseConfig;
}

/**
 * Clear any cached schemas to force regeneration with new configuration
 */
function clearSchemaCache(): void {
  // This will be called from database-initializer to clear the static cache
  // We'll use a module-level variable to track if cache needs clearing
  (globalThis as any).__schemaCacheCleared = true;
}

/**
 * Get a specific table name with fallback to default
 */
export function getTableName(tableKey: keyof DatabaseTableConfig): string {
  const config = getDatabaseConfig();
  const tableNames = config.tableNames || DEFAULT_TABLE_NAMES;
  return tableNames[tableKey] || DEFAULT_TABLE_NAMES[tableKey];
}

/**
 * Get all configured table names
 */
export function getAllTableNames(): Required<DatabaseTableConfig> {
  const config = getDatabaseConfig();
  return {
    ...DEFAULT_TABLE_NAMES,
    ...config.tableNames,
  };
}

/**
 * Utility function to create a schema extension
 */
export function createSchemaExtension(
  additionalColumns?: ColumnDefinition[],
  modifiedColumns?: ColumnDefinition[],
  removedColumns?: string[],
): SchemaExtension {
  return {
    additionalColumns,
    modifiedColumns,
    removedColumns,
  };
}

/**
 * Predefined common column definitions that can be used in extensions
 */
export const COMMON_COLUMNS = {
  // Timestamp columns
  createdAt: {
    name: "created_at",
    type: "DATETIME",
    defaultValue: "CURRENT_TIMESTAMP",
  },
  updatedAt: {
    name: "updated_at",
    type: "DATETIME",
    defaultValue: "CURRENT_TIMESTAMP",
  },
  deletedAt: { name: "deleted_at", type: "DATETIME" },

  // Soft delete columns
  isDeleted: { name: "is_deleted", type: "BOOLEAN", defaultValue: false },

  // Common user fields
  phoneNumber: { name: "phone_number", type: "TEXT" },
  avatarUrl: { name: "avatar_url", type: "TEXT" },
  timezone: { name: "timezone", type: "TEXT", defaultValue: "UTC" },
  language: { name: "language", type: "TEXT", defaultValue: "en" },

  // Status fields
  status: { name: "status", type: "TEXT", defaultValue: "active" },
  isActive: { name: "is_active", type: "BOOLEAN", defaultValue: true },

  // Audit fields
  createdBy: { name: "created_by", type: "TEXT" },
  updatedBy: { name: "updated_by", type: "TEXT" },

  // Metadata
  metadata: { name: "metadata", type: "TEXT" }, // JSON string
} as const;

/**
 * Predefined schema extensions for common use cases
 */
export const SchemaExtensions = {
  /**
   * Add soft delete functionality to any table
   */
  addSoftDelete: (): SchemaExtension => ({
    additionalColumns: [COMMON_COLUMNS.deletedAt, COMMON_COLUMNS.isDeleted],
  }),

  /**
   * Add audit fields (created_by, updated_by) to any table
   */
  addAuditFields: (): SchemaExtension => ({
    additionalColumns: [COMMON_COLUMNS.createdBy, COMMON_COLUMNS.updatedBy],
  }),

  /**
   * Add common user profile fields to users table
   */
  addUserProfileFields: (): SchemaExtension => ({
    additionalColumns: [
      COMMON_COLUMNS.phoneNumber,
      COMMON_COLUMNS.avatarUrl,
      COMMON_COLUMNS.timezone,
      COMMON_COLUMNS.language,
    ],
  }),

  /**
   * Add status field instead of is_active
   */
  useStatusField: (): SchemaExtension => ({
    additionalColumns: [COMMON_COLUMNS.status],
    removedColumns: ["is_active"],
  }),

  /**
   * Add metadata field for storing JSON data
   */
  addMetadata: (): SchemaExtension => ({
    additionalColumns: [COMMON_COLUMNS.metadata],
  }),
};
