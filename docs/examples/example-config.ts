/**
 * Example configuration file showing how to customize table names and extend schemas
 * Copy this file and modify it for your specific needs
 */

import {
  setDatabaseConfig,
  SchemaExtensions,
  COMMON_COLUMNS,
} from "../../src/database/config";

// Example 1: Custom table names with Spanish names
const spanishTableNames = {
  users: "usuarios",
  roles: "roles",
  permissions: "permisos",
  userRoles: "usuario_roles",
  rolePermissions: "rol_permisos",
  sessions: "sesiones",
};

// Example 2: Custom table names with prefixes
const prefixedTableNames = {
  users: "app_users",
  roles: "app_roles",
  permissions: "app_permissions",
  userRoles: "app_user_roles",
  rolePermissions: "app_role_permissions",
  sessions: "app_sessions",
};

// Example 3: Extended user schema with additional fields
const extendedUserSchema = {
  users: SchemaExtensions.addUserProfileFields(), // Adds phone, avatar, timezone, language
  roles: SchemaExtensions.addMetadata(), // Adds metadata field for JSON data
  sessions: SchemaExtensions.addSoftDelete(), // Adds soft delete functionality
};

// Example 4: Complete custom configuration
const completeCustomConfig = {
  tableNames: prefixedTableNames,
  schemaExtensions: {
    users: SchemaExtensions.addUserProfileFields(),
    roles: {
      additionalColumns: [
        { name: "level", type: "INTEGER" as const, defaultValue: 1 },
        {
          name: "color",
          type: "TEXT" as const,
          defaultValue: "#007bff",
        },
      ],
    },
    permissions: SchemaExtensions.addMetadata(),
    userRoles: SchemaExtensions.addAuditFields(), // Adds created_by, updated_by
    sessions: SchemaExtensions.addSoftDelete(),
  },
  enableMigrations: true,
  enableForeignKeys: true,
};

// Example 5: Status field instead of is_active
const statusBasedConfig = {
  tableNames: spanishTableNames,
  schemaExtensions: {
    users: {
      additionalColumns: [COMMON_COLUMNS.phoneNumber, COMMON_COLUMNS.avatarUrl],
      removedColumns: ["is_active"],
    },
    roles: SchemaExtensions.useStatusField(), // Replaces is_active with status field
    permissions: SchemaExtensions.addMetadata(),
  },
};

// Apply configuration (choose one of the examples above)

// Example: Apply Spanish table names
// setDatabaseConfig({
//   tableNames: spanishTableNames
// });

// Example: Apply extended schemas with default table names
// setDatabaseConfig({
//   schemaExtensions: extendedUserSchema
// });

// Example: Apply complete custom configuration
// setDatabaseConfig(completeCustomConfig);

// Example: Apply status-based configuration
// setDatabaseConfig(statusBasedConfig);

// Export configurations for use in your application
export {
  spanishTableNames,
  prefixedTableNames,
  extendedUserSchema,
  completeCustomConfig,
  statusBasedConfig,
};

/**
 * Usage instructions:
 *
 * 1. Import and call setDatabaseConfig() BEFORE initializing your database
 * 2. Choose one of the predefined configurations or create your own
 * 3. All services and middleware will automatically use the custom table names
 *
 * Example in your main application file:
 *
 * import { setDatabaseConfig } from './database/config';
 * import { completeCustomConfig } from './database/example-config';
 *
 * // Set configuration before database initialization
 * setDatabaseConfig(completeCustomConfig);
 *
 * // Now initialize your database as usual
 * const dbInitializer = new DatabaseInitializer(database);
 * await dbInitializer.initialize();
 *
 * // All services will now use the custom table names and schemas
 */
