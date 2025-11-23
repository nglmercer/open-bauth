import type { TableSchema, ColumnDefinition } from "./base-controller";
import {
  getDatabaseConfig,
  getAllTableNames,
  getTableName,
  COMMON_COLUMNS,
} from "./config";

/**
 * Base schema definitions that will be customized based on configuration
 */
const BASE_SCHEMAS: Record<string, Omit<TableSchema, "tableName">> = {
  users: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      { name: "email", type: "TEXT", unique: true, notNull: true },
      { name: "password_hash", type: "TEXT", notNull: true },
      { name: "first_name", type: "TEXT" },
      { name: "last_name", type: "TEXT" },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      {
        name: "updated_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      { name: "last_login_at", type: "DATETIME" },
      { name: "is_active", type: "BOOLEAN", defaultValue: true },
    ],
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_active", columns: ["is_active"] },
    ],
  },
  roles: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      { name: "name", type: "TEXT", unique: true, notNull: true },
      { name: "description", type: "TEXT" },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      {
        name: "updated_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      { name: "is_active", type: "BOOLEAN", defaultValue: true },
    ],
    indexes: [{ name: "idx_roles_name", columns: ["name"], unique: true }],
  },
  permissions: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      { name: "name", type: "TEXT", unique: true, notNull: true },
      { name: "resource", type: "TEXT", notNull: true },
      { name: "action", type: "TEXT", notNull: true },
      { name: "description", type: "TEXT" },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
    ],
    indexes: [
      { name: "idx_permissions_name", columns: ["name"], unique: true },
      { name: "idx_permissions_resource", columns: ["resource"] },
      { name: "idx_permissions_action", columns: ["action"] },
    ],
  },
  userRoles: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      {
        name: "user_id",
        type: "TEXT",
        notNull: true,
        references: { table: "users", column: "id" },
      },
      {
        name: "role_id",
        type: "TEXT",
        notNull: true,
        references: { table: "roles", column: "id" },
      },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      {
        name: "updated_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
    ],
    indexes: [
      { name: "idx_user_roles_user_id", columns: ["user_id"] },
      { name: "idx_user_roles_role_id", columns: ["role_id"] },
      {
        name: "idx_user_roles_unique",
        columns: ["user_id", "role_id"],
        unique: true,
      },
    ],
  },
  rolePermissions: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      {
        name: "role_id",
        type: "TEXT",
        notNull: true,
        references: { table: "roles", column: "id" },
      },
      {
        name: "permission_id",
        type: "TEXT",
        notNull: true,
        references: { table: "permissions", column: "id" },
      },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      {
        name: "updated_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
    ],
    indexes: [
      { name: "idx_role_permissions_role_id", columns: ["role_id"] },
      {
        name: "idx_role_permissions_permission_id",
        columns: ["permission_id"],
      },
      {
        name: "idx_role_permissions_unique",
        columns: ["role_id", "permission_id"],
        unique: true,
      },
    ],
  },
  sessions: {
    columns: [
      {
        name: "id",
        type: "TEXT",
        primaryKey: true,
        defaultValue: "(lower(hex(randomblob(16))))",
      },
      {
        name: "user_id",
        type: "TEXT",
        notNull: true,
        references: { table: "users", column: "id" },
      },
      { name: "token", type: "TEXT", unique: true, notNull: true },
      {
        name: "created_at",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      { name: "expires_at", type: "DATETIME", notNull: true },
      {
        name: "last_activity",
        type: "DATETIME",
        defaultValue: "CURRENT_TIMESTAMP",
      },
      { name: "ip_address", type: "TEXT" },
      { name: "user_agent", type: "TEXT" },
      { name: "is_active", type: "BOOLEAN", defaultValue: true },
    ],
    indexes: [
      { name: "idx_sessions_user_id", columns: ["user_id"] },
      { name: "idx_sessions_token", columns: ["token"], unique: true },
      { name: "idx_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_sessions_active", columns: ["is_active"] },
    ],
  },
};

/**
 * Apply schema extensions to a base schema
 */
function applySchemaExtensions(
  baseSchema: Omit<TableSchema, "tableName">,
  extension?: import("./config").SchemaExtension,
  tableName?: string,
): Omit<TableSchema, "tableName"> {
  if (!extension) return baseSchema;

  let columns = [...baseSchema.columns];

  // Remove specified columns
  if (extension.removedColumns) {
    columns = columns.filter(
      (col) => !extension.removedColumns!.includes(col.name),
    );
  }

  // Apply modified columns (override existing)
  if (extension.modifiedColumns) {
    extension.modifiedColumns.forEach((modifiedCol) => {
      const index = columns.findIndex((col) => col.name === modifiedCol.name);
      if (index !== -1) {
        columns[index] = modifiedCol;
      }
    });
  }

  // Add additional columns
  if (extension.additionalColumns) {
    columns.push(...extension.additionalColumns);
  }

  return {
    ...baseSchema,
    columns,
  };
}

/**
 * Update references in foreign keys to use custom table names
 */
function updateTableReferences(
  schema: Omit<TableSchema, "tableName">,
  originalTableName: string,
  tableNames: Record<string, string>,
): Omit<TableSchema, "tableName"> {
  const updatedColumns = schema.columns.map((column) => {
    if (column.references) {
      const referencedTable = column.references.table;

      // Map reference to custom table name
      let newReferencedTable = referencedTable;
      switch (referencedTable) {
        case "users":
          newReferencedTable = tableNames.users;
          break;
        case "roles":
          newReferencedTable = tableNames.roles;
          break;
        case "permissions":
          newReferencedTable = tableNames.permissions;
          break;
        case "user_roles":
          newReferencedTable = tableNames.userRoles;
          break;
        case "role_permissions":
          newReferencedTable = tableNames.rolePermissions;
          break;
        case "sessions":
          newReferencedTable = tableNames.sessions;
          break;
      }

      return {
        ...column,
        references: {
          ...column.references,
          table: newReferencedTable,
        },
      };
    }
    return column;
  });

  // Update index names to reflect custom table names
  const updatedIndexes = (schema.indexes || []).map((index) => {
    const oldName = index.name;
    let newName = oldName;

    // Replace table name in index names
    newName = oldName.replace(/idx_users_/, `idx_${tableNames.users}_`);
    newName = newName.replace(/idx_roles_/, `idx_${tableNames.roles}_`);
    newName = newName.replace(
      /idx_permissions_/,
      `idx_${tableNames.permissions}_`,
    );
    newName = newName.replace(
      /idx_user_roles_/,
      `idx_${tableNames.userRoles}_`,
    );
    newName = newName.replace(
      /idx_role_permissions_/,
      `idx_${tableNames.rolePermissions}_`,
    );
    newName = newName.replace(/idx_sessions_/, `idx_${tableNames.sessions}_`);

    return {
      ...index,
      name: newName,
    };
  });

  return {
    ...schema,
    columns: updatedColumns,
    indexes: updatedIndexes,
  };
}

/**
 * Build all database schemas based on current configuration
 */
export function buildDatabaseSchemas(): TableSchema[] {
  const config = getDatabaseConfig();
  const tableNames = getAllTableNames();
  const schemaExtensions = config.schemaExtensions || {};

  const schemas: TableSchema[] = [];
  
  // Build each table schema
  const tableKeys: (keyof typeof tableNames)[] = [
    "users",
    "roles",
    "permissions",
    "userRoles",
    "rolePermissions",
    "sessions",
  ];

  for (const tableKey of tableKeys) {
    const baseSchema = BASE_SCHEMAS[tableKey];
    const customTableName = tableNames[tableKey];
    const extension = schemaExtensions[tableKey];

    if (baseSchema) {
      // Apply schema extensions
      let extendedSchema = applySchemaExtensions(
        baseSchema,
        extension,
        customTableName,
      );

      // Update table references to use custom names
      extendedSchema = updateTableReferences(
        extendedSchema,
        tableKey,
        tableNames,
      );

      schemas.push({
        tableName: customTableName,
        ...extendedSchema,
      });
    }
  }

  // Include OAuth schemas if they're registered as extensions
  const oauthTableKeys: (keyof typeof tableNames)[] = [
    "oauthClients",
    "authorizationCodes",
    "refreshTokens",
    "deviceSecrets",
    "biometricCredentials",
    "anonymousUsers",
    "userDevices",
    "mfaConfigurations",
    "securityChallenges",
    "oauthSessions",
  ];

  // Check if OAuth schemas are registered in extensions
  for (const tableKey of oauthTableKeys) {
    const extension = schemaExtensions[tableKey];
    const customTableName = tableNames[tableKey];

    if (extension && extension.additionalColumns && extension.additionalColumns.length > 0) {
      // Create OAuth schema from extension
      const oauthSchema: TableSchema = {
        tableName: customTableName,
        columns: extension.additionalColumns,
        indexes: [],
      };

      schemas.push(oauthSchema);
    }
  }

  return schemas;
}

/**
 * Get schema for a specific table
 */
export function getTableSchema(tableName: string): TableSchema | null {
  const schemas = buildDatabaseSchemas();
  return schemas.find((schema) => schema.tableName === tableName) || null;
}

/**
 * Get table schema by key (users, roles, etc.)
 */
export function getTableSchemaByKey(
  tableKey: keyof import("./config").DatabaseTableConfig,
): TableSchema | null {
  const customTableName = getTableName(tableKey);
  return getTableSchema(customTableName);
}

// SchemaExtensions moved to config.ts to avoid circular dependencies
