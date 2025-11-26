import type { TableSchema, ColumnDefinition } from "../base-controller";
import { Schema } from "./schema"; // <--- IMPORTANTE: Importar la nueva clase
import {
  getDatabaseConfig,
  getAllTableNames,
  getTableName,
} from "../config";

/**
 * Base schema definitions using the new Schema class
 */
const BASE_SCHEMAS: Record<string, Schema> = {
  users: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    email: { type: String, required: true, unique: true },
    username: String,
    password_hash: { type: String, required: true },
    first_name: String,
    last_name: String,
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
    last_login_at: Date,
    is_active: { type: Boolean, default: true }
  }, {
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_username", columns: ["username"], unique: true },
      { name: "idx_users_active", columns: ["is_active"] },
    ]
  }),

  roles: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    name: { type: String, required: true, unique: true },
    description: String,
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
    is_active: { type: Boolean, default: true }
  }, {
    indexes: [{ name: "idx_roles_name", columns: ["name"], unique: true }]
  }),

  permissions: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    name: { type: String, required: true, unique: true },
    resource: { type: String, required: true },
    action: { type: String, required: true },
    description: String,
    created_at: { type: Date, default: Date.now },
  }, {
    indexes: [
      { name: "idx_permissions_name", columns: ["name"], unique: true },
      { name: "idx_permissions_resource", columns: ["resource"] },
      { name: "idx_permissions_action", columns: ["action"] },
    ]
  }),

  userRoles: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    user_id: { type: "TEXT", required: true, ref: "users" },
    role_id: { type: "TEXT", required: true, ref: "roles" },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  }, {
    indexes: [
      { name: "idx_user_roles_user_id", columns: ["user_id"] },
      { name: "idx_user_roles_role_id", columns: ["role_id"] },
      { name: "idx_user_roles_unique", columns: ["user_id", "role_id"], unique: true },
    ]
  }),

  rolePermissions: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    role_id: { type: "TEXT", required: true, ref: "roles" },
    permission_id: { type: "TEXT", required: true, ref: "permissions" },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  }, {
    indexes: [
      { name: "idx_role_permissions_role_id", columns: ["role_id"] },
      { name: "idx_role_permissions_permission_id", columns: ["permission_id"] },
      { name: "idx_role_permissions_unique", columns: ["role_id", "permission_id"], unique: true },
    ]
  }),

  sessions: new Schema({
    id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
    user_id: { type: "TEXT", required: true, ref: "users" },
    token: { type: String, required: true, unique: true },
    created_at: { type: Date, default: Date.now },
    expires_at: { type: Date, required: true },
    last_activity: { type: Date, default: Date.now },
    ip_address: String,
    user_agent: String,
    is_active: { type: Boolean, default: true }
  }, {
    indexes: [
      { name: "idx_sessions_user_id", columns: ["user_id"] },
      { name: "idx_sessions_token", columns: ["token"], unique: true },
      { name: "idx_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_sessions_active", columns: ["is_active"] },
    ]
  })
};

/**
 * Apply schema extensions to a base schema
 * (Modificado para aceptar TableSchema directamente)
 */
function applySchemaExtensions(
  baseSchema: TableSchema,
  extension?: import("../config").SchemaExtension
): TableSchema {
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
  schema: TableSchema,
  originalTableName: string,
  tableNames: Record<string, string>,
): TableSchema {
  const updatedColumns = schema.columns.map((column) => {
    if (column.references) {
      const referencedTable = column.references.table;

      // Map reference to custom table name
      let newReferencedTable = referencedTable;
      switch (referencedTable) {
        case "users": newReferencedTable = tableNames.users; break;
        case "roles": newReferencedTable = tableNames.roles; break;
        case "permissions": newReferencedTable = tableNames.permissions; break;
        case "user_roles": newReferencedTable = tableNames.userRoles; break;
        case "role_permissions": newReferencedTable = tableNames.rolePermissions; break;
        case "sessions": newReferencedTable = tableNames.sessions; break;
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
    let newName = index.name;
    // Replace standard prefixes with custom table name prefixes if needed
    // This is a simple replacement logic based on your previous code
    newName = newName.replace(/idx_users_/, `idx_${tableNames.users}_`);
    newName = newName.replace(/idx_roles_/, `idx_${tableNames.roles}_`);
    newName = newName.replace(/idx_permissions_/, `idx_${tableNames.permissions}_`);
    newName = newName.replace(/idx_user_roles_/, `idx_${tableNames.userRoles}_`);
    newName = newName.replace(/idx_role_permissions_/, `idx_${tableNames.rolePermissions}_`);
    newName = newName.replace(/idx_sessions_/, `idx_${tableNames.sessions}_`);

    return { ...index, name: newName };
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
  
  const tableKeys: (keyof typeof tableNames)[] = [
    "users",
    "roles",
    "permissions",
    "userRoles",
    "rolePermissions",
    "sessions",
  ];

  for (const tableKey of tableKeys) {
    const schemaDefinition = BASE_SCHEMAS[tableKey];
    const customTableName = tableNames[tableKey];
    const extension = schemaExtensions[tableKey];

    if (schemaDefinition) {
      // 1. Convert Schema Class to basic TableSchema
      let currentSchema = schemaDefinition.toTableSchema(customTableName);

      // 2. Apply extensions (modifies columns)
      currentSchema = applySchemaExtensions(currentSchema, extension);

      // 3. Update references (Dynamic table names)
      currentSchema = updateTableReferences(currentSchema, tableKey, tableNames);

      schemas.push(currentSchema);
    }
  }

  // Include OAuth schemas (Existing logic unchanged)
  const oauthTableKeys: (keyof typeof tableNames)[] = [
    "oauthClients", "authorizationCodes", "refreshTokens", 
    "deviceSecrets", "biometricCredentials", "anonymousUsers", 
    "userDevices", "mfaConfigurations", "securityChallenges", "oauthSessions",
  ];

  for (const tableKey of oauthTableKeys) {
    const extension = schemaExtensions[tableKey];
    const customTableName = tableNames[tableKey];
    if (extension && extension.additionalColumns && extension.additionalColumns.length > 0) {
      schemas.push({
        tableName: customTableName,
        columns: extension.additionalColumns,
        indexes: [],
      });
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
 * Get table schema by key
 */
export function getTableSchemaByKey(
  tableKey: keyof import("../config").DatabaseTableConfig,
): TableSchema | null {
  const customTableName = getTableName(tableKey);
  return getTableSchema(customTableName);
}