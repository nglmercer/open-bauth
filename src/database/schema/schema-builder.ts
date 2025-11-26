import type { TableSchema, ColumnDefinition } from "../base-controller";
import { Schema } from "./schema";
import {
  getDatabaseConfig,
  getAllTableNames,
  getTableName,
  type DatabaseTableConfig
} from "../config";

// Utils

const StandardFields = {
  UUID: { type: String, primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  Timestamps: {
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  },
  Active: { type: Boolean, default: true },
};

// Schema base 

const BASE_SCHEMAS: Record<string, Schema> = {
  users: new Schema({
    id: StandardFields.UUID,
    email: { type: String, required: true, unique: true },
    username: String,
    password_hash: { type: String, required: true },
    first_name: String,
    last_name: String,
    ...StandardFields.Timestamps,
    last_login_at: Date,
    is_active: StandardFields.Active
  }, {
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_username", columns: ["username"], unique: true },
      { name: "idx_users_active", columns: ["is_active"] },
    ]
  }),

  roles: new Schema({
    id: StandardFields.UUID,
    name: { type: String, required: true, unique: true },
    description: String,
    ...StandardFields.Timestamps,
    is_active: StandardFields.Active
  }, {
    indexes: [{ name: "idx_roles_name", columns: ["name"], unique: true }]
  }),

  permissions: new Schema({
    id: StandardFields.UUID,
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
    id: StandardFields.UUID,
    user_id: { type: "TEXT", required: true, ref: "users" },
    role_id: { type: "TEXT", required: true, ref: "roles" },
    ...StandardFields.Timestamps,
  }, {
    indexes: [
      { name: "idx_user_roles_user_id", columns: ["user_id"] },
      { name: "idx_user_roles_role_id", columns: ["role_id"] },
      { name: "idx_user_roles_unique", columns: ["user_id", "role_id"], unique: true },
    ]
  }),

  rolePermissions: new Schema({
    id: StandardFields.UUID,
    role_id: { type: "TEXT", required: true, ref: "roles" },
    permission_id: { type: "TEXT", required: true, ref: "permissions" },
    ...StandardFields.Timestamps,
  }, {
    indexes: [
      { name: "idx_role_permissions_role_id", columns: ["role_id"] },
      { name: "idx_role_permissions_permission_id", columns: ["permission_id"] },
      { name: "idx_role_permissions_unique", columns: ["role_id", "permission_id"], unique: true },
    ]
  }),

  sessions: new Schema({
    id: StandardFields.UUID,
    user_id: { type: "TEXT", required: true, ref: "users" },
    token: { type: String, required: true, unique: true },
    created_at: { type: Date, default: Date.now },
    expires_at: { type: Date, required: true },
    last_activity: { type: Date, default: Date.now },
    ip_address: String,
    user_agent: String,
    is_active: StandardFields.Active
  }, {
    indexes: [
      { name: "idx_sessions_user_id", columns: ["user_id"] },
      { name: "idx_sessions_token", columns: ["token"], unique: true },
      { name: "idx_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_sessions_active", columns: ["is_active"] },
    ]
  })
};

// constructor functions

function applySchemaExtensions(
  baseSchema: TableSchema,
  extension?: import("../config").SchemaExtension
): TableSchema {
  if (!extension) return baseSchema;

  let columns = [...baseSchema.columns];

  if (extension.removedColumns) {
    const toRemove = new Set(extension.removedColumns);
    columns = columns.filter(col => !toRemove.has(col.name));
  }

  if (extension.modifiedColumns) {
    const modifications = new Map(extension.modifiedColumns.map(c => [c.name, c]));
    columns = columns.map(col => modifications.get(col.name) || col);
  }

  if (extension.additionalColumns) {
    columns.push(...extension.additionalColumns);
  }

  return { ...baseSchema, columns };
}

function updateTableReferences(
  schema: TableSchema,
  tableNames: Record<string, string>,
): TableSchema {
  // Mapeo inverso de claves conocidas a nombres personalizados
  const referenceMap: Record<string, string> = {
    users: tableNames.users,
    roles: tableNames.roles,
    permissions: tableNames.permissions,
    user_roles: tableNames.userRoles,
    role_permissions: tableNames.rolePermissions,
    sessions: tableNames.sessions
  };

  const updatedColumns = schema.columns.map((column) => {
    if (column.references && referenceMap[column.references.table]) {
      return {
        ...column,
        references: {
          ...column.references,
          table: referenceMap[column.references.table],
        },
      };
    }
    return column;
  });

  const updatedIndexes = (schema.indexes || []).map((index) => {
    let newName = index.name;
    // Reemplazo dinámico de prefijos basado en el mapa
    Object.entries(referenceMap).forEach(([key, customName]) => {
      if (newName.includes(`idx_${key}_`)) {
        newName = newName.replace(`idx_${key}_`, `idx_${customName}_`);
      }
    });
    return { ...index, name: newName };
  });

  return {
    ...schema,
    columns: updatedColumns,
    indexes: updatedIndexes,
  };
}

export function buildDatabaseSchemas(): TableSchema[] {
  const config = getDatabaseConfig();
  const tableNames = getAllTableNames();
  const schemaExtensions = config.schemaExtensions || {};
  const schemas: TableSchema[] = [];
  
  // 1. Procesar Esquemas Base
  const baseKeys = Object.keys(BASE_SCHEMAS) as (keyof typeof BASE_SCHEMAS)[];

  for (const key of baseKeys) {
    const definition = BASE_SCHEMAS[key];
    // key mapping BASE_SCHEMAS  -> config.tableNames
    //  (users -> users, roles -> roles, etc.)
    const configKey = key as keyof DatabaseTableConfig; 
    const customTableName = tableNames[configKey];
    const extension = schemaExtensions[configKey];

    if (definition && customTableName) {
      let schema = definition.toTableSchema(customTableName);
      schema = applySchemaExtensions(schema, extension);
      schema = updateTableReferences(schema, tableNames);
      schemas.push(schema);
    }
  }

  // Oauth Schemes
  const oauthKeys: (keyof DatabaseTableConfig)[] = [
    "oauthClients", "authorizationCodes", "refreshTokens", 
    "deviceSecrets", "biometricCredentials", "anonymousUsers", 
    "userDevices", "mfaConfigurations", "securityChallenges", "oauthSessions",
  ];

  for (const key of oauthKeys) {
    const extension = schemaExtensions[key];
    const tableName = tableNames[key];
    
    if (extension?.additionalColumns?.length) {
      schemas.push({
        tableName: tableName || key, 
        columns: extension.additionalColumns,
        indexes: [], 
      });
    }
  }

  return schemas;
}

export function getTableSchema(tableName: string): TableSchema | null {
  return buildDatabaseSchemas().find((s) => s.tableName === tableName) || null;
}

export function getTableSchemaByKey(
  tableKey: keyof DatabaseTableConfig,
): TableSchema | null {
  return getTableSchema(getTableName(tableKey));
}