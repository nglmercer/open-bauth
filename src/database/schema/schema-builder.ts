/**
 * Schema Builder - Dynamic Schema Construction
 * 
 * This module provides utilities for building database schemas dynamically.
 * By default, no schemas are predefined - you must import and register them.
 * 
 * @example
 * ```ts
 * // Import predefined schemas
 * import { getAuthSchemas, getOAuthSchemas } from 'open-bauth/schemas';
 * 
 * // Register schemas for use in buildDatabaseSchemas()
 * import { registerBaseSchemas } from 'open-bauth/schema-builder';
 * registerBaseSchemas([...getAuthSchemas(), ...getOAuthSchemas()]);
 * 
 * // Or use with DatabaseInitializer
 * const db = new DatabaseInitializer({
 *   database,
 *   externalSchemas: [...getAuthSchemas(), ...getOAuthSchemas()],
 * });
 * ```
 */

import type { TableSchema, ColumnDefinition } from "../base-controller";
import { Schema } from "./schema";
import {
  getDatabaseConfig,
  getAllTableNames,
  getTableName,
  type DatabaseTableConfig,
} from "../config";
import { StandardFields } from "./constants";

// Re-export constants
export * from "./constants";

/**
 * Base schemas storage - populated via registerBaseSchemas()
 * This allows declarative schema registration for all tests and usage
 */
let BASE_SCHEMAS: Record<string, Schema> = {};

/**
 * Registered schema extensions - populated via registerBaseSchemas()
 * This stores the TableSchema representations for schema extensions
 */
let registeredSchemaExtensions: Record<string, TableSchema> = {};

/**
 * Register schemas to be used by buildDatabaseSchemas()
 * This is the declarative way to add schemas - call this once at app/test initialization
 * @param schemas Array of TableSchema to use as base schemas
 */
export function registerBaseSchemas(schemas: TableSchema[]): void {
  BASE_SCHEMAS = {};
  registeredSchemaExtensions = {};
  
  for (const schema of schemas) {
    // Store the table schema for later processing
    registeredSchemaExtensions[schema.tableName] = schema;
    
    // Also create a Schema instance if we have columns
    if (schema.columns && schema.columns.length > 0) {
      // Create a minimal Schema object that will produce the correct TableSchema
      // We store the tableName and will use it directly
      (BASE_SCHEMAS as any)[schema.tableName] = {
        toTableSchema: (tableName: string) => ({
          tableName,
          columns: schema.columns,
          indexes: schema.indexes || [],
        }),
      };
    }
  }
}

/**
 * Get the currently registered base schemas
 * Useful for debugging or introspection
 */
export function getRegisteredBaseSchemas(): TableSchema[] {
  return Object.values(registeredSchemaExtensions);
}

/**
 * Clear all registered schemas - useful for testing
 */
export function clearBaseSchemas(): void {
  BASE_SCHEMAS = {};
  registeredSchemaExtensions = {};
  
  // Also clear the globalThis registered schemas
  (globalThis as any).__registeredSchemas = [];
}

/**
 * Apply schema extensions to a base schema
 */
function applySchemaExtensions(
  baseSchema: TableSchema,
  extension?: import("../config").SchemaExtension,
): TableSchema {
  if (!extension) return baseSchema;

  let columns = [...baseSchema.columns];

  if (extension.removedColumns) {
    const toRemove = new Set(extension.removedColumns);
    columns = columns.filter((col) => !toRemove.has(col.name));
  }

  if (extension.modifiedColumns) {
    const modifications = new Map(
      extension.modifiedColumns.map((c) => [c.name, c]),
    );
    columns = columns.map((col) => modifications.get(col.name) || col);
  }

  if (extension.additionalColumns) {
    columns.push(...extension.additionalColumns);
  }

  return { ...baseSchema, columns };
}

/**
 * Update table references based on custom table names
 */
function updateTableReferences(
  schema: TableSchema,
  tableNames: Record<string, string>,
): TableSchema {
  const referenceMap: Record<string, string> = {};

  // Build reference map from known table names
  // Map both config keys and default table names to custom names
  Object.entries(tableNames).forEach(([key, name]) => {
    referenceMap[key] = name;
  });
  
  // Also map default table names to handle index renaming
  // This maps "users", "user_roles", etc. to their custom names
  const defaultToKey: Record<string, string> = {
    "users": "users",
    "roles": "roles", 
    "permissions": "permissions",
    "user_roles": "userRoles",
    "role_permissions": "rolePermissions",
    "sessions": "sessions",
  };
  
  Object.entries(defaultToKey).forEach(([defaultName, configKey]) => {
    if (tableNames[configKey as keyof typeof tableNames]) {
      referenceMap[defaultName] = tableNames[configKey as keyof typeof tableNames];
    }
  });

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

/**
 * Build database schemas from configuration
 * 
 * This function returns schemas from:
 * 1. Registered base schemas (via registerBaseSchemas())
 * 2. Schema extensions configured via setDatabaseConfig
 * 3. Schemas registered via registerSchemas() from database-initializer
 * 
 * For predefined auth/OAuth schemas, import them from 'open-bauth/schemas'
 * and register them using registerBaseSchemas()
 */
export function buildDatabaseSchemas(): TableSchema[] {
  const config = getDatabaseConfig();
  const tableNames = getAllTableNames();
  const schemaExtensions = config.schemaExtensions || {};
  const schemas: TableSchema[] = [];

  // Map: default table name -> config key
  const defaultNameToConfigKey: Record<string, keyof DatabaseTableConfig> = {
    'users': 'users',
    'roles': 'roles', 
    'permissions': 'permissions',
    'user_roles': 'userRoles',
    'role_permissions': 'rolePermissions',
    'sessions': 'sessions',
  };

  // Map: config key -> custom table name
  const configKeyToCustomName: Record<string, string> = {
    users: tableNames.users,
    roles: tableNames.roles,
    permissions: tableNames.permissions,
    userRoles: tableNames.userRoles,
    rolePermissions: tableNames.rolePermissions,
    sessions: tableNames.sessions,
  };

  // Process registered base schemas via registerBaseSchemas()
  const registeredKeys = Object.keys(registeredSchemaExtensions);

  for (const defaultTableName of registeredKeys) {
    const schema = registeredSchemaExtensions[defaultTableName];
    
    // Find the config key for this default table name
    const configKey = defaultNameToConfigKey[defaultTableName];
    
    // Get the custom table name (from config or use default)
    const customTableName = configKey 
      ? (configKeyToCustomName[configKey] || defaultTableName)
      : defaultTableName;
    
    const extension = configKey ? schemaExtensions[configKey] : undefined;
    
    let builtSchema = { ...schema, tableName: customTableName };
    builtSchema = applySchemaExtensions(builtSchema, extension);
    builtSchema = updateTableReferences(builtSchema, tableNames);
    schemas.push(builtSchema);
  }

  // Get schemas registered via registerSchemas() from database-initializer
  const registeredSchemas = (globalThis as any).__registeredSchemas || [];
  for (const schema of registeredSchemas) {
    // Check if schema already exists (avoid duplicates)
    if (!schemas.find(s => s.tableName === schema.tableName)) {
      schemas.push(schema);
    }
  }

  // Process schema extensions that define complete tables
  const extensionKeys: (keyof DatabaseTableConfig)[] = [
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
    "users",
    "roles",
    "permissions",
    "userRoles",
    "rolePermissions",
    "sessions",
  ];

  for (const key of extensionKeys) {
    const extension = schemaExtensions[key];
    const tableName = tableNames[key];

    if (extension?.additionalColumns?.length) {
      // Check if schema already exists
      const existingSchema = schemas.find(s => s.tableName === (tableName || key));
      if (!existingSchema) {
        schemas.push({
          tableName: tableName || key,
          columns: extension.additionalColumns,
          indexes: (extension as any).indexes || [],
        });
      }
    }
  }

  return schemas;
}

/**
 * Get table schema by table name
 */
export function getTableSchema(tableName: string): TableSchema | null {
  return buildDatabaseSchemas().find((s) => s.tableName === tableName) || null;
}

/**
 * Get table schema by configuration key
 */
export function getTableSchemaByKey(
  tableKey: keyof DatabaseTableConfig,
): TableSchema | null {
  return getTableSchema(getTableName(tableKey));
}

/**
 * Register external schemas to be used by the database
 * This is the recommended way to add schemas
 */
export function registerExternalSchemas(schemas: TableSchema[]): void {
  const { setDatabaseConfig, getDatabaseConfig, createSchemaExtension } = require("../config");
  const currentConfig = getDatabaseConfig();
  
  const schemaExtensions: Record<string, ReturnType<typeof createSchemaExtension>> = {};
  
  for (const schema of schemas) {
    schemaExtensions[schema.tableName] = createSchemaExtension(
      schema.columns,
      [],
      [],
    );
  }

  setDatabaseConfig({
    ...currentConfig,
    schemaExtensions: {
      ...currentConfig.schemaExtensions,
      ...schemaExtensions,
    },
  });
}

/**
 * Merge schemas from multiple sources
 */
export function mergeSchemas(...schemaArrays: TableSchema[][]): TableSchema[] {
  const merged = new Map<string, TableSchema>();
  
  for (const schemas of schemaArrays) {
    for (const schema of schemas) {
      merged.set(schema.tableName, schema);
    }
  }
  
  return Array.from(merged.values());
}