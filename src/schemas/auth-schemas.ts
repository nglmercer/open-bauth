/**
 * Auth Schemas Module - Optional Predefined Schemas
 * 
 * This module provides predefined schemas for authentication tables.
 * Import and register these schemas if you want to use the built-in auth system.
 * Schemas are optional - the system works without them.
 * 
 * @example
 * ```ts
 * import { getAuthSchemas, authSchemas } from 'open-bauth/schemas';
 * 
 * // Get schemas for database initialization
 * const schemas = getAuthSchemas();
 * 
 * // Or use with DatabaseInitializer
 * const db = new DatabaseInitializer({
 *   database,
 *   externalSchemas: authSchemas,
 * });
 * ```
 */

import { Schema, StandardFields } from "../database/schema";
import type { TableSchema, ColumnDefinition } from "../database/base-controller";
import type {
  SchemaDefinition,
  SchemaField,
  SchemaOptions,
  SchemaIndex,
  SchemaTypeOptions,
  ModelZodSchemas,
  TypedModelZodSchemas,
} from "../database/schema";

// Re-export core schema utilities
export { Schema, StandardFields } from "../database/schema";
export type {
  SchemaDefinition,
  SchemaField,
  SchemaOptions,
  SchemaIndex,
  SchemaTypeOptions,
  ModelZodSchemas,
  TypedModelZodSchemas,
} from "../database/schema";

export type { TableSchema, ColumnDefinition } from "../database/base-controller";

// Re-export Zod utilities
export {
  mapSqlTypeToZodType,
  mapConstructorToZodType,
  flexibleBoolean,
} from "../database/schema/zod-mapping";
export type { ConstructorType } from "../database/schema/zod-mapping";

// Re-export SchemaRegistry from database-initializer for compatibility
export { SchemaRegistry } from "../database/database-initializer";

/**
 * Empty schemas - default when no schemas are provided
 * This allows the system to work without any predefined schema
 */
export const emptySchemas: TableSchema[] = [];

// ==================== Schema Instances ====================

/**
 * Predefined User Schema
 */
export const usersSchema = new Schema(
  {
    id: StandardFields.UUID,
    email: { type: String, required: true, unique: true },
    username: String,
    password_hash: { type: String, required: true },
    first_name: String,
    last_name: String,
    ...StandardFields.Timestamps,
    last_login_at: Date,
    is_active: StandardFields.Active,
  },
  {
    indexes: [
      { name: "idx_users_email", columns: ["email"], unique: true },
      { name: "idx_users_username", columns: ["username"], unique: true },
      { name: "idx_users_active", columns: ["is_active"] },
    ],
  },
);

/**
 * Predefined Role Schema
 */
export const rolesSchema = new Schema(
  {
    id: StandardFields.UUID,
    name: { type: String, required: true, unique: true },
    description: String,
    ...StandardFields.Timestamps,
    is_active: StandardFields.Active,
  },
  {
    indexes: [{ name: "idx_roles_name", columns: ["name"], unique: true }],
  },
);

/**
 * Predefined Permission Schema
 */
export const permissionsSchema = new Schema(
  {
    id: StandardFields.UUID,
    name: { type: String, required: true, unique: true },
    resource: { type: String, required: true },
    action: { type: String, required: true },
    description: String,
    created_at: { type: Date, default: Date.now },
  },
  {
    indexes: [
      { name: "idx_permissions_name", columns: ["name"], unique: true },
      { name: "idx_permissions_resource", columns: ["resource"] },
      { name: "idx_permissions_action", columns: ["action"] },
    ],
  },
);

/**
 * Predefined UserRole Schema (junction table)
 */
export const userRolesSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: {
      type: "TEXT",
      required: true,
      ref: "users",
      onDelete: "CASCADE",
    },
    role_id: {
      type: "TEXT",
      required: true,
      ref: "roles",
      onDelete: "CASCADE",
    },
    ...StandardFields.Timestamps,
  },
  {
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
);

/**
 * Predefined RolePermission Schema (junction table)
 */
export const rolePermissionsSchema = new Schema(
  {
    id: StandardFields.UUID,
    role_id: {
      type: "TEXT",
      required: true,
      ref: "roles",
      onDelete: "CASCADE",
    },
    permission_id: {
      type: "TEXT",
      required: true,
      ref: "permissions",
      onDelete: "CASCADE",
    },
    ...StandardFields.Timestamps,
  },
  {
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
);

/**
 * Predefined Session Schema
 */
export const sessionsSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: {
      type: "TEXT",
      required: true,
      ref: "users",
      onDelete: "CASCADE",
    },
    token: { type: String, required: true, unique: true },
    created_at: { type: Date, default: Date.now },
    expires_at: { type: Date, required: true },
    last_activity: { type: Date, default: Date.now },
    ip_address: String,
    user_agent: String,
    is_active: StandardFields.Active,
  },
  {
    indexes: [
      { name: "idx_sessions_user_id", columns: ["user_id"] },
      { name: "idx_sessions_token", columns: ["token"], unique: true },
      { name: "idx_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_sessions_active", columns: ["is_active"] },
    ],
  },
);

// ==================== Schema Map ====================

/**
 * Schema map for easy access by table name
 */
const authSchemasMap: Record<string, Schema> = {
  users: usersSchema,
  roles: rolesSchema,
  permissions: permissionsSchema,
  user_roles: userRolesSchema,
  role_permissions: rolePermissionsSchema,
  sessions: sessionsSchema,
};

// ==================== Helper Functions ====================

/**
 * Get all authentication schemas as TableSchema array
 * @param tableNames - Optional custom table names
 */
export function getAuthSchemas(tableNames?: {
  users?: string;
  roles?: string;
  permissions?: string;
  userRoles?: string;
  rolePermissions?: string;
  sessions?: string;
}): TableSchema[] {
  const names = tableNames || {};
  
  return [
    usersSchema.toTableSchema(names.users || "users"),
    rolesSchema.toTableSchema(names.roles || "roles"),
    permissionsSchema.toTableSchema(names.permissions || "permissions"),
    userRolesSchema.toTableSchema(names.userRoles || "user_roles"),
    rolePermissionsSchema.toTableSchema(names.rolePermissions || "role_permissions"),
    sessionsSchema.toTableSchema(names.sessions || "sessions"),
  ];
}

/**
 * Get a specific auth schema by table name
 */
export function getAuthSchema(tableName: string): TableSchema | null {
  const schema = authSchemasMap[tableName];
  return schema ? schema.toTableSchema(tableName) : null;
}

/**
 * Get all auth schema instances (for advanced usage)
 */
export function getAuthSchemaInstances(): Record<string, Schema> {
  return { ...authSchemasMap };
}

/**
 * Get Zod schemas for all auth tables
 */
export function getAuthZodSchemas(): Record<string, ModelZodSchemas> {
  const result: Record<string, ModelZodSchemas> = {};
  for (const [name, schema] of Object.entries(authSchemasMap)) {
    result[name] = schema.toZod();
  }
  return result;
}

/**
 * Get typed Zod schemas for all auth tables
 */
export function getAuthTypedZodSchemas(): Record<string, TypedModelZodSchemas<any>> {
  const result: Record<string, TypedModelZodSchemas<any>> = {};
  for (const [name, schema] of Object.entries(authSchemasMap)) {
    result[name] = schema.toZodTyped();
  }
  return result;
}

// ==================== Default Exports ====================

/**
 * Default export - all auth schemas as TableSchema[]
 */
export const authSchemas = getAuthSchemas();

/**
 * Schema instances grouped by name
 */
export const schemas = {
  users: usersSchema,
  roles: rolesSchema,
  permissions: permissionsSchema,
  userRoles: userRolesSchema,
  rolePermissions: rolePermissionsSchema,
  sessions: sessionsSchema,
};

/**
 * Zod schemas (create, update, read) for each table
 */
export const zodSchemas = {
  users: usersSchema.toZod(),
  roles: rolesSchema.toZod(),
  permissions: permissionsSchema.toZod(),
  userRoles: userRolesSchema.toZod(),
  rolePermissions: rolePermissionsSchema.toZod(),
  sessions: sessionsSchema.toZod(),
};

/**
 * Typed Zod schemas with full type inference
 */
export const typedZodSchemas = {
  users: usersSchema.toZodTyped(),
  roles: rolesSchema.toZodTyped(),
  permissions: permissionsSchema.toZodTyped(),
  userRoles: userRolesSchema.toZodTyped(),
  rolePermissions: rolePermissionsSchema.toZodTyped(),
  sessions: sessionsSchema.toZodTyped(),
};

// ==================== Schema Builder Class ====================

/**
 * Schema Builder - allows dynamic registration and management of schemas
 * (Renamed to avoid conflict with DatabaseInitializer's SchemaRegistry)
 */
export class SchemaBuilder {
  private schemas: Map<string, Schema> = new Map();
  private tableSchemas: Map<string, TableSchema> = new Map();

  constructor(initial: Schema[] = []) {
    for (const schema of initial) {
      this.register(schema);
    }
  }

  /**
   * Register a schema with a table name
   */
  register(schema: Schema, tableName?: string): void {
    const name = tableName || this.deriveTableName(schema);
    this.schemas.set(name, schema);
    this.tableSchemas.set(name, schema.toTableSchema(name));
  }

  /**
   * Register multiple schemas at once
   */
  registerMany(schemas: Array<{ schema: Schema; tableName?: string }>): void {
    for (const { schema, tableName } of schemas) {
      this.register(schema, tableName);
    }
  }

  /**
   * Get a schema by table name
   */
  get(tableName: string): Schema | undefined {
    return this.schemas.get(tableName);
  }

  /**
   * Get all schemas
   */
  getAll(): Schema[] {
    return Array.from(this.schemas.values());
  }

  /**
   * Get all table schemas
   */
  getTableSchemas(): TableSchema[] {
    return Array.from(this.tableSchemas.values());
  }

  /**
   * Check if a table exists
   */
  has(tableName: string): boolean {
    return this.schemas.has(tableName);
  }

  /**
   * Remove a schema
   */
  remove(tableName: string): void {
    this.schemas.delete(tableName);
    this.tableSchemas.delete(tableName);
  }

  /**
   * Clear all schemas
   */
  clear(): void {
    this.schemas.clear();
    this.tableSchemas.clear();
  }

  /**
   * Get Zod schemas for all tables
   */
  getZodSchemas(): Record<string, ModelZodSchemas> {
    const result: Record<string, ModelZodSchemas> = {};
    for (const [name, schema] of this.schemas) {
      result[name] = schema.toZod();
    }
    return result;
  }

  /**
   * Get typed Zod schemas for all tables
   */
  getTypedZodSchemas(): Record<string, TypedModelZodSchemas<any>> {
    const result: Record<string, TypedModelZodSchemas<any>> = {};
    for (const [name, schema] of this.schemas) {
      result[name] = schema.toZodTyped();
    }
    return result;
  }

  private deriveTableName(schema: Schema): string {
    const def = schema.getDefinition();
    const keys = Object.keys(def);
    return keys[0] || "unknown";
  }

  /**
   * Create from TableSchema array (useful for external schemas)
   */
  static fromTableSchemas(tableSchemas: TableSchema[]): SchemaBuilder {
    const registry = new SchemaBuilder();
    for (const ts of tableSchemas) {
      registry.tableSchemas.set(ts.tableName, ts);
      registry.schemas.set(ts.tableName, Schema.fromTableSchema(ts));
    }
    return registry;
  }

  /**
   * Merge multiple registries
   */
  static merge(...registries: SchemaBuilder[]): SchemaBuilder {
    const merged = new SchemaBuilder();
    for (const reg of registries) {
      for (const [name, schema] of reg.schemas) {
        merged.register(schema, name);
      }
    }
    return merged;
  }
}

// ==================== Factory Functions ====================

/**
 * Creates a schema module from a definition object
 */
export function createSchemaModule<T extends Record<string, Schema>>(
  schemas: T
): {
  schemas: T;
  getTableSchemas: (tableNames?: Record<keyof T, string>) => TableSchema[];
  getZodSchemas: () => Record<keyof T, ModelZodSchemas>;
  getTypedZodSchemas: () => Record<keyof T, TypedModelZodSchemas<any>>;
} {
  return {
    schemas,
    
    getTableSchemas(tableNames?: Record<keyof T, string>): TableSchema[] {
      const names = tableNames || {} as Record<keyof T, string>;
      return Object.entries(this.schemas).map(([key, schema]) => {
        const tableName = names[key as keyof T] || key;
        return schema.toTableSchema(tableName);
      });
    },
    
    getZodSchemas(): Record<keyof T, ModelZodSchemas> {
      return Object.fromEntries(
        Object.entries(this.schemas).map(([key, schema]) => [key, schema.toZod()])
      ) as Record<keyof T, ModelZodSchemas>;
    },
    
    getTypedZodSchemas(): Record<keyof T, TypedModelZodSchemas<any>> {
      return Object.fromEntries(
        Object.entries(this.schemas).map(([key, schema]) => [key, schema.toZodTyped()])
      ) as Record<keyof T, TypedModelZodSchemas<any>>;
    },
  };
}

/**
 * Merge multiple schema modules into one
 */
export function mergeSchemaModules<T extends Record<string, Schema>>(
  ...modules: Array<{ schemas: T }>
): T {
  return Object.assign({}, ...modules.map((m) => m.schemas)) as T;
}

/**
 * Convert a TableSchema to a Schema instance
 */
export function tableSchemaToSchema(tableSchema: TableSchema): Schema {
  return Schema.fromTableSchema(tableSchema);
}

/**
 * Convert TableSchemas to a SchemaBuilder
 */
export function tableSchemasToRegistry(tableSchemas: TableSchema[]): SchemaBuilder {
  return SchemaBuilder.fromTableSchemas(tableSchemas);
}