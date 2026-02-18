/**
 * Schemas Module
 * 
 * This module provides optional predefined schemas for authentication and OAuth.
 * These schemas are NOT included by default - you must explicitly import and register them.
 * 
 * @example
 * ```ts
 * // Import and use auth schemas
 * import { getAuthSchemas } from 'open-bauth/schemas';
 * 
 * // Import and use OAuth schemas
 * import { getOAuthSchemas } from 'open-bauth/schemas';
 * 
 * // Or get all schemas at once
 * import { getAllSchemas } from 'open-bauth/schemas';
 * ```
 */

// ==================== Core Schema Utilities ====================
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
export {
  mapSqlTypeToZodType,
  mapConstructorToZodType,
  flexibleBoolean,
} from "../database/schema/zod-mapping";
export type { ConstructorType } from "../database/schema/zod-mapping";
export type { TableSchema, ColumnDefinition } from "../database/base-controller";

// ==================== Auth Schemas ====================
export {
  usersSchema,
  rolesSchema,
  permissionsSchema,
  userRolesSchema,
  rolePermissionsSchema,
  sessionsSchema,
  getAuthSchemas,
  getAuthSchema,
  getAuthSchemaInstances,
  getAuthZodSchemas,
  getAuthTypedZodSchemas,
  authSchemas,
  schemas as authSchemaInstances,
  zodSchemas as authZodSchemas,
  typedZodSchemas as authTypedZodSchemas,
  SchemaRegistry,
  SchemaBuilder,
  emptySchemas,
  createSchemaModule,
  mergeSchemaModules,
  tableSchemaToSchema,
  tableSchemasToRegistry,
} from "./auth-schemas";

// ==================== OAuth Schemas ====================
export {
  oauthClientsSchema,
  authorizationCodesSchema,
  refreshTokensSchema,
  deviceSecretsSchema,
  biometricCredentialsSchema,
  anonymousUsersSchema,
  userDevicesSchema,
  mfaConfigurationsSchema,
  securityChallengesSchema,
  oauthSessionsSchema,
  getOAuthSchemas,
  getOAuthSchema,
  getOAuthSchemaInstances,
  getOAuthSchemaExtensions,
  OAUTH_SCHEMAS,
} from "./oauth-schemas";

// ==================== Combined Helpers ====================

import { getAuthSchemas as _getAuthSchemas, authSchemas as _authSchemas } from "./auth-schemas";
import { getOAuthSchemas as _getOAuthSchemas, OAUTH_SCHEMAS as _OAUTH_SCHEMAS } from "./oauth-schemas";
import type { TableSchema } from "../database/base-controller";

/**
 * Get all predefined schemas (auth + OAuth)
 */
export function getAllSchemas(): TableSchema[] {
  return [..._getAuthSchemas(), ..._getOAuthSchemas()];
}

/**
 * All schemas as a single array (pre-computed)
 */
export const allSchemas: TableSchema[] = [
  ..._authSchemas,
  ...Object.entries(_OAUTH_SCHEMAS).map(([name, schema]) => schema.toTableSchema(name))
];

/**
 * Schema categories for easy access
 */
export const schemaCategories = {
  auth: _authSchemas,
  oauth: Object.entries(_OAUTH_SCHEMAS).map(([name, schema]) => schema.toTableSchema(name)),
};