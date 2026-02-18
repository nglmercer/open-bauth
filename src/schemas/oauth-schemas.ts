/**
 * OAuth Schemas Module
 * 
 * This module provides predefined schemas for OAuth 2.0 and security features.
 * Import and register these schemas if you want to use the built-in OAuth system.
 * 
 * @example
 * ```ts
 * import { registerOAuthSchemas, getOAuthSchemas } from 'open-bauth/schemas/oauth';
 * 
 * // Get schemas for database initialization
 * const oauthSchemas = getOAuthSchemas();
 * 
 * // Or register them with the database config
 * registerOAuthSchemas();
 * ```
 */

import { Schema, StandardFields } from "../database/schema";
import type { TableSchema } from "../database/base-controller";

// OAuth Client Schema
export const oauthClientsSchema = new Schema(
  {
    id: StandardFields.UUID,
    client_id: { type: String, required: true, unique: true },
    client_secret: String,
    client_secret_salt: String,
    client_name: { type: String, required: true },
    redirect_uris: { type: "TEXT", required: true }, // JSON array
    grant_types: { type: "TEXT", required: true }, // JSON array
    response_types: { type: "TEXT", required: true }, // JSON array
    scope: { type: String, default: "" },
    logo_uri: String,
    client_uri: String,
    policy_uri: String,
    tos_uri: String,
    jwks_uri: String,
    token_endpoint_auth_method: {
      type: String,
      default: "client_secret_basic",
    },
    is_public: { type: Boolean, default: false },
    is_active: StandardFields.Active,
    ...StandardFields.Timestamps,
  },
  {
    indexes: [
      {
        name: "idx_oauth_clients_client_id",
        columns: ["client_id"],
        unique: true,
      },
      { name: "idx_oauth_clients_active", columns: ["is_active"] },
    ],
  },
);

export const authorizationCodesSchema = new Schema(
  {
    id: StandardFields.UUID,
    code: { type: String, required: true, unique: true },
    client_id: { type: String, required: true },
    user_id: { type: String, required: true },
    redirect_uri: { type: String, required: true },
    scope: { type: String, default: "" },
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: { type: Date, required: true },
    is_used: { type: Boolean, default: false },
    used_at: Date,
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      { name: "idx_auth_codes_code", columns: ["code"], unique: true },
      { name: "idx_auth_codes_client_id", columns: ["client_id"] },
      { name: "idx_auth_codes_user_id", columns: ["user_id"] },
      { name: "idx_auth_codes_expires_at", columns: ["expires_at"] },
      { name: "idx_auth_codes_used", columns: ["is_used"] },
    ],
  },
);

export const refreshTokensSchema = new Schema(
  {
    id: StandardFields.UUID,
    token: { type: String, required: true, unique: true },
    client_id: { type: String, required: true },
    user_id: { type: String, required: true },
    scope: { type: String, default: "" },
    expires_at: { type: Date, required: true },
    is_revoked: { type: Boolean, default: false },
    revoked_at: Date,
    rotation_count: { type: Number, default: 0 },
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      { name: "idx_refresh_tokens_token", columns: ["token"], unique: true },
      { name: "idx_refresh_tokens_client_id", columns: ["client_id"] },
      { name: "idx_refresh_tokens_user_id", columns: ["user_id"] },
      { name: "idx_refresh_tokens_expires_at", columns: ["expires_at"] },
      { name: "idx_refresh_tokens_revoked", columns: ["is_revoked"] },
    ],
  },
);

export const deviceSecretsSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: { type: String, required: true },
    device_id: { type: String, required: true, unique: true },
    device_name: { type: String, required: true },
    device_type: { type: String, required: true },
    secret_hash: { type: String, required: true },
    secret_salt: String,
    is_trusted: { type: Boolean, default: false },
    last_used_at: Date,
    expires_at: Date,
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      { name: "idx_device_secrets_user_id", columns: ["user_id"] },
      {
        name: "idx_device_secrets_device_id",
        columns: ["device_id"],
        unique: true,
      },
      { name: "idx_device_secrets_trusted", columns: ["is_trusted"] },
      { name: "idx_device_secrets_expires_at", columns: ["expires_at"] },
    ],
  },
);

export const biometricCredentialsSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: { type: String, required: true },
    biometric_type: { type: String, required: true },
    credential_data: { type: String, required: true },
    device_id: String,
    is_active: StandardFields.Active,
    created_at: StandardFields.CreatedAt,
    expires_at: Date,
  },
  {
    indexes: [
      { name: "idx_biometric_creds_user_id", columns: ["user_id"] },
      { name: "idx_biometric_creds_type", columns: ["biometric_type"] },
      { name: "idx_biometric_creds_device_id", columns: ["device_id"] },
      { name: "idx_biometric_creds_active", columns: ["is_active"] },
      { name: "idx_biometric_creds_expires_at", columns: ["expires_at"] },
    ],
  },
);

export const anonymousUsersSchema = new Schema(
  {
    id: StandardFields.UUID,
    anonymous_id: { type: String, required: true, unique: true },
    session_data: { type: String, required: true }, // JSON
    created_at: StandardFields.CreatedAt,
    promoted_to_user_id: String,
    promoted_at: Date,
    expires_at: { type: Date, required: true },
  },
  {
    indexes: [
      {
        name: "idx_anon_users_anonymous_id",
        columns: ["anonymous_id"],
        unique: true,
      },
      { name: "idx_anon_users_promoted_to", columns: ["promoted_to_user_id"] },
      { name: "idx_anon_users_expires_at", columns: ["expires_at"] },
    ],
  },
);

export const userDevicesSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: { type: String, required: true },
    device_id: { type: String, required: true, unique: true },
    device_name: { type: String, required: true },
    device_type: { type: String, required: true },
    platform: String,
    user_agent: String,
    is_trusted: { type: Boolean, default: false },
    last_seen_at: Date,
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      { name: "idx_user_devices_user_id", columns: ["user_id"] },
      {
        name: "idx_user_devices_device_id",
        columns: ["device_id"],
        unique: true,
      },
      { name: "idx_user_devices_trusted", columns: ["is_trusted"] },
      { name: "idx_user_devices_last_seen", columns: ["last_seen_at"] },
    ],
  },
);

export const mfaConfigurationsSchema = new Schema(
  {
    id: StandardFields.UUID,
    user_id: { type: String, required: true },
    mfa_type: { type: String, required: true },
    is_enabled: { type: Boolean, default: false },
    is_primary: { type: Boolean, default: false },
    secret: String,
    phone_number: String,
    email: String,
    backup_codes: String, // JSON array
    configuration_data: String, // JSON
    ...StandardFields.Timestamps,
  },
  {
    indexes: [
      { name: "idx_mfa_configs_user_id", columns: ["user_id"] },
      { name: "idx_mfa_configs_type", columns: ["mfa_type"] },
      { name: "idx_mfa_configs_enabled", columns: ["is_enabled"] },
      { name: "idx_mfa_configs_primary", columns: ["is_primary"] },
    ],
  },
);

export const securityChallengesSchema = new Schema(
  {
    id: StandardFields.UUID,
    challenge_id: { type: String, required: true, unique: true },
    challenge_type: { type: String, required: true },
    challenge_data: { type: String, required: true },
    expires_at: { type: Date, required: true },
    is_solved: { type: Boolean, default: false },
    solved_at: Date,
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      {
        name: "idx_security_challenges_challenge_id",
        columns: ["challenge_id"],
        unique: true,
      },
      { name: "idx_security_challenges_type", columns: ["challenge_type"] },
      { name: "idx_security_challenges_expires_at", columns: ["expires_at"] },
      { name: "idx_security_challenges_solved", columns: ["is_solved"] },
    ],
  },
);

export const oauthSessionsSchema = new Schema(
  {
    id: StandardFields.UUID,
    session_id: { type: String, required: true, unique: true },
    client_id: { type: String, required: true },
    user_id: String,
    auth_time: Date,
    expires_at: { type: Date, required: true },
    is_active: StandardFields.Active,
    session_data: String, // JSON
    created_at: StandardFields.CreatedAt,
  },
  {
    indexes: [
      {
        name: "idx_oauth_sessions_session_id",
        columns: ["session_id"],
        unique: true,
      },
      { name: "idx_oauth_sessions_client_id", columns: ["client_id"] },
      { name: "idx_oauth_sessions_user_id", columns: ["user_id"] },
      { name: "idx_oauth_sessions_expires_at", columns: ["expires_at"] },
      { name: "idx_oauth_sessions_active", columns: ["is_active"] },
    ],
  },
);

// Schema map for easy access
const oauthSchemasMap: Record<string, Schema> = {
  oauth_clients: oauthClientsSchema,
  authorization_codes: authorizationCodesSchema,
  refresh_tokens: refreshTokensSchema,
  device_secrets: deviceSecretsSchema,
  biometric_credentials: biometricCredentialsSchema,
  anonymous_users: anonymousUsersSchema,
  user_devices: userDevicesSchema,
  mfa_configurations: mfaConfigurationsSchema,
  security_challenges: securityChallengesSchema,
  oauth_sessions: oauthSessionsSchema,
};

/**
 * Get all OAuth schemas as TableSchema array
 */
export function getOAuthSchemas(): TableSchema[] {
  return Object.entries(oauthSchemasMap).map(([tableName, schema]) =>
    schema.toTableSchema(tableName),
  );
}

/**
 * Get a specific OAuth schema by table name
 */
export function getOAuthSchema(tableName: string): TableSchema | null {
  const schema = oauthSchemasMap[tableName];
  return schema ? schema.toTableSchema(tableName) : null;
}

/**
 * Get all OAuth schema instances (for advanced usage)
 */
export function getOAuthSchemaInstances(): Record<string, Schema> {
  return { ...oauthSchemasMap };
}

/**
 * Register OAuth schemas with the database config
 * This extends the global database configuration with OAuth schemas
 */
export function registerOAuthSchemas(): void {
  const { setDatabaseConfig, getDatabaseConfig, createSchemaExtension } = require("../database/config");
  const currentConfig = getDatabaseConfig();
  
  const schemaExtensions: Record<string, ReturnType<typeof createSchemaExtension>> = {};
  
  Object.entries(oauthSchemasMap).forEach(([tableName, schema]) => {
    schemaExtensions[tableName] = createSchemaExtension(
      schema.getColumns(),
      [],
      [],
    );
  });

  setDatabaseConfig({
    ...currentConfig,
    schemaExtensions: {
      ...currentConfig.schemaExtensions,
      ...schemaExtensions,
    },
  });
}

/**
 * Get OAuth schema extensions for use with database config
 */
export function getOAuthSchemaExtensions(): Record<
  string,
  Omit<TableSchema, "tableName">
> {
  const result: Record<string, Omit<TableSchema, "tableName">> = {};

  Object.entries(oauthSchemasMap).forEach(([key, schemaInstance]) => {
    const raw = schemaInstance.toTableSchema("dummy");
    result[key] = {
      columns: raw.columns,
      indexes: raw.indexes,
    };
  });

  return result;
}

// Export schema map
export const OAUTH_SCHEMAS = oauthSchemasMap;