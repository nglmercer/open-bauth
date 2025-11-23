// src/database/oauth-schema-extensions.ts

import type { TableSchema, ColumnDefinition } from "./base-controller";
import { COMMON_COLUMNS } from "./config";

/**
 * OAuth 2.0 Client Schema
 */
export const oauthClientsSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "client_id", type: "TEXT", unique: true, notNull: true },
    { name: "client_secret", type: "TEXT" },
    { name: "client_secret_salt", type: "TEXT" },
    { name: "client_name", type: "TEXT", notNull: true },
    { name: "redirect_uris", type: "TEXT", notNull: true }, // JSON array
    { name: "grant_types", type: "TEXT", notNull: true }, // JSON array
    { name: "response_types", type: "TEXT", notNull: true }, // JSON array
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "logo_uri", type: "TEXT" },
    { name: "client_uri", type: "TEXT" },
    { name: "policy_uri", type: "TEXT" },
    { name: "tos_uri", type: "TEXT" },
    { name: "jwks_uri", type: "TEXT" },
    { name: "token_endpoint_auth_method", type: "TEXT", defaultValue: "client_secret_basic" },
    { name: "is_public", type: "BOOLEAN", defaultValue: false },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    COMMON_COLUMNS.createdAt,
    COMMON_COLUMNS.updatedAt,
  ],
  indexes: [
    { name: "idx_oauth_clients_client_id", columns: ["client_id"], unique: true },
    { name: "idx_oauth_clients_active", columns: ["is_active"] },
  ],
};

/**
 * Authorization Codes Schema
 */
export const authorizationCodesSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "code", type: "TEXT", unique: true, notNull: true },
    { name: "client_id", type: "TEXT", notNull: true },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "redirect_uri", type: "TEXT", notNull: true },
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "state", type: "TEXT" },
    { name: "nonce", type: "TEXT" },
    { name: "code_challenge", type: "TEXT" },
    { name: "code_challenge_method", type: "TEXT" },
    { name: "expires_at", type: "DATETIME", notNull: true },
    { name: "is_used", type: "BOOLEAN", defaultValue: false },
    { name: "used_at", type: "DATETIME" },
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_auth_codes_code", columns: ["code"], unique: true },
    { name: "idx_auth_codes_client_id", columns: ["client_id"] },
    { name: "idx_auth_codes_user_id", columns: ["user_id"] },
    { name: "idx_auth_codes_expires_at", columns: ["expires_at"] },
    { name: "idx_auth_codes_used", columns: ["is_used"] },
  ],
};

/**
 * Refresh Tokens Schema
 */
export const refreshTokensSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "token", type: "TEXT", unique: true, notNull: true },
    { name: "client_id", type: "TEXT", notNull: true },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "scope", type: "TEXT", defaultValue: "" },
    { name: "expires_at", type: "DATETIME", notNull: true },
    { name: "is_revoked", type: "BOOLEAN", defaultValue: false },
    { name: "revoked_at", type: "DATETIME" },
    { name: "rotation_count", type: "INTEGER", defaultValue: 0 },
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_refresh_tokens_token", columns: ["token"], unique: true },
    { name: "idx_refresh_tokens_client_id", columns: ["client_id"] },
    { name: "idx_refresh_tokens_user_id", columns: ["user_id"] },
    { name: "idx_refresh_tokens_expires_at", columns: ["expires_at"] },
    { name: "idx_refresh_tokens_revoked", columns: ["is_revoked"] },
  ],
};

/**
 * Device Secrets Schema (for SSO)
 */
export const deviceSecretsSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "device_id", type: "TEXT", unique: true, notNull: true },
    { name: "device_name", type: "TEXT", notNull: true },
    { name: "device_type", type: "TEXT", notNull: true },
    { name: "secret_hash", type: "TEXT", notNull: true },
    { name: "secret_salt", type: "TEXT" },
    { name: "is_trusted", type: "BOOLEAN", defaultValue: false },
    { name: "last_used_at", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME" },
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_device_secrets_user_id", columns: ["user_id"] },
    { name: "idx_device_secrets_device_id", columns: ["device_id"], unique: true },
    { name: "idx_device_secrets_trusted", columns: ["is_trusted"] },
    { name: "idx_device_secrets_expires_at", columns: ["expires_at"] },
  ],
};

/**
 * Biometric Credentials Schema
 */
export const biometricCredentialsSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "biometric_type", type: "TEXT", notNull: true },
    { name: "credential_data", type: "TEXT", notNull: true }, // Encrypted biometric template
    { name: "device_id", type: "TEXT" },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    COMMON_COLUMNS.createdAt,
    { name: "expires_at", type: "DATETIME" },
  ],
  indexes: [
    { name: "idx_biometric_creds_user_id", columns: ["user_id"] },
    { name: "idx_biometric_creds_type", columns: ["biometric_type"] },
    { name: "idx_biometric_creds_device_id", columns: ["device_id"] },
    { name: "idx_biometric_creds_active", columns: ["is_active"] },
    { name: "idx_biometric_creds_expires_at", columns: ["expires_at"] },
  ],
};

/**
 * Anonymous Users Schema
 */
export const anonymousUsersSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "anonymous_id", type: "TEXT", unique: true, notNull: true },
    { name: "session_data", type: "TEXT", notNull: true }, // JSON string
    COMMON_COLUMNS.createdAt,
    { name: "promoted_to_user_id", type: "TEXT" },
    { name: "promoted_at", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME", notNull: true },
  ],
  indexes: [
    { name: "idx_anon_users_anonymous_id", columns: ["anonymous_id"], unique: true },
    { name: "idx_anon_users_promoted_to", columns: ["promoted_to_user_id"] },
    { name: "idx_anon_users_expires_at", columns: ["expires_at"] },
  ],
};

/**
 * User Devices Schema
 */
export const userDevicesSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "device_id", type: "TEXT", unique: true, notNull: true },
    { name: "device_name", type: "TEXT", notNull: true },
    { name: "device_type", type: "TEXT", notNull: true },
    { name: "platform", type: "TEXT" },
    { name: "user_agent", type: "TEXT" },
    { name: "is_trusted", type: "BOOLEAN", defaultValue: false },
    { name: "last_seen_at", type: "DATETIME" },
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_user_devices_user_id", columns: ["user_id"] },
    { name: "idx_user_devices_device_id", columns: ["device_id"], unique: true },
    { name: "idx_user_devices_trusted", columns: ["is_trusted"] },
    { name: "idx_user_devices_last_seen", columns: ["last_seen_at"] },
  ],
};

/**
 * MFA Configurations Schema
 */
export const mfaConfigurationsSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "user_id", type: "TEXT", notNull: true },
    { name: "mfa_type", type: "TEXT", notNull: true },
    { name: "is_enabled", type: "BOOLEAN", defaultValue: false },
    { name: "is_primary", type: "BOOLEAN", defaultValue: false },
    { name: "secret", type: "TEXT" }, // For TOTP
    { name: "phone_number", type: "TEXT" }, // For SMS
    { name: "email", type: "TEXT" }, // For email
    { name: "backup_codes", type: "TEXT" }, // Encrypted backup codes (JSON array)
    { name: "configuration_data", type: "TEXT" }, // JSON for additional config
    COMMON_COLUMNS.createdAt,
    COMMON_COLUMNS.updatedAt,
  ],
  indexes: [
    { name: "idx_mfa_configs_user_id", columns: ["user_id"] },
    { name: "idx_mfa_configs_type", columns: ["mfa_type"] },
    { name: "idx_mfa_configs_enabled", columns: ["is_enabled"] },
    { name: "idx_mfa_configs_primary", columns: ["is_primary"] },
  ],
};

/**
 * Security Challenges Schema
 */
export const securityChallengesSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "challenge_id", type: "TEXT", unique: true, notNull: true },
    { name: "challenge_type", type: "TEXT", notNull: true },
    { name: "challenge_data", type: "TEXT", notNull: true },
    { name: "expires_at", type: "DATETIME", notNull: true },
    { name: "is_solved", type: "BOOLEAN", defaultValue: false },
    { name: "solved_at", type: "DATETIME" },
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_security_challenges_challenge_id", columns: ["challenge_id"], unique: true },
    { name: "idx_security_challenges_type", columns: ["challenge_type"] },
    { name: "idx_security_challenges_expires_at", columns: ["expires_at"] },
    { name: "idx_security_challenges_solved", columns: ["is_solved"] },
  ],
};

/**
 * OAuth 2.0 Session Schema (for tracking OAuth sessions)
 */
export const oauthSessionsSchema: Omit<TableSchema, "tableName"> = {
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    { name: "session_id", type: "TEXT", unique: true, notNull: true },
    { name: "client_id", type: "TEXT", notNull: true },
    { name: "user_id", type: "TEXT" },
    { name: "auth_time", type: "DATETIME" },
    { name: "expires_at", type: "DATETIME", notNull: true },
    { name: "is_active", type: "BOOLEAN", defaultValue: true },
    { name: "session_data", type: "TEXT" }, // JSON string for additional session data
    COMMON_COLUMNS.createdAt,
  ],
  indexes: [
    { name: "idx_oauth_sessions_session_id", columns: ["session_id"], unique: true },
    { name: "idx_oauth_sessions_client_id", columns: ["client_id"] },
    { name: "idx_oauth_sessions_user_id", columns: ["user_id"] },
    { name: "idx_oauth_sessions_expires_at", columns: ["expires_at"] },
    { name: "idx_oauth_sessions_active", columns: ["is_active"] },
  ],
};

/**
 * Function to get all OAuth schema extensions
 */
export function getOAuthSchemaExtensions(): Record<string, Omit<TableSchema, "tableName">> {
  return {
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
}
/**
 * Function to get OAuth schemas as complete TableSchema objects
 */
export function getOAuthSchemas(): TableSchema[] {
  const extensions = getOAuthSchemaExtensions();
  
  // Convert each schema extension to a complete TableSchema
  return Object.entries(extensions).map(([tableName, schema]) => ({
    tableName,
    ...schema,
  }));
}

/**
 * Function to register OAuth schema extensions with the database configuration
 */
export function registerOAuthSchemaExtensions(): void {
  const { setDatabaseConfig, createSchemaExtension } = require("./config");
  
  const extensions = getOAuthSchemaExtensions();
  const schemaExtensions: Record<string, any> = {};
  
  // Convert each schema to a schema extension format
  Object.entries(extensions).forEach(([tableName, schema]) => {
    schemaExtensions[tableName] = createSchemaExtension(
      schema.columns, // additionalColumns
      [], // modifiedColumns (none for now)
      [], // removedColumns (none for now)
    );
  });
  
  // Update the global database configuration
  setDatabaseConfig({
    schemaExtensions,
  });
}