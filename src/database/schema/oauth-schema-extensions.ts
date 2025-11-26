import { Schema } from "./schema"; // Importamos tu nueva clase
import type { TableSchema } from "../base-controller";
import { setDatabaseConfig, createSchemaExtension } from "../config";

// Helper para reutilizar columnas comunes en la sintaxis de Schema
const CommonFields = {
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
};

/**
 * OAuth 2.0 Client Schema
 */
export const oauthClientsSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  client_id: { type: String, required: true, unique: true },
  client_secret: String,
  client_secret_salt: String,
  client_name: { type: String, required: true },
  redirect_uris: { type: "TEXT", required: true }, // JSON array
  grant_types: { type: "TEXT", required: true },   // JSON array
  response_types: { type: "TEXT", required: true },// JSON array
  scope: { type: String, default: "" },
  logo_uri: String,
  client_uri: String,
  policy_uri: String,
  tos_uri: String,
  jwks_uri: String,
  token_endpoint_auth_method: { type: String, default: "client_secret_basic" },
  is_public: { type: Boolean, default: false },
  is_active: { type: Boolean, default: true },
  created_at: CommonFields.createdAt,
  updated_at: CommonFields.updatedAt
}, {
  indexes: [
    { name: "idx_oauth_clients_client_id", columns: ["client_id"], unique: true },
    { name: "idx_oauth_clients_active", columns: ["is_active"] },
  ]
});

/**
 * Authorization Codes Schema
 */
export const authorizationCodesSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
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
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_auth_codes_code", columns: ["code"], unique: true },
    { name: "idx_auth_codes_client_id", columns: ["client_id"] },
    { name: "idx_auth_codes_user_id", columns: ["user_id"] },
    { name: "idx_auth_codes_expires_at", columns: ["expires_at"] },
    { name: "idx_auth_codes_used", columns: ["is_used"] },
  ]
});

/**
 * Refresh Tokens Schema
 */
export const refreshTokensSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  token: { type: String, required: true, unique: true },
  client_id: { type: String, required: true },
  user_id: { type: String, required: true },
  scope: { type: String, default: "" },
  expires_at: { type: Date, required: true },
  is_revoked: { type: Boolean, default: false },
  revoked_at: Date,
  rotation_count: { type: Number, default: 0 },
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_refresh_tokens_token", columns: ["token"], unique: true },
    { name: "idx_refresh_tokens_client_id", columns: ["client_id"] },
    { name: "idx_refresh_tokens_user_id", columns: ["user_id"] },
    { name: "idx_refresh_tokens_expires_at", columns: ["expires_at"] },
    { name: "idx_refresh_tokens_revoked", columns: ["is_revoked"] },
  ]
});

/**
 * Device Secrets Schema (for SSO)
 */
export const deviceSecretsSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  user_id: { type: String, required: true },
  device_id: { type: String, required: true, unique: true },
  device_name: { type: String, required: true },
  device_type: { type: String, required: true },
  secret_hash: { type: String, required: true },
  secret_salt: String,
  is_trusted: { type: Boolean, default: false },
  last_used_at: Date,
  expires_at: Date,
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_device_secrets_user_id", columns: ["user_id"] },
    { name: "idx_device_secrets_device_id", columns: ["device_id"], unique: true },
    { name: "idx_device_secrets_trusted", columns: ["is_trusted"] },
    { name: "idx_device_secrets_expires_at", columns: ["expires_at"] },
  ]
});

/**
 * Biometric Credentials Schema
 */
export const biometricCredentialsSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  user_id: { type: String, required: true },
  biometric_type: { type: String, required: true },
  credential_data: { type: String, required: true }, // Encrypted
  device_id: String,
  is_active: { type: Boolean, default: true },
  created_at: CommonFields.createdAt,
  expires_at: Date
}, {
  indexes: [
    { name: "idx_biometric_creds_user_id", columns: ["user_id"] },
    { name: "idx_biometric_creds_type", columns: ["biometric_type"] },
    { name: "idx_biometric_creds_device_id", columns: ["device_id"] },
    { name: "idx_biometric_creds_active", columns: ["is_active"] },
    { name: "idx_biometric_creds_expires_at", columns: ["expires_at"] },
  ]
});

/**
 * Anonymous Users Schema
 */
export const anonymousUsersSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  anonymous_id: { type: String, required: true, unique: true },
  session_data: { type: String, required: true }, // JSON
  created_at: CommonFields.createdAt,
  promoted_to_user_id: String,
  promoted_at: Date,
  expires_at: { type: Date, required: true }
}, {
  indexes: [
    { name: "idx_anon_users_anonymous_id", columns: ["anonymous_id"], unique: true },
    { name: "idx_anon_users_promoted_to", columns: ["promoted_to_user_id"] },
    { name: "idx_anon_users_expires_at", columns: ["expires_at"] },
  ]
});

/**
 * User Devices Schema
 */
export const userDevicesSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  user_id: { type: String, required: true },
  device_id: { type: String, required: true, unique: true },
  device_name: { type: String, required: true },
  device_type: { type: String, required: true },
  platform: String,
  user_agent: String,
  is_trusted: { type: Boolean, default: false },
  last_seen_at: Date,
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_user_devices_user_id", columns: ["user_id"] },
    { name: "idx_user_devices_device_id", columns: ["device_id"], unique: true },
    { name: "idx_user_devices_trusted", columns: ["is_trusted"] },
    { name: "idx_user_devices_last_seen", columns: ["last_seen_at"] },
  ]
});

/**
 * MFA Configurations Schema
 */
export const mfaConfigurationsSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  user_id: { type: String, required: true },
  mfa_type: { type: String, required: true },
  is_enabled: { type: Boolean, default: false },
  is_primary: { type: Boolean, default: false },
  secret: String,
  phone_number: String,
  email: String,
  backup_codes: String, // JSON array
  configuration_data: String, // JSON
  created_at: CommonFields.createdAt,
  updated_at: CommonFields.updatedAt
}, {
  indexes: [
    { name: "idx_mfa_configs_user_id", columns: ["user_id"] },
    { name: "idx_mfa_configs_type", columns: ["mfa_type"] },
    { name: "idx_mfa_configs_enabled", columns: ["is_enabled"] },
    { name: "idx_mfa_configs_primary", columns: ["is_primary"] },
  ]
});

/**
 * Security Challenges Schema
 */
export const securityChallengesSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  challenge_id: { type: String, required: true, unique: true },
  challenge_type: { type: String, required: true },
  challenge_data: { type: String, required: true },
  expires_at: { type: Date, required: true },
  is_solved: { type: Boolean, default: false },
  solved_at: Date,
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_security_challenges_challenge_id", columns: ["challenge_id"], unique: true },
    { name: "idx_security_challenges_type", columns: ["challenge_type"] },
    { name: "idx_security_challenges_expires_at", columns: ["expires_at"] },
    { name: "idx_security_challenges_solved", columns: ["is_solved"] },
  ]
});

/**
 * OAuth 2.0 Session Schema
 */
export const oauthSessionsSchema = new Schema({
  id: { type: "TEXT", primaryKey: true, default: "(lower(hex(randomblob(16))))" },
  session_id: { type: String, required: true, unique: true },
  client_id: { type: String, required: true },
  user_id: String,
  auth_time: Date,
  expires_at: { type: Date, required: true },
  is_active: { type: Boolean, default: true },
  session_data: String, // JSON
  created_at: CommonFields.createdAt
}, {
  indexes: [
    { name: "idx_oauth_sessions_session_id", columns: ["session_id"], unique: true },
    { name: "idx_oauth_sessions_client_id", columns: ["client_id"] },
    { name: "idx_oauth_sessions_user_id", columns: ["user_id"] },
    { name: "idx_oauth_sessions_expires_at", columns: ["expires_at"] },
    { name: "idx_oauth_sessions_active", columns: ["is_active"] },
  ]
});

// ==========================================
// Adaptadores de Compatibilidad (Importante)
// ==========================================

const schemasMap = {
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
 * Function to get all OAuth schema extensions in "Raw" TableSchema format
 * for compatibility with config
 */
export function getOAuthSchemaExtensions(): Record<string, Omit<TableSchema, "tableName">> {
  const result: Record<string, Omit<TableSchema, "tableName">> = {};
  
  // Convertimos las instancias de Schema a objetos planos que config.ts entiende
  Object.entries(schemasMap).forEach(([key, schemaInstance]) => {
    // Usamos un nombre dummy porque aquí solo nos importan las columnas/índices
    const raw = schemaInstance.toTableSchema("dummy");
    result[key] = {
      columns: raw.columns,
      indexes: raw.indexes
    };
  });
  
  return result;
}

/**
 * Function to get OAuth schemas as complete TableSchema objects
 */
export function getOAuthSchemas(): TableSchema[] {
  return Object.entries(schemasMap).map(([tableName, schemaInstance]) => 
    schemaInstance.toTableSchema(tableName)
  );
}

/**
 * Function to register OAuth schema extensions with the database configuration
 */
export function registerOAuthSchemaExtensions(): void {
  
  const schemaExtensions: Record<string, any> = {};
  
  Object.entries(schemasMap).forEach(([tableName, schemaInstance]) => {
    // Extraemos las columnas SQL puras de la instancia de Schema
    const columns = schemaInstance.getColumns();
    
    schemaExtensions[tableName] = createSchemaExtension(
      columns, // additionalColumns
      [],      // modifiedColumns
      [],      // removedColumns
    );
  });
  
  // Update the global database configuration
  setDatabaseConfig({
    schemaExtensions,
  });
}