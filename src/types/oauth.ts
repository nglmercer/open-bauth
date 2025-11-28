// src/types/oauth.ts

import type { User } from "../types/auth";
import type { BaseEntity, EntityId, UserId } from "./common";

/**
 * OAuth 2.0 Client Types
 */
export interface OAuthClient extends BaseEntity {
  id: string;
  client_id: string;
  client_secret?: string;
  client_secret_salt?: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: OAuthGrantType[];
  response_types: OAuthResponseType[];
  scope: string;
  logo_uri?: string;
  client_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  jwks_uri?: string;
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  is_public: boolean;
  is_active: boolean;
}

export interface CreateOAuthClientData {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  grant_types?: OAuthGrantType[];
  response_types?: OAuthResponseType[];
  scope?: string;
  logo_uri?: string;
  client_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  jwks_uri?: string;
  token_endpoint_auth_method?: TokenEndpointAuthMethod;
  is_public?: boolean;
  is_active?: boolean;
}

export interface UpdateOAuthClientData {
  client_name?: string;
  redirect_uris?: string[];
  grant_types?: OAuthGrantType[];
  response_types?: OAuthResponseType[];
  scope?: string;
  logo_uri?: string;
  client_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  jwks_uri?: string;
  token_endpoint_auth_method?: TokenEndpointAuthMethod;
  is_public?: boolean;
  is_active?: boolean;
}

/**
 * Authorization Codes
 */
export interface AuthorizationCode extends BaseEntity {
  id: string;
  code: string;
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: PKCEMethod;
  expires_at: string;
  is_used: boolean;
  used_at?: string;
}

/**
 * Refresh Tokens
 */
export interface RefreshToken extends BaseEntity {
  id: string;
  token: string;
  client_id: string;
  user_id: string;
  scope: string;
  expires_at: string;
  is_revoked: boolean;
  revoked_at?: string;
  rotation_count?: number;
}

/**
 * Device Secrets for SSO
 */
export interface DeviceSecret extends BaseEntity {
  id: string;
  user_id: string;
  device_id: string;
  device_name: string;
  device_type: DeviceType;
  secret_hash: string;
  secret_salt?: string;
  is_trusted: boolean;
  last_used_at?: string;
  expires_at?: string;
}

/**
 * Biometric Credentials
 */
export interface BiometricCredential extends BaseEntity {
  id: string;
  user_id: string;
  biometric_type: BiometricType;
  credential_data: string; // Encrypted biometric template
  device_id?: string;
  is_active: boolean;
  created_at: string;
  expires_at?: string;
}

/**
 * Anonymous Users
 */
export interface AnonymousUser extends BaseEntity {
  id: string;
  anonymous_id: string;
  session_data: string; // JSON string
  created_at: string;
  promoted_to_user_id?: string;
  promoted_at?: string;
  expires_at: string;
}

/**
 * User Devices
 */
export interface UserDevice extends BaseEntity {
  id: string;
  user_id: string;
  device_id: string;
  device_name: string;
  device_type: DeviceType;
  platform?: string;
  user_agent?: string;
  is_trusted: boolean;
  last_seen_at?: string;
  created_at: string;
}

/**
 * MFA Configurations
 */
export interface MFAConfiguration extends BaseEntity {
  id: string;
  user_id: string;
  mfa_type: MFAType;
  is_enabled: boolean;
  is_primary: boolean;
  secret?: string; // For TOTP
  phone_number?: string; // For SMS
  email?: string; // For email
  backup_codes?: string[]; // Encrypted backup codes
  configuration_data?: string; // JSON for additional config
  created_at: string;
  updated_at: string;
}

/**
 * OAuth 2.0 Enums
 */
export enum OAuthGrantType {
  AUTHORIZATION_CODE = "authorization_code",
  IMPLICIT = "implicit",
  RESOURCE_OWNER_PASSWORD_CREDENTIALS = "password",
  CLIENT_CREDENTIALS = "client_credentials",
  REFRESH_TOKEN = "refresh_token",
  DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code",
  JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer",
  SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer",
}

export enum OAuthResponseType {
  CODE = "code",
  TOKEN = "token",
  ID_TOKEN = "id_token",
  NONE = "none",
}

export enum TokenEndpointAuthMethod {
  CLIENT_SECRET_BASIC = "client_secret_basic",
  CLIENT_SECRET_POST = "client_secret_post",
  CLIENT_SECRET_JWT = "client_secret_jwt",
  PRIVATE_KEY_JWT = "private_key_jwt",
  NONE = "none",
}

export enum PKCEMethod {
  PLAIN = "plain",
  S256 = "S256",
}

export enum DeviceType {
  DESKTOP = "desktop",
  MOBILE = "mobile",
  TABLET = "tablet",
  TV = "tv",
  WEARABLE = "wearable",
  IOT = "iot",
  UNKNOWN = "unknown",
}

export enum BiometricType {
  FINGERPRINT = "fingerprint",
  FACE = "face",
  VOICE = "voice",
  IRIS = "iris",
  RETINA = "retina",
  PALM = "palm",
}

export enum MFAType {
  TOTP = "totp",
  SMS = "sms",
  EMAIL = "email",
  PUSH = "push",
  HARDWARE_TOKEN = "hardware_token",
  BACKUP_CODE = "backup_code",
}

/**
 * OAuth 2.0 Request/Response Types
 */
export interface AuthorizationRequest {
  response_type: OAuthResponseType;
  client_id: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: PKCEMethod;
  prompt?: "none" | "login" | "consent" | "select_account";
  max_age?: number;
  ui_locales?: string;
  id_token_hint?: string;
  login_hint?: string;
  acr_values?: string;
}

export interface AuthorizationResponse {
  code?: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  state?: string;
  id_token?: string;
  error?: OAuthErrorType;
  error_description?: string;
  error_uri?: string;
}

export interface TokenRequest {
  grant_type: OAuthGrantType;
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  scope?: string;
  code_verifier?: string;
  device_code?: string;
  assertion?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  error?: OAuthErrorType;
  error_description?: string;
  error_uri?: string;
}

export interface DeviceAuthorizationRequest {
  client_id: string;
  scope?: string;
}

export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export interface IntrospectionRequest {
  token: string;
  token_type_hint?: "access_token" | "refresh_token";
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  jti?: string;
}

export interface RevocationRequest {
  token: string;
  token_type_hint?: "access_token" | "refresh_token";
  client_id?: string;
  client_secret?: string;
}

/**
 * OAuth 2.0 Error Types
 */
export enum OAuthErrorType {
  INVALID_REQUEST = "invalid_request",
  UNAUTHORIZED_CLIENT = "unauthorized_client",
  ACCESS_DENIED = "access_denied",
  UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type",
  INVALID_SCOPE = "invalid_scope",
  SERVER_ERROR = "server_error",
  TEMPORARILY_UNAVAILABLE = "temporarily_unavailable",
  INVALID_CLIENT = "invalid_client",
  INVALID_GRANT = "invalid_grant",
  UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type",
  INVALID_CLIENT_CREDENTIALS = "invalid_client_credentials",
  EXPIRED_TOKEN = "expired_token",
  REDIRECT_URI_MISMATCH = "redirect_uri_mismatch",
  SLOW_DOWN = "slow_down",
  AUTHORIZATION_PENDING = "authorization_pending",
  INVALID_TOKEN = "invalid_token",
}

/**
 * OAuth 2.0 Context
 */
export interface OAuthContext {
  client?: OAuthClient;
  user?: User;
  scopes: string[];
  grant_type?: OAuthGrantType;
  response_type?: OAuthResponseType;
  redirect_uri?: string;
  state?: string;
  nonce?: string;
  is_authenticated: boolean;
  consent_given?: boolean;
}

/**
 * Security Types
 */
export interface PKCEChallenge {
  code_challenge: string;
  code_challenge_method: PKCEMethod;
  code_verifier: string;
}

export interface DPoPProof {
  htu: string; // HTTP URI
  htm: string; // HTTP Method
  jkt: string; // JWK Thumbprint
  iat: number; // Issued At
  jti: string; // JWT ID
}

export interface SecurityChallenge {
  challenge_id: string;
  challenge_type: ChallengeType;
  challenge_data: string;
  expires_at: string;
  is_solved: boolean;
  solved_at?: string;
}

export enum ChallengeType {
  CAPTCHA = "captcha",
  BIOMETRIC = "biometric",
  DEVICE_VERIFICATION = "device_verification",
  EMAIL_VERIFICATION = "email_verification",
  SMS_VERIFICATION = "sms_verification",
  MFA = "mfa",
}

/**
 * Repository Interfaces
 */
export interface OAuthClientRepositoryInterface {
  findById(id: string): Promise<OAuthClient | null>;
  findByClientId(clientId: string): Promise<OAuthClient | null>;
  create(data: CreateOAuthClientData): Promise<OAuthClient>;
  update(id: string, data: UpdateOAuthClientData): Promise<OAuthClient>;
  delete(id: string): Promise<boolean>;
  authenticateClient(
    clientId: string,
    clientSecret?: string,
  ): Promise<OAuthClient | null>;
  validateRedirectUri(clientId: string, redirectUri: string): Promise<boolean>;
}

export interface AuthorizationCodeRepositoryInterface {
  findById(id: string): Promise<AuthorizationCode | null>;
  findByCode(code: string): Promise<AuthorizationCode | null>;
  create(data: Partial<AuthorizationCode>): Promise<AuthorizationCode>;
  markAsUsed(id: string): Promise<boolean>;
  delete(id: string): Promise<boolean>;
  cleanupExpired(): Promise<number>;
}

export interface RefreshTokenRepositoryInterface {
  findById(id: string): Promise<RefreshToken | null>;
  findByToken(token: string): Promise<RefreshToken | null>;
  create(data: Partial<RefreshToken>): Promise<RefreshToken>;
  revoke(id: string): Promise<boolean>;
  revokeByUserId(userId: string): Promise<number>;
  rotate(id: string, newToken: string): Promise<RefreshToken>;
  cleanupExpired(): Promise<number>;
}

/**
 * OIDC (OpenID Connect) Extensions
 */
export interface OIDCUserInfo {
  sub: string; // Subject (user ID)
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  updated_at?: number;
}

export interface OIDCClaims {
  auth_time?: number;
  acr?: string;
  amr?: string[];
  azp?: string; // Authorized party
  at_hash?: string;
  c_hash?: string;
  nonce?: string;
  s_hash?: string;
}

/**
 * JWT Token Extensions for OAuth 2.0
 */
export interface OAuthJWTPayload {
  iss?: string; // Issuer
  sub: string; // Subject (user ID)
  aud: string[] | string; // Audience
  exp: number; // Expiration time
  iat: number; // Issued at
  jti: string; // JWT ID
  scope?: string; // OAuth 2.0 scopes
  client_id?: string; // OAuth 2.0 client ID
  token_type?: "access_token" | "refresh_token";
  // OIDC claims
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  // Additional claims
  [key: string]: unknown;
}
