export const ServiceErrors = {
    // Common
    DATABASE_ERROR: "Database operation failed",
    NOT_FOUND: "Resource not found",
    VALIDATION_ERROR: "Validation failed",

    // Auth Service
    EMAIL_REQUIRED: "Email is required",
    PASSWORD_REQUIRED: "Password is required",
    USER_ALREADY_EXISTS: "A user with this email already exists",
    INVALID_CREDENTIALS: "Invalid credentials",
    NEW_PASSWORD_EMPTY: "New password cannot be empty",
    USER_NOT_FOUND: "User not found",
    FAILED_TO_FIND_USER: "Failed to find user",
    FAILED_TO_CREATE_USER: "Failed to create user",
    FAILED_TO_UPDATE_USER: "Failed to update user",
    FAILED_TO_DELETE_USER: "Failed to delete user",
    ROLE_NOT_FOUND: "Role not found",
    USER_NO_ROLE: "User does not have this role",

    // Enhanced User Service
    ANONYMOUS_CREATE_FAILED: "Failed to create anonymous user",
    ANONYMOUS_NOT_FOUND: "Anonymous user not found",
    DEVICE_NOT_FOUND: "Device not found",
    DEVICE_UPDATE_FAILED: "Failed to update device",
    DEVICE_REGISTER_FAILED: "Failed to register device",
    DEVICE_TRUST_FAILED: "Failed to trust device",
    DEVICE_SECRET_CREATE_FAILED: "Failed to create device secret",
    DEVICE_SECRET_NOT_FOUND: "Device secret not found",
    DEVICE_SECRET_EXPIRED: "Device secret has expired",
    DEVICE_SECRET_INVALID: "Invalid device secret",
    BIOMETRIC_REGISTER_FAILED: "Failed to register biometric credential",
    BIOMETRIC_NOT_FOUND: "No biometric credentials found",
    BIOMETRIC_VERIFY_FAILED: "Biometric verification failed",
    BIOMETRIC_DEACTIVATE_FAILED: "Failed to deactivate biometric credential",
    MFA_SETUP_FAILED: "Failed to setup MFA",
    MFA_ENABLE_FAILED: "Failed to enable MFA",
    MFA_DISABLE_FAILED: "Failed to disable MFA",
    MFA_CONFIG_NOT_FOUND: "MFA configuration not found",
    MFA_SET_PRIMARY_FAILED: "Failed to set primary MFA",

    // MFA Verification
    MFA_NOT_CONFIGURED: "MFA is not configured for this user",
    MFA_CONFIG_INVALID: "MFA configuration is invalid",
    MFA_SECRET_MISSING: "MFA secret is missing",
    MFA_INVALID_CODE: "Invalid MFA code",
    MFA_TYPE_NOT_SUPPORTED: "MFA type is not supported",

    // Challenge Management
    CHALLENGE_NOT_FOUND: "Security challenge not found or expired",
    CHALLENGE_CREATE_FAILED: "Failed to create security challenge",
    CHALLENGE_ALREADY_SOLVED: "Security challenge has already been solved",

    // JWT Service
    JWT_SECRET_REQUIRED: "JWT secret is required",
    INVALID_USER_OBJECT: "Invalid user object provided. User must have an id and an email.",
    TOKEN_GEN_FAILED: "Failed to generate token",
    ID_TOKEN_GEN_FAILED: "Failed to generate ID token",
    REFRESH_TOKEN_GEN_FAILED: "Failed to generate refresh token",
    TOKEN_REQUIRED: "Token is required",
    INVALID_TOKEN_FORMAT: "Invalid token format",
    INVALID_TOKEN_SIGNATURE: "Invalid token signature",
    INVALID_TOKEN_PAYLOAD: "Invalid token: malformed payload",
    TOKEN_EXPIRED: "Token has expired",
    REFRESH_TOKEN_REQUIRED: "Refresh token is required",
    INVALID_REFRESH_TOKEN_FORMAT: "Invalid refresh token format",
    INVALID_REFRESH_TOKEN_SIGNATURE: "Invalid refresh token signature",
    INVALID_REFRESH_TOKEN_PAYLOAD: "Invalid refresh token: malformed payload",
    INVALID_TOKEN_TYPE: "Invalid token type",
    REFRESH_TOKEN_EXPIRED: "Refresh token has expired",
    REFRESH_TOKEN_MISSING_USER: "Invalid refresh token: missing userId",
    REFRESH_TOKEN_ROTATE_FAILED: "Failed to rotate refresh token",

    // DPoP (JWT Service specific)
    DPOP_INVALID_FORMAT: "Invalid DPoP proof format",
    DPOP_MISSING_FIELDS: "Missing required DPoP fields",
    DPOP_METHOD_MISMATCH: "HTTP method mismatch",
    DPOP_URI_MISMATCH: "HTTP URI mismatch",
    DPOP_TIMESTAMP_RANGE: "DPoP proof timestamp out of range",
    DPOP_REPLAY_DETECTED: "DPoP proof replay detected",
    DPOP_INVALID_SIGNATURE: "Invalid DPoP signature",

    // OAuth Service
    CLIENT_CREATE_FAILED: "Failed to create OAuth client",
    CLIENT_UPDATE_FAILED: "Failed to update OAuth client",
    AUTH_CODE_CREATE_FAILED: "Failed to create authorization code",
    REFRESH_TOKEN_CREATE_FAILED: "Failed to create refresh token",
    REFRESH_TOKEN_NOT_FOUND: "Refresh token not found",
    UNAUTHORIZED_CLIENT: "Invalid or inactive client",
    INVALID_REDIRECT_URI: "Invalid redirect URI",
    UNSUPPORTED_RESPONSE_TYPE: "Unsupported response type",
    USER_AUTH_REQUIRED: "User authentication required",
    UNSUPPORTED_GRANT_TYPE: "Unsupported grant type",
    AUTH_CODE_REQUIRED: "Authorization code is required",
    INVALID_AUTH_CODE: "Invalid authorization code",
    AUTH_CODE_USED: "Authorization code has already been used",
    AUTH_CODE_EXPIRED: "Authorization code has expired",
    INVALID_CLIENT: "Invalid client credentials",
    REDIRECT_URI_MISMATCH: "Redirect URI mismatch",
    INVALID_PKCE: "Invalid PKCE verifier",
    REFRESH_TOKEN_REVOKED: "Refresh token has been revoked",
    CLIENT_MISMATCH: "Client mismatch for refresh token",
    PUBLIC_CLIENT_NO_CREDENTIALS: "Public clients cannot use client credentials grant",

    // Permission Service
    PERMISSION_VALIDATION_ERROR: "Name, resource, and action are required",
    PERMISSION_EXISTS: "Permission already exists", // Parametrized in code, generic here
    PERMISSION_CREATE_FAILED: "Failed to create permission",
    PERMISSION_UPDATE_FAILED: "Failed to update permission",
    PERMISSION_DELETE_FAILED: "Failed to delete permission",
    ROLE_NAME_REQUIRED: "Role name is required",
    ROLE_EXISTS: "Role already exists",
    ROLE_CREATE_FAILED: "Failed to create role",
    ROLE_UPDATE_FAILED: "Failed to update role",
    ROLE_DELETE_FAILED: "Failed to delete role",
    ASSIGN_PERMISSION_FAILED: "Failed to assign permission to role",
    PERMISSION_NOT_ASSIGNED: "Permission is not assigned to this role",
    REMOVE_PERMISSION_FAILED: "Failed to remove permission from role",
    ASSIGN_ROLE_FAILED: "Failed to assign role to user",
} as const;
export function errorParser(error: unknown, prefix?: string): Error {
  let parsedError: Error;

  // Parse the error
  if (error instanceof Error) {
    parsedError = error;
  } else if (typeof error === "string") {
    parsedError = new Error(error);
  } else if (error && typeof error === "object" && "message" in error) {
    parsedError = new Error(String(error.message));
  } else {
    parsedError = new Error(String(error));
  }

  // Prepend prefix if provided
  if (prefix) {
    parsedError.message = `${prefix}: ${parsedError.message}`;
  }

  return parsedError;
}