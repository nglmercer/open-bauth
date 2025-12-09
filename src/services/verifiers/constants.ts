
export const VerifierMessages = {
    // TOTP
    TOTP_REQUIRED: "MFA token is required",
    TOTP_CONFIG_INVALID: "Invalid MFA configuration",
    TOTP_INVALID: "Invalid or expired MFA code",

    // Code (Email/SMS)
    CODE_REQUIRED: "Verification code is required",
    CODE_DATA_INVALID: "Invalid challenge data",
    CODE_INVALID: "Invalid code",

    // Backup Code
    BACKUP_CODE_REQUIRED: "Recovery code is required",
    BACKUP_CONFIG_INVALID: "Invalid backup codes configuration",
    BACKUP_CODE_INVALID: "Invalid recovery code",

    // Generic
    CHALLENGE_EXPIRED: "Challenge has expired",
    CHALLENGE_SOLVED: "Challenge has already been solved",
    UNKNOWN_TYPE: "Unknown challenge type",

    // Placeholders
    CAPTCHA_NOT_CONFIGURED: "CAPTCHA provider not configured",
    BIOMETRIC_NOT_CONFIGURED: "Biometric provider not configured",
    DEVICE_NOT_CONFIGURED: "Device verification not configured",

    // DPoP
    DPOP_INVALID_FORMAT: "Invalid DPoP proof format",
    DPOP_MISSING_FIELDS: "Missing required DPoP fields",
    DPOP_METHOD_MISMATCH: "HTTP method mismatch",
    DPOP_URI_MISMATCH: "HTTP URI mismatch",
    DPOP_TIMESTAMP_RANGE: "DPoP proof timestamp out of range",
    DPOP_INVALID_SIGNATURE: "Invalid DPoP signature",

    // Encryption
    ENCRYPTION_INVALID_FORMAT: "Invalid encrypted data format"
} as const;
