
export const VerifierMessages = {
    // TOTP
    TOTP_REQUIRED: "Token MFA es requerido",
    TOTP_CONFIG_INVALID: "Configuración MFA inválida",
    TOTP_INVALID: "Código MFA inválido o expirado",

    // Code (Email/SMS)
    CODE_REQUIRED: "Código de verificación requerido",
    CODE_DATA_INVALID: "Datos del desafío inválidos",
    CODE_INVALID: "Código inválido",

    // Backup Code
    BACKUP_CODE_REQUIRED: "Recovery code is required",
    BACKUP_CONFIG_INVALID: "Invalid backup codes configuration",
    BACKUP_CODE_INVALID: "Invalid recovery code",

    // Generic
    CHALLENGE_EXPIRED: "Challenge has expired",
    CHALLENGE_SOLVED: "Challenge has already been solved",
    UNKNOWN_TYPE: "Unknown challenge type",

    // Placeholders
    CAPTCHA_NOT_CONFIGURED: "Proveedor de CAPTCHA no configurado",
    BIOMETRIC_NOT_CONFIGURED: "Proveedor Biométrico no configurado",
    DEVICE_NOT_CONFIGURED: "Verificación de dispositivo no configurada"
} as const;
