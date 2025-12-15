// src/services/enhanced-user.ts

import type { DatabaseInitializer } from "../database/database-initializer";
import type { BaseController } from "../database/base-controller";
import type { User, CreateUserData, UpdateUserData } from "../types/auth";
import type {
  DeviceSecret,
  BiometricCredential,
  AnonymousUser,
  UserDevice,
  MFAConfiguration,
  BiometricType,
  SecurityChallenge,
} from "../types/oauth";
import { DeviceType, ChallengeType, MFAType } from "../types/oauth";
import { SecurityService } from "./security";
import { ServiceErrors } from "./constants";

/**
 * Enhanced User Service with support for biometric, anonymous users, and MFA
 */
export class EnhancedUserService {
  private userController: BaseController<User>;
  private deviceSecretController: BaseController<DeviceSecret>;
  private biometricController: BaseController<BiometricCredential>;
  private anonymousUserController: BaseController<AnonymousUser>;
  private userDeviceController: BaseController<UserDevice>;
  private mfaController: BaseController<MFAConfiguration>;
  private challengeController: BaseController<SecurityChallenge>;
  private securityService: SecurityService;

  constructor(
    dbInitializer: DatabaseInitializer,
    securityService: SecurityService,
  ) {
    this.userController = dbInitializer.createController<User>("users");
    this.deviceSecretController =
      dbInitializer.createController<DeviceSecret>("device_secrets");
    this.biometricController =
      dbInitializer.createController<BiometricCredential>(
        "biometric_credentials",
      );
    this.anonymousUserController =
      dbInitializer.createController<AnonymousUser>("anonymous_users");
    this.userDeviceController =
      dbInitializer.createController<UserDevice>("user_devices");
    this.mfaController =
      dbInitializer.createController<MFAConfiguration>("mfa_configurations");
    this.challengeController =
      dbInitializer.createController<SecurityChallenge>("security_challenges");
    this.securityService = securityService;
  }

  // --- Enhanced User Management ---

  /**
   * Create a new user with enhanced features
   */
  async createUser(
    data: CreateUserData,
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    try {
      // Check if user already exists
      const existingUser = await this.userController.findFirst({
        email: data.email.toLowerCase(),
      });

      if (existingUser.data) {
        return {
          success: false,
          error: {
            type: "USER_ALREADY_EXISTS",
            message: ServiceErrors.USER_ALREADY_EXISTS,
          },
        };
      }

      // Hash password
      const password_hash = await Bun.password.hash(data.password);

      // Create user
      const result = await this.userController.create({
        email: data.email.toLowerCase(),
        password_hash,
        username: data.username,
        first_name: data.first_name,
        last_name: data.last_name,
        is_active: data.is_active !== undefined ? data.is_active : true,
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.FAILED_TO_CREATE_USER,
          },
        };
      }

      return { success: true, user: result.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Update user with enhanced fields
   */
  async updateUser(
    userId: string,
    data: UpdateUserData,
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    const result = await this.userController.update(userId, data);
    if (!result.success || !result.data) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || ServiceErrors.FAILED_TO_UPDATE_USER,
        },
      };
    }
    return { success: true, user: result.data };
  }

  /**
   * Find user by ID
   */
  async findUserById(userId: string): Promise<User | null> {
    const result = await this.userController.findById(userId);
    return result.data || null;
  }

  /**
   * Find user by email
   */
  async findUserByEmail(email: string): Promise<User | null> {
    const result = await this.userController.findFirst({
      email: email.toLowerCase(),
    });
    return result.data || null;
  }

  // --- Anonymous User Management ---

  /**
   * Create an anonymous user
   */
  async createAnonymousUser(
    sessionData: any,
    expiresAt?: Date,
  ): Promise<{ success: boolean; anonymousUser?: AnonymousUser; error?: any }> {
    try {
      const anonymousId = this.securityService.generateSecureToken(32);
      const expires = expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      const result = await this.anonymousUserController.create({
        anonymous_id: anonymousId,
        session_data: JSON.stringify(sessionData),
        expires_at: expires.toISOString(),
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.ANONYMOUS_CREATE_FAILED,
          },
        };
      }

      return { success: true, anonymousUser: result.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Find anonymous user by ID
   */
  async findAnonymousUserById(
    anonymousId: string,
  ): Promise<AnonymousUser | null> {
    const result = await this.anonymousUserController.findFirst({
      anonymous_id: anonymousId,
    });
    return result.data || null;
  }

  /**
   * Promote anonymous user to full user
   */
  async promoteAnonymousUser(
    anonymousId: string,
    userData: CreateUserData,
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    try {
      // Find anonymous user
      const anonymousUser = await this.findAnonymousUserById(anonymousId);
      if (!anonymousUser) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: ServiceErrors.ANONYMOUS_NOT_FOUND,
          },
        };
      }

      // Create full user
      const createUserResult = await this.createUser(userData);
      if (!createUserResult.success) {
        return createUserResult;
      }

      // Update anonymous user with promotion info
      await this.anonymousUserController.update(anonymousUser.id, {
        promoted_to_user_id: createUserResult.user!.id,
        promoted_at: new Date().toISOString(),
      });

      return createUserResult;
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  // --- Device Management ---

  /**
   * Register a new device for a user
   */
  async registerDevice(
    userId: string,
    deviceId: string,
    deviceName: string,
    deviceType: DeviceType,
    platform?: string,
    userAgent?: string,
  ): Promise<{ success: boolean; device?: UserDevice; error?: any }> {
    try {
      // Check if device already exists
      const existingDevice = await this.userDeviceController.findFirst({
        device_id: deviceId,
      });

      if (existingDevice.data) {
        // Update existing device
        const result = await this.userDeviceController.update(
          existingDevice.data.id,
          {
            device_name: deviceName,
            device_type: deviceType,
            platform,
            user_agent: userAgent,
            last_seen_at: new Date().toISOString(),
          },
        );

        if (!result.success || !result.data) {
          return {
            success: false,
            error: {
              type: "DATABASE_ERROR",
              message: result.error || ServiceErrors.DEVICE_UPDATE_FAILED,
            },
          };
        }

        return { success: true, device: result.data };
      }

      // Create new device
      const result = await this.userDeviceController.create({
        user_id: userId,
        device_id: deviceId,
        device_name: deviceName,
        device_type: deviceType,
        platform,
        user_agent: userAgent,
        is_trusted: false,
        last_seen_at: new Date().toISOString(),
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.DEVICE_REGISTER_FAILED,
          },
        };
      }

      return { success: true, device: result.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Trust a device for SSO
   */
  async trustDevice(
    userId: string,
    deviceId: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      const device = await this.userDeviceController.findFirst({
        user_id: userId,
        device_id: deviceId,
      });

      if (!device.data) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: ServiceErrors.DEVICE_NOT_FOUND,
          },
        };
      }

      const result = await this.userDeviceController.update(device.data.id, {
        is_trusted: true,
      });

      if (!result.success) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.DEVICE_TRUST_FAILED,
          },
        };
      }

      // Create device secret for SSO
      await this.createDeviceSecret(userId, deviceId, device.data.device_name);

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Get user devices
   */
  async getUserDevices(userId: string): Promise<UserDevice[]> {
    const result = await this.userDeviceController.search({
      user_id: userId,
    });
    return result.data || [];
  }

  // --- Device Secrets for SSO ---

  /**
   * Create device secret for SSO
   */
  async createDeviceSecret(
    userId: string,
    deviceId: string,
    deviceName: string,
    deviceType: DeviceType = DeviceType.UNKNOWN,
  ): Promise<{
    success: boolean;
    deviceSecret?: DeviceSecret;
    secret?: string;
    error?: any;
  }> {
    try {
      const secret = this.securityService.generateSecureToken(64);
      const { hash, salt } = await this.securityService.hashPassword(secret);

      const result = await this.deviceSecretController.create({
        user_id: userId,
        device_id: deviceId,
        device_name: deviceName,
        device_type: deviceType,
        secret_hash: hash,
        secret_salt: salt,
        is_trusted: true,
        expires_at: new Date(
          Date.now() + 365 * 24 * 60 * 60 * 1000,
        ).toISOString(), // 1 year
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.DEVICE_SECRET_CREATE_FAILED,
          },
        };
      }

      // Return the secret (only time it's returned)
      return { success: true, deviceSecret: result.data, secret };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Verify device secret for SSO
   */
  async verifyDeviceSecret(
    deviceId: string,
    secret: string,
  ): Promise<{ success: boolean; deviceSecret?: DeviceSecret; error?: any }> {
    try {
      const deviceSecret = await this.deviceSecretController.findFirst({
        device_id: deviceId,
      });

      if (!deviceSecret.data) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: ServiceErrors.DEVICE_SECRET_NOT_FOUND,
          },
        };
      }

      // Check if expired
      if (
        deviceSecret.data.expires_at &&
        new Date() > new Date(deviceSecret.data.expires_at)
      ) {
        return {
          success: false,
          error: {
            type: "EXPIRED",
            message: ServiceErrors.DEVICE_SECRET_EXPIRED,
          },
        };
      }

      // Verify secret
      const isValid = await this.securityService.verifyPassword(
        secret,
        deviceSecret.data.secret_hash || "",
        deviceSecret.data.secret_salt || "",
      );

      if (!isValid) {
        return {
          success: false,
          error: {
            type: "INVALID_CREDENTIALS",
            message: ServiceErrors.DEVICE_SECRET_INVALID,
          },
        };
      }

      // Update last used time
      await this.deviceSecretController.update(deviceSecret.data.id, {
        last_used_at: new Date().toISOString(),
      });

      return { success: true, deviceSecret: deviceSecret.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  // --- Biometric Authentication ---

  /**
   * Register biometric credentials
   */
  async registerBiometricCredential(
    userId: string,
    biometricType: BiometricType,
    biometricData: string,
    deviceId?: string,
    expiresAt?: Date,
  ): Promise<{
    success: boolean;
    credential?: BiometricCredential;
    error?: any;
  }> {
    try {
      // Encrypt biometric data
      const encryptionKey =
        process.env.BIOMETRIC_ENCRYPTION_KEY || "default-key";
      const encryptedData = await this.securityService.encrypt(
        biometricData,
        encryptionKey,
      );

      const result = await this.biometricController.create({
        user_id: userId,
        biometric_type: biometricType,
        credential_data: encryptedData,
        device_id: deviceId,
        is_active: true,
        expires_at: expiresAt?.toISOString(),
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.BIOMETRIC_REGISTER_FAILED,
          },
        };
      }

      return { success: true, credential: result.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Verify biometric credentials
   */
  async verifyBiometricCredential(
    userId: string,
    biometricType: BiometricType,
    biometricData: string,
    deviceId?: string,
  ): Promise<{
    success: boolean;
    credential?: BiometricCredential;
    error?: any;
  }> {
    try {
      // Find matching biometric credentials
      const credentials = await this.biometricController.search({
        user_id: userId,
        biometric_type: biometricType,
        is_active: true,
      });

      if (!credentials.data || credentials.data.length === 0) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: ServiceErrors.BIOMETRIC_NOT_FOUND,
          },
        };
      }

      // Decrypt stored biometric data and compare
      const encryptionKey =
        process.env.BIOMETRIC_ENCRYPTION_KEY || "default-key";

      for (const credential of credentials.data) {
        try {
          const storedData = await this.securityService.decrypt(
            credential.credential_data,
            encryptionKey,
          );

          // In a real implementation, you would use a proper biometric comparison algorithm
          // This is a simplified comparison for demonstration
          if (this.compareBiometricData(storedData, biometricData)) {
            // Update last used time
            await this.biometricController.update(credential.id, {
              last_used_at: new Date().toISOString(),
            });

            return { success: true, credential };
          }
        } catch (error) {
          // Skip invalid encrypted data
          continue;
        }
      }

      return {
        success: false,
        error: {
          type: "INVALID_CREDENTIALS",
          message: ServiceErrors.BIOMETRIC_VERIFY_FAILED,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Get user biometric credentials
   */
  async getUserBiometricCredentials(
    userId: string,
  ): Promise<BiometricCredential[]> {
    const result = await this.biometricController.search({
      user_id: userId,
      is_active: true,
    });
    return result.data || [];
  }

  /**
   * Deactivate biometric credential
   */
  async deactivateBiometricCredential(
    credentialId: string,
  ): Promise<{ success: boolean; error?: any }> {
    const result = await this.biometricController.update(credentialId, {
      is_active: false,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || ServiceErrors.BIOMETRIC_DEACTIVATE_FAILED,
        },
      };
    }

    return { success: true };
  }

  // --- MFA Management ---

  /**
   * Setup MFA for user
   */
  async setupMFA(
    userId: string,
    mfaType: MFAType,
    configuration: any,
  ): Promise<{ success: boolean; mfaConfig?: MFAConfiguration; error?: any }> {
    try {
      // Check if MFA of this type already exists
      const existingMFA = await this.mfaController.findFirst({
        user_id: userId,
        mfa_type: mfaType,
      });

      let result;
      if (existingMFA.data) {
        // Update existing MFA
        result = await this.mfaController.update(existingMFA.data.id, {
          ...configuration,
          is_enabled: true,
        });
      } else {
        // Create new MFA
        result = await this.mfaController.create({
          user_id: userId,
          mfa_type: mfaType,
          is_enabled: true,
          is_primary: false,
          ...configuration,
        });
      }

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.MFA_SETUP_FAILED,
          },
        };
      }

      return { success: true, mfaConfig: result.data };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Enable MFA for user
   */
  async enableMFA(
    mfaConfigId: string,
  ): Promise<{ success: boolean; error?: any }> {
    const result = await this.mfaController.update(mfaConfigId, {
      is_enabled: true,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || ServiceErrors.MFA_ENABLE_FAILED,
        },
      };
    }

    return { success: true };
  }

  /**
   * Disable MFA for user
   */
  async disableMFA(
    mfaConfigId: string,
  ): Promise<{ success: boolean; error?: any }> {
    const result = await this.mfaController.update(mfaConfigId, {
      is_enabled: false,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || ServiceErrors.MFA_DISABLE_FAILED,
        },
      };
    }

    return { success: true };
  }

  /**
   * Set MFA as primary
   */
  async setPrimaryMFA(
    mfaConfigId: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      // Get the MFA configuration
      const mfaConfig = await this.mfaController.findById(mfaConfigId);
      if (!mfaConfig.data) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: ServiceErrors.MFA_CONFIG_NOT_FOUND,
          },
        };
      }

      // Unset all other primary MFAs for this user
      await this.mfaController.search({ user_id: mfaConfig.data.user_id });
      const allUserMFAs = await this.mfaController.search({
        user_id: mfaConfig.data.user_id,
      });

      if (allUserMFAs.data) {
        for (const mfa of allUserMFAs.data) {
          if (mfa.is_primary) {
            await this.mfaController.update(mfa.id, { is_primary: false });
          }
        }
      }

      // Set this MFA as primary
      const result = await this.mfaController.update(mfaConfigId, {
        is_primary: true,
      });

      if (!result.success) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || ServiceErrors.MFA_SET_PRIMARY_FAILED,
          },
        };
      }

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Get user MFA configurations
   */
  async getUserMFAConfigurations(userId: string): Promise<MFAConfiguration[]> {
    const result = await this.mfaController.search({
      user_id: userId,
    });
    return result.data || [];
  }

  /**
   * Get enabled MFA configurations for user
   */
  async getEnabledMFAConfigurations(
    userId: string,
  ): Promise<MFAConfiguration[]> {
    const result = await this.mfaController.search({
      user_id: userId,
      is_enabled: true,
    });
    return result.data || [];
  }

  /**
   * Get primary MFA configuration for user
   */
  async getPrimaryMFAConfiguration(
    userId: string,
  ): Promise<MFAConfiguration | null> {
    const result = await this.mfaController.findFirst({
      user_id: userId,
      is_primary: true,
    });
    return result.data || null;
  }

  // --- MFA Verification ---

  /**
   * Verify MFA code for TOTP-based authentication (Google Authenticator, Authy, etc.)
   * 
   * This method uses SecurityService.verifyChallenge() with a temporary challenge.
   * The challenge is not persisted in the database since TOTP is stateless.
   * 
   * @param userId - User ID to verify MFA for
   * @param code - 6-digit TOTP code provided by the user
   * @param mfaType - Type of MFA (defaults to 'totp')
   * @returns Success/error result
   * 
   * @example
   * ```typescript
   * const result = await enhancedUserService.verifyMFA(userId, '123456');
   * if (result.success) {
   *   // MFA verified successfully
   * }
   * ```
   */
  async verifyMFA(
    userId: string,
    code: string,
    mfaType: MFAType = MFAType.TOTP,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      // 1. Get the user's enabled MFA configuration
      const mfaConfig = await this.mfaController.findFirst({
        user_id: userId,
        mfa_type: mfaType,
        is_enabled: true,
      });

      if (!mfaConfig.data) {
        return {
          success: false,
          error: {
            type: "MFA_NOT_CONFIGURED",
            message: ServiceErrors.MFA_NOT_CONFIGURED,
          },
        };
      }

      const config = mfaConfig.data;

      // 2. Validate MFA configuration has required secret
      if (!config.secret) {
        return {
          success: false,
          error: {
            type: "MFA_SECRET_MISSING",
            message: ServiceErrors.MFA_SECRET_MISSING,
          },
        };
      }

      // 3. Create a temporary challenge (in memory, not persisted)
      // TOTP is stateless - we only need the secret to verify the current code
      const tempChallenge: SecurityChallenge = {
        id: this.securityService.generateSecureToken(16),
        challenge_id: this.securityService.generateSecureToken(32),
        challenge_type: ChallengeType.MFA,
        challenge_data: JSON.stringify({ secret: config.secret }),
        expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 min
        is_solved: false,
        created_at: new Date().toISOString(),
      };

      // 4. Verify using SecurityService
      // Internally calls TOTPVerifier.verify()
      const result = await this.securityService.verifyChallenge(
        tempChallenge,
        { token: code }, // TOTPSolution format
      );

      if (!result.valid) {
        return {
          success: false,
          error: {
            type: "MFA_INVALID_CODE",
            message: result.error || ServiceErrors.MFA_INVALID_CODE,
          },
        };
      }

      // ✅ Code verified successfully
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Generate MFA challenge for Email/SMS verification
   * 
   * Creates a security challenge with a hashed code and stores it in the database.
   * Use this when SENDING the verification code to the user.
   * 
   * @param userId - User ID to generate challenge for
   * @param mfaType - Type of MFA ('email' or 'sms')
   * @param codeLength - Length of the verification code (default: 6)
   * @returns Challenge with plain text code to send to user
   * 
   * @example
   * ```typescript
   * const result = await enhancedUserService.generateMFAChallenge(userId, 'email');
   * if (result.success) {
   *   await sendEmail(user.email, `Your code is: ${result.code}`);
   *   // Store result.challenge.challenge_id for later verification
   * }
   * ```
   */
  async generateMFAChallenge(
    userId: string,
    mfaType: MFAType.EMAIL | MFAType.SMS,
    codeLength: number = 6,
  ): Promise<{
    success: boolean;
    challenge?: SecurityChallenge;
    code?: string;
    error?: any;
  }> {
    try {
      // 1. Verify user has this MFA type configured
      const mfaConfig = await this.mfaController.findFirst({
        user_id: userId,
        mfa_type: mfaType,
        is_enabled: true,
      });

      if (!mfaConfig.data) {
        return {
          success: false,
          error: {
            type: "MFA_NOT_CONFIGURED",
            message: ServiceErrors.MFA_NOT_CONFIGURED,
          },
        };
      }

      // 2. Generate random verification code
      const min = Math.pow(10, codeLength - 1);
      const max = Math.pow(10, codeLength) - 1;
      const code = Math.floor(min + Math.random() * (max - min + 1)).toString();

      // 3. Hash the code for secure storage
      const { createHash } = await import("crypto");
      const salt = this.securityService.generateSecureToken(16);
      const codeHash = createHash("sha256")
        .update(code + salt)
        .digest("hex");

      // 4. Create challenge using SecurityService
      const challengeType =
        mfaType === MFAType.EMAIL
          ? ChallengeType.EMAIL_VERIFICATION
          : ChallengeType.SMS_VERIFICATION;

      const challengeData = this.securityService.createChallenge(
        challengeType,
        {
          expectedHash: codeHash,
          salt: salt,
          userId: userId, // Metadata for searching
          mfaType: mfaType,
        },
        10, // 10 minutes validity
      );

      // 5. Persist challenge to database
      const result = await this.challengeController.create({
        ...challengeData,
        created_at: new Date().toISOString(),
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "CHALLENGE_CREATE_FAILED",
            message:
              result.error || ServiceErrors.CHALLENGE_CREATE_FAILED,
          },
        };
      }

      // 6. Return success with PLAIN TEXT code (only returned here, never stored)
      return {
        success: true,
        challenge: result.data,
        code: code, // ⭐ Send this to the user via email/sms
      };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Verify MFA code for Email/SMS verification
   * 
   * Verifies a code against a previously generated challenge.
   * Use this when the user SUBMITS the verification code.
   * 
   * @param userId - User ID to verify for
   * @param code - The verification code entered by the user
   * @param challengeId - The challenge_id from generateMFAChallenge
   * @returns Success/error result
   * 
   * @example
   * ```typescript
   * const result = await enhancedUserService.verifyMFACode(
   *   userId,
   *   '123456',
   *   storedChallengeId
   * );
   * if (result.success) {
   *   // Code verified, challenge marked as solved
   * }
   * ```
   */
  async verifyMFACode(
    userId: string,
    code: string,
    challengeId: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      // 1. Find the challenge in database
      const challengeResult = await this.challengeController.findFirst({
        challenge_id: challengeId,
        is_solved: false, // Only unsolved challenges
      });

      if (!challengeResult.data) {
        return {
          success: false,
          error: {
            type: "CHALLENGE_NOT_FOUND",
            message: ServiceErrors.CHALLENGE_NOT_FOUND,
          },
        };
      }

      const challenge = challengeResult.data;

      // 2. Verify the code using SecurityService
      // Internally calls SecureCodeVerifier.verify()
      const result = await this.securityService.verifyChallenge(challenge, {
        code: code, // CodeSolution format
      });

      if (!result.valid) {
        return {
          success: false,
          error: {
            type: "MFA_INVALID_CODE",
            message: result.error || ServiceErrors.MFA_INVALID_CODE,
          },
        };
      }

      // 3. ✅ Mark challenge as solved (DO NOT DELETE)
      // This prevents reuse and maintains audit trail
      await this.challengeController.update(challenge.id, {
        is_solved: true,
        solved_at: new Date().toISOString(),
      });

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: { type: "DATABASE_ERROR", message: error.message },
      };
    }
  }

  /**
   * Clean up expired and solved challenges
   * 
   * Should be called periodically (e.g., daily cron job) to remove old challenges.
   * Only removes challenges that are both solved AND older than the retention period.
   * 
   * @param retentionDays - Number of days to keep solved challenges (default: 7)
   * @returns Number of challenges cleaned up
   * 
   * @example
   * ```typescript
   * // In a cron job
   * const cleaned = await enhancedUserService.cleanupExpiredChallenges(7);
   * console.log(`Cleaned up ${cleaned} old challenges`);
   * ```
   */
  async cleanupExpiredChallenges(retentionDays: number = 7): Promise<number> {
    try {
      const cutoffDate = new Date(
        Date.now() - retentionDays * 24 * 60 * 60 * 1000,
      );

      // Find expired challenges that are solved
      const expiredChallenges = await this.challengeController.search({
        is_solved: true,
      });

      if (!expiredChallenges.data) {
        return 0;
      }

      let cleanedCount = 0;

      // Delete challenges that are old enough
      for (const challenge of expiredChallenges.data) {
        const solvedAt = challenge.solved_at
          ? new Date(challenge.solved_at)
          : new Date(challenge.created_at!);

        if (solvedAt < cutoffDate) {
          const deleteResult = await this.challengeController.delete(
            challenge.id,
          );
          if (deleteResult.success) {
            cleanedCount++;
          }
        }
      }

      return cleanedCount;
    } catch (error: any) {
      console.error("Error cleaning up challenges:", error);
      return 0;
    }
  }

  // --- Helper Methods ---

  /**
   * Compare biometric data (simplified implementation)
   * In a real implementation, this would use sophisticated biometric comparison algorithms
   */
  private compareBiometricData(
    storedData: string,
    providedData: string,
  ): boolean {
    // This is a very simplified comparison for demonstration
    // Real biometric comparison would use specialized algorithms
    return storedData === providedData;
  }
}
