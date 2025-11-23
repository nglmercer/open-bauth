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
  MFAType,
  BiometricType,
} from "../types/oauth";
import { DeviceType } from "../types/oauth";
import { SecurityService } from "./security";

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
  private securityService: SecurityService;

  constructor(
    dbInitializer: DatabaseInitializer,
    securityService: SecurityService
  ) {
    this.userController = dbInitializer.createController<User>("users");
    this.deviceSecretController = dbInitializer.createController<DeviceSecret>("device_secrets");
    this.biometricController = dbInitializer.createController<BiometricCredential>("biometric_credentials");
    this.anonymousUserController = dbInitializer.createController<AnonymousUser>("anonymous_users");
    this.userDeviceController = dbInitializer.createController<UserDevice>("user_devices");
    this.mfaController = dbInitializer.createController<MFAConfiguration>("mfa_configurations");
    this.securityService = securityService;
  }

  // --- Enhanced User Management ---

  /**
   * Create a new user with enhanced features
   */
  async createUser(data: CreateUserData): Promise<{ success: boolean; user?: User; error?: any }> {
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
            message: "A user with this email already exists",
          },
        };
      }

      // Hash password
      const password_hash = await Bun.password.hash(data.password);

      // Create user
      const result = await this.userController.create({
        email: data.email.toLowerCase(),
        password_hash,
        first_name: data.first_name,
        last_name: data.last_name,
        is_active: data.is_active !== undefined ? data.is_active : true,
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || "Failed to create user",
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
    data: UpdateUserData
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    const result = await this.userController.update(userId, data);
    if (!result.success || !result.data) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || "Failed to update user",
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
    expiresAt?: Date
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
            message: result.error || "Failed to create anonymous user",
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
  async findAnonymousUserById(anonymousId: string): Promise<AnonymousUser | null> {
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
    userData: CreateUserData
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    try {
      // Find anonymous user
      const anonymousUser = await this.findAnonymousUserById(anonymousId);
      if (!anonymousUser) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: "Anonymous user not found",
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
    userAgent?: string
  ): Promise<{ success: boolean; device?: UserDevice; error?: any }> {
    try {
      // Check if device already exists
      const existingDevice = await this.userDeviceController.findFirst({
        device_id: deviceId,
      });

      if (existingDevice.data) {
        // Update existing device
        const result = await this.userDeviceController.update(existingDevice.data.id, {
          device_name: deviceName,
          device_type: deviceType,
          platform,
          user_agent: userAgent,
          last_seen_at: new Date().toISOString(),
        });

        if (!result.success || !result.data) {
          return {
            success: false,
            error: {
              type: "DATABASE_ERROR",
              message: result.error || "Failed to update device",
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
            message: result.error || "Failed to register device",
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
    deviceId: string
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
            message: "Device not found",
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
            message: result.error || "Failed to trust device",
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
    deviceType: DeviceType = DeviceType.UNKNOWN
  ): Promise<{ success: boolean; deviceSecret?: DeviceSecret; secret?: string; error?: any }> {
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
        expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
      });

      if (!result.success || !result.data) {
        return {
          success: false,
          error: {
            type: "DATABASE_ERROR",
            message: result.error || "Failed to create device secret",
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
    secret: string
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
            message: "Device secret not found",
          },
        };
      }

      // Check if expired
      if (deviceSecret.data.expires_at && new Date() > new Date(deviceSecret.data.expires_at)) {
        return {
          success: false,
          error: {
            type: "EXPIRED",
            message: "Device secret has expired",
          },
        };
      }

      // Verify secret
      const isValid = await this.securityService.verifyPassword(
        secret,
        deviceSecret.data.secret_hash || "",
        (deviceSecret.data as any).secret_salt || ""
      );

      if (!isValid) {
        return {
          success: false,
          error: {
            type: "INVALID_CREDENTIALS",
            message: "Invalid device secret",
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
    expiresAt?: Date
  ): Promise<{ success: boolean; credential?: BiometricCredential; error?: any }> {
    try {
      // Encrypt biometric data
      const encryptionKey = process.env.BIOMETRIC_ENCRYPTION_KEY || "default-key";
      const encryptedData = await this.securityService.encrypt(biometricData, encryptionKey);

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
            message: result.error || "Failed to register biometric credential",
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
    deviceId?: string
  ): Promise<{ success: boolean; credential?: BiometricCredential; error?: any }> {
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
            message: "No biometric credentials found",
          },
        };
      }

      // Decrypt stored biometric data and compare
      const encryptionKey = process.env.BIOMETRIC_ENCRYPTION_KEY || "default-key";
      
      for (const credential of credentials.data) {
        try {
          const storedData = await this.securityService.decrypt(
            credential.credential_data,
            encryptionKey
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
          message: "Biometric verification failed",
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
  async getUserBiometricCredentials(userId: string): Promise<BiometricCredential[]> {
    const result = await this.biometricController.search({
      user_id: userId,
      is_active: true,
    });
    return result.data || [];
  }

  /**
   * Deactivate biometric credential
   */
  async deactivateBiometricCredential(credentialId: string): Promise<{ success: boolean; error?: any }> {
    const result = await this.biometricController.update(credentialId, {
      is_active: false,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || "Failed to deactivate biometric credential",
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
    configuration: any
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
            message: result.error || "Failed to setup MFA",
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
  async enableMFA(mfaConfigId: string): Promise<{ success: boolean; error?: any }> {
    const result = await this.mfaController.update(mfaConfigId, {
      is_enabled: true,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || "Failed to enable MFA",
        },
      };
    }

    return { success: true };
  }

  /**
   * Disable MFA for user
   */
  async disableMFA(mfaConfigId: string): Promise<{ success: boolean; error?: any }> {
    const result = await this.mfaController.update(mfaConfigId, {
      is_enabled: false,
    });

    if (!result.success) {
      return {
        success: false,
        error: {
          type: "DATABASE_ERROR",
          message: result.error || "Failed to disable MFA",
        },
      };
    }

    return { success: true };
  }

  /**
   * Set MFA as primary
   */
  async setPrimaryMFA(mfaConfigId: string): Promise<{ success: boolean; error?: any }> {
    try {
      // Get the MFA configuration
      const mfaConfig = await this.mfaController.findById(mfaConfigId);
      if (!mfaConfig.data) {
        return {
          success: false,
          error: {
            type: "NOT_FOUND",
            message: "MFA configuration not found",
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
            message: result.error || "Failed to set primary MFA",
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
  async getEnabledMFAConfigurations(userId: string): Promise<MFAConfiguration[]> {
    const result = await this.mfaController.search({
      user_id: userId,
      is_enabled: true,
    });
    return result.data || [];
  }

  /**
   * Get primary MFA configuration for user
   */
  async getPrimaryMFAConfiguration(userId: string): Promise<MFAConfiguration | null> {
    const result = await this.mfaController.findFirst({
      user_id: userId,
      is_primary: true,
    });
    return result.data || null;
  }

  // --- Helper Methods ---

  /**
   * Compare biometric data (simplified implementation)
   * In a real implementation, this would use sophisticated biometric comparison algorithms
   */
  private compareBiometricData(storedData: string, providedData: string): boolean {
    // This is a very simplified comparison for demonstration
    // Real biometric comparison would use specialized algorithms
    return storedData === providedData;
  }
}