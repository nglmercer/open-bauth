import type { DatabaseInitializer } from "../database/database-initializer";
import type { BaseController, ControllerResponse } from "../database/base-controller";
import type { JWTService } from "./jwt";
import { ServiceErrors } from "./constants";
import {
  AuthResult,
  LoginData,
  RegisterData,
  UpdateUserData,
  User,
  Role,
  UserQueryOptions,
  AuthErrorType,
} from "../types/auth";
/**
 * Main service for authentication, registration, and user management.
 */
export class AuthService {
  private userController: BaseController<User>;
  private roleController: BaseController<Role>;
  private userRoleController: BaseController<{
    id: string;
    user_id: string;
    role_id: string;
  }>;
  private jwtService: JWTService;

  constructor(dbInitializer: DatabaseInitializer, jwtService: JWTService) {
    // Use configured table names instead of hardcoded ones
    this.userController = dbInitializer.createControllerByKey<User>("users");
    this.roleController = dbInitializer.createControllerByKey<Role>("roles");
    this.userRoleController = dbInitializer.createControllerByKey("userRoles");
    this.jwtService = jwtService;
  }

  private getErrorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
  private sanitizeUser(user: User): User {
    const { password_hash, ...sanitizedUser } = user;
    return sanitizedUser as User;
  }

  private async attachRolesToUser(user: User): Promise<User> {
    try {
      if (!user || !user.id) {
        return { ...user, roles: [] };
      }
      const assignments = await this.userRoleController.search({
        user_id: user.id,
      });
      if (!assignments.data || assignments.data.length === 0) {
        return { ...user, roles: [] };
      }

      const roleIds = assignments.data.map((a) => a.role_id);
      const roles = await Promise.all(
        roleIds.map(async (id) => {
          const role = await this.roleController.findById(id);
          return role.data;
        }),
      );

      return { ...user, roles: roles.filter((r): r is Role => r !== null) };
    } catch (error: unknown) {
      // Return user with empty roles on error
      return { ...user, roles: [] };
    }
  }

  async getRoleByName(roleName: string): Promise<Role | null> {
    try {
      const result = await this.roleController.findFirst({ name: roleName });
      return result.data || null;
    } catch (error: unknown) {
      // Return null on error
      return null;
    }
  }

  // --- Core Authentication Methods ---

  async register(data: RegisterData): Promise<AuthResult> {
    if (typeof data.email !== "string" || !data.email) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: ServiceErrors.EMAIL_REQUIRED,
        },
      };
    }
    if (typeof data.password !== "string" || !data.password) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: ServiceErrors.PASSWORD_REQUIRED,
        },
      };
    }

    try {
      const existingUser = await this.userController.findFirst({
        email: data.email.toLowerCase(),
      });
      if (existingUser.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.USER_ALREADY_EXISTS,
            message: ServiceErrors.USER_ALREADY_EXISTS,
          },
        };
      }

      const password_hash = await Bun.password.hash(data.password);

      const createResult = await this.userController.create({
        email: data.email.toLowerCase(),
        password_hash,
        username: data.username,
        first_name: data.first_name,
        last_name: data.last_name,
        is_active: data.is_active !== undefined ? data.is_active : true,
      });

      if (!createResult.success || !createResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.DATABASE_ERROR,
            message: createResult.error || ServiceErrors.FAILED_TO_CREATE_USER,
          },
        };
      }

      const newUser = createResult.data;
      const userWithRoles = await this.attachRolesToUser(newUser);
      const token = await this.jwtService.generateToken(userWithRoles);

      return {
        success: true,
        user: this.sanitizeUser(userWithRoles),
        token,
      };
    } catch (error: unknown) {
      // Verificar si es un error de constraint de SQLite para email duplicado
      if (
        this.getErrorMessage(error) &&
        (this.getErrorMessage(error).includes("UNIQUE constraint failed") ||
          this.getErrorMessage(error).includes("constraint failed"))
      ) {
        return {
          success: false,
          error: {
            type: AuthErrorType.USER_ALREADY_EXISTS,
            message: ServiceErrors.USER_ALREADY_EXISTS,
          },
        };
      }
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: (error as Error).message,
        },
      };
    }
  }

  async login(data: LoginData): Promise<AuthResult> {
    if (typeof data.email !== "string" || !data.email) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: ServiceErrors.EMAIL_REQUIRED,
        },
      };
    }
    if (typeof data.password !== "string" || !data.password) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: ServiceErrors.PASSWORD_REQUIRED,
        },
      };
    }

    try {
      const userResult = await this.userController.findFirst({
        email: data.email.toLowerCase(),
      });
      const user = userResult.data;

      if (!user || !user.password_hash) {
        return {
          success: false,
          error: {
            type: AuthErrorType.INVALID_CREDENTIALS,
            message: ServiceErrors.INVALID_CREDENTIALS,
          },
        };
      }

      if (!user.is_active) {
        return {
          success: false,
          error: {
            type: AuthErrorType.INVALID_CREDENTIALS, // Cambiar a INVALID_CREDENTIALS como esperan los tests
            message: ServiceErrors.INVALID_CREDENTIALS,
          },
        };
      }

      const isPasswordValid = await Bun.password.verify(
        data.password,
        user.password_hash,
      );
      if (!isPasswordValid) {
        return {
          success: false,
          error: {
            type: AuthErrorType.INVALID_CREDENTIALS,
            message: ServiceErrors.INVALID_CREDENTIALS,
          },
        };
      }

      const userWithRoles = await this.attachRolesToUser(user);
      const token = await this.jwtService.generateToken(userWithRoles);

      this.userController.update(user.id, {
        last_login_at: new Date().toISOString(),
      });

      return {
        success: true,
        user: this.sanitizeUser(userWithRoles),
        token,
      };
    } catch (error: unknown) {
      // Preserve original error message for better error handling
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: (error as Error).message,
        },
      };
    }
  }

  // --- User Management Methods ---

  async findUserById(
    id: string | number,
    options: UserQueryOptions = {},
  ): Promise<User | null> {
    try {
      const userResult = await this.userController.findById(String(id));
      if (!userResult.data) return null;

      let user = userResult.data;
      if (options.includeRoles) {
        user = await this.attachRolesToUser(user);
      }

      return this.sanitizeUser(user);
    } catch (error: unknown) {
      // Return null on error
      return null;
    }
  }

  async findUserByEmail(
    email: string,
    options: UserQueryOptions = {},
  ): Promise<User | null> {
    try {
      const userResult = await this.userController.findFirst({
        email: email.toLowerCase(),
      });
      if (!userResult.data) return null;

      let user = userResult.data;
      if (options.includeRoles) {
        user = await this.attachRolesToUser(user);
      }

      return this.sanitizeUser(user);
    } catch (error: unknown) {
      // Return null on error
      return null;
    }
  }

  async updateUser(
    userId: string,
    data: UpdateUserData,
  ): Promise<{ success: boolean; user?: User; error?: any }> {
    const result = await this.userController.update(userId, data);
    if (!result.success || !result.data) {
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: result.error || ServiceErrors.FAILED_TO_UPDATE_USER,
        },
      };
    }
    return { success: true, user: this.sanitizeUser(result.data) };
  }

  async updatePassword(
    userId: string,
    newPassword: string,
  ) {
    if (typeof newPassword !== "string" || !newPassword) {
      return {
        success: false,
        error: {
          type: AuthErrorType.VALIDATION_ERROR,
          message: ServiceErrors.NEW_PASSWORD_EMPTY,
        },
      };
    }
    const password_hash = await Bun.password.hash(newPassword);
    const result = await this.userController.update(userId, { password_hash });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return result;
  }
  async changePassword(
    filter: string,
    currentPassword: string,
    newPassword: string,
  ) {
    let userResult: ControllerResponse<User | null>;
    userResult = await this.userController.findById(filter);
    if (!userResult.success || !userResult.data) {
      userResult = await this.userController.findFirst({ email: filter });
    }

    if (!userResult.success || !userResult.data) {
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: ServiceErrors.FAILED_TO_FIND_USER,
        },
      };
    }

    const user = userResult.data;
    const isPasswordValid = await Bun.password.verify(
      currentPassword,
      user.password_hash!
    );

    if (!isPasswordValid) {
      return {
        success: false,
        error: {
          type: AuthErrorType.INVALID_CREDENTIALS,
          message: ServiceErrors.INVALID_CREDENTIALS,
        },
      };
    }

    return await this.updatePassword(user.id!, newPassword);
  }
  async deactivateUser(
    userId: string,
  ) {
    const result = await this.userController.update(userId, {
      is_active: false,
    });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return result;
  }

  async activateUser(
    userId: string,
  ) {
    const result = await this.userController.update(userId, {
      is_active: true,
    });
    if (!result.success) {
      return {
        success: false,
        error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
      };
    }
    return result;
  }

  async deleteUser(
    userId: string | number,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      // Idealmente, esto debería estar en una transacción.
      const assignments = await this.userRoleController.search(
        { user_id: String(userId) },
        { limit: 1000 },
      );
      if (assignments.data) {
        for (const assignment of assignments.data) {
          await this.userRoleController.delete(assignment.id);
        }
      }

      const result = await this.userController.delete(userId);
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return { success: true };
    } catch (error: unknown) {
      // Preserve original error message for better error handling
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: (error as Error).message,
        },
      };
    }
  }

  // --- Role Management Methods ---

  async assignRole(
    userId: string | number,
    roleName: string,
  ) {
    try {
      const roleResult = await this.roleController.findFirst({
        name: roleName,
      });
      if (!roleResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: ServiceErrors.ROLE_NOT_FOUND,
          },
        };
      }

      const userResult = await this.userController.findById(String(userId));
      if (!userResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.USER_NOT_FOUND,
            message: ServiceErrors.USER_NOT_FOUND,
          },
        };
      }

      const existing = await this.userRoleController.findFirst({
        user_id: String(userId),
        role_id: roleResult.data.id,
      });
      if (existing.data) {
        return { success: true }; // El rol ya está asignado, operación exitosa.
      }

      const result = await this.userRoleController.create({
        user_id: String(userId),
        role_id: roleResult.data.id,
      });
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return result;
    } catch (error: unknown) {
      // Preserve original error message for better error handling
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: (error as Error).message,
        },
      };
    }
  }

  async removeRole(
    userId: string | number,
    roleName: string,
  ): Promise<{ success: boolean; error?: any }> {
    try {
      const roleResult = await this.roleController.findFirst({
        name: roleName,
      });
      if (!roleResult.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: ServiceErrors.ROLE_NOT_FOUND,
            details: roleResult.error,
          },
        };
      }

      const assignment = await this.userRoleController.findFirst({
        user_id: String(userId),
        role_id: roleResult.data.id,
      });
      if (!assignment.data) {
        return {
          success: false,
          error: {
            type: AuthErrorType.NOT_FOUND_ERROR,
            message: ServiceErrors.USER_NO_ROLE,
          },
        };
      }

      const result = await this.userRoleController.delete(assignment.data.id);
      if (!result.success) {
        return {
          success: false,
          error: { type: AuthErrorType.DATABASE_ERROR, message: result.error },
        };
      }
      return { success: true };
    } catch (error: unknown) {
      // Preserve original error message for better error handling
      return {
        success: false,
        error: {
          type: AuthErrorType.DATABASE_ERROR,
          message: (error as Error).message,
        },
      };
    }
  }

  // --- Data Retrieval Methods ---

  async getUsers(
    page: number = 1,
    limit: number = 20,
    options: UserQueryOptions = {},
  ): Promise<{ users: User[]; total: number }> {
    const offset = (page - 1) * limit;
    try {
      const result = await this.userController.findAll({ limit, offset });

      let users = result.data || [];
      const total = result.total || 0;

      if (options.includeRoles && users.length > 0) {
        users = await Promise.all(
          users.map((user) => this.attachRolesToUser(user)),
        );
      }

      return { users: users.map(this.sanitizeUser), total };
    } catch (error: unknown) {
      // Return empty result with error information
      return { users: [], total: 0 };
    }
  }

  async getUserRoles(userId: string | number): Promise<Role[]> {
    try {
      const user = await this.userController.findById(String(userId));
      if (!user.data) {
        return [];
      }

      const userWithRoles = await this.attachRolesToUser(user.data);
      return userWithRoles.roles || [];
    } catch (error: unknown) {
      // Return empty array on error
      return [];
    }
  }
}
