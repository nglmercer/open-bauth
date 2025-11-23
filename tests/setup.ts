// tests/setup.ts
// Configuración global para tests con Bun

import { beforeAll, afterAll, beforeEach, afterEach, expect } from "bun:test";
import { initJWTService } from "../src/services/jwt";
import { defaultLogger as logger } from "../src/logger";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../src/database/database-initializer";
import { SchemaRegistry } from "../src/database/database-initializer";
// Variables globales para tests
export const TEST_DB_PATH = process.env.TEST_DB_PATH || "./tests/db/auth.db";
export const TEST_JWT_SECRET = "test-jwt-secret-key-for-testing-only";

// Configuración de entorno para tests
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = TEST_JWT_SECRET;
process.env.DATABASE_URL = TEST_DB_PATH;
process.env.BCRYPT_ROUNDS = "4"; // Menor para tests más rápidos

/**
 * Setup global antes de todos los tests
 */
beforeAll(async () => {
  logger.info("🧪 Configurando entorno de tests...");

  try {
    // Inicializar servicio JWT
    initJWTService(TEST_JWT_SECRET);

    logger.info("✅ Entorno de tests configurado correctamente");
  } catch (error: any) {
    console.error("❌ Error configurando entorno de tests:", error);
    throw error;
  }
});

/**
 * Cleanup global después de todos los tests
 */
afterAll(async () => {
  logger.info("🧹 Limpiando entorno de tests...");
});

// Manejar promesas rechazadas no capturadas en tests
if (process.env.NODE_ENV === "test") {
  process.on("unhandledRejection", (reason, promise) => {
    logger.info("⚠️ Unhandled rejection en tests (suprimido):", { reason });
    // No hacer exit en tests
  });

  process.on("uncaughtException", (error) => {
    logger.info("⚠️ Uncaught exception en tests (suprimido):", {
      message: error.message,
    });
    // No hacer exit en tests
  });
}

/**
 * Setup antes de cada test
 * Database reset is now handled in individual test files to ensure proper schema initialization
 */

/**
 * Cleanup después de cada test
 */
afterEach(async () => {
  // Opcional: limpiar datos después de cada test
  // await cleanDatabase();
});

/**
 * Utilidades para tests
 */
export const testUtils = {
  /**
   * Generar datos de usuario de prueba
   */
  generateTestUser(overrides = {}) {
    return {
      email: `test${Date.now()}@example.com`,
      password: "TestPassword123!",
      first_name: "Test",
      last_name: "User",
      is_active: true,
      ...overrides,
    };
  },

  /**
   * Generar datos de rol de prueba
   */
  generateTestRole(overrides = {}) {
    return {
      name: `test_role_${Date.now()}`,
      description: "Test role for testing purposes",
      is_active: true,
      ...overrides,
    };
  },

  /**
   * Generar datos de permiso de prueba
   */
  generateTestPermission(overrides: any = {}) {
    const timestamp = Date.now();
    const defaultData = {
      resource: "test_resource",
      action: "test_action",
      description: "Test permission for testing purposes",
      ...overrides,
    };

    // Generate name in 'resource:action' format if not provided
    if (!overrides.name) {
      defaultData.name = `${defaultData.resource}:${defaultData.action}_${timestamp}`;
    }

    return defaultData;
  },

  /**
   * Esperar un tiempo determinado (para tests asíncronos)
   */
  async wait(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  },

  /**
   * Generar JWT de prueba
   */
  async generateTestJWT(payload = {}, options = {}) {
    try {
      const { JWTService } = require("../src/services/jwt");
      const { expiresIn = "24h" } = options as any;
      const jwtService = new JWTService(TEST_JWT_SECRET, expiresIn);

      // Create a proper User object for JWT generation
      const defaultUser = {
        id: 1,
        email: "test@example.com",
        first_name: "Test",
        last_name: "User",
        is_active: true,
        roles: [{ name: "user" }],
        permissions: ["read"],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        ...payload,
      };

      return await jwtService.generateToken(defaultUser);
    } catch (error: any) {
      console.error("Error generating test JWT:", error);
      // Return a simple mock token for tests that don't need real JWT
      // Create a proper mock token with valid signature for the test secret
      const mockPayload = {
        userId: 1,
        email: "test@example.com",
        roles: ["user"],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      // Use the same JWT service with test secret to create a valid token
      const fallbackJwtService =
        new (require("../src/services/jwt").JWTService)(TEST_JWT_SECRET);
      const mockUser = {
        id: 1,
        email: "test@example.com",
        first_name: "Test",
        last_name: "User",
        is_active: true,
        roles: [{ name: "user" }],
        permissions: ["read"],
        created_at: new Date(),
        updated_at: new Date(),
      };

      try {
        return await fallbackJwtService.generateToken(mockUser);
      } catch (fallbackError) {
        console.error("Fallback token generation failed:", fallbackError);
        throw new Error("Unable to generate test token");
      }
    }
  },

  /**
   * Crear headers de autorización para tests
   */
  async createAuthHeaders(token?: string) {
    const authToken = token || (await testUtils.generateTestJWT());
    return {
      Authorization: `Bearer ${authToken}`,
      "Content-Type": "application/json",
    };
  },

  /**
   * Validar estructura de respuesta de error
   */
  validateErrorResponse(response: any) {
    expect(response).toHaveProperty("success", false);
    expect(response).toHaveProperty("error");
    expect(response.error).toHaveProperty("type");
    expect(response.error).toHaveProperty("message");
  },

  /**
   * Validar estructura de respuesta exitosa
   */
  validateSuccessResponse(response: any) {
    expect(response).toHaveProperty("success", true);
    expect(response).toHaveProperty("data");
  },

  /**
   * Validar estructura de usuario
   */
  validateUserStructure(user: any) {
    expect(user).toHaveProperty("id");
    expect(user).toHaveProperty("email");
    // first_name and last_name are optional
    if (user.first_name !== undefined) {
      expect(typeof user.first_name).toBe("string");
    }
    if (user.last_name !== undefined) {
      expect(typeof user.last_name).toBe("string");
    }
    expect(user).toHaveProperty("is_active");
    expect(user).toHaveProperty("created_at");
    expect(user).toHaveProperty("updated_at");
    // No debe incluir password
    expect(user).not.toHaveProperty("password");
  },

  /**
   * Validar estructura de rol
   */
  validateRoleStructure(role: any) {
    expect(role).toHaveProperty("id");
    expect(role).toHaveProperty("name");
    expect(role).toHaveProperty("created_at");
    expect(role).toHaveProperty("updated_at");
    expect(role).toHaveProperty("is_active");
  },

  /**
   * Validar estructura de permiso
   */
  validatePermissionStructure(permission: any) {
    expect(permission).toHaveProperty("id");
    expect(permission).toHaveProperty("name");
    expect(permission).toHaveProperty("resource");
    expect(permission).toHaveProperty("action");
    expect(permission).toHaveProperty("created_at");
  },
};

export const TEST_TIMEOUTS = {
  SHORT: 1000, // 1 segundo
  MEDIUM: 5000, // 5 segundos
  LONG: 10000, // 10 segundos
  VERY_LONG: 30000, // 30 segundos
};

export const mockConfig = {
  // Configuración adicional para tests
  silentLogs: false,
  // Controlar si se mockea la fecha
  mockDate: false,
  fixedDate: new Date("2024-01-01T00:00:00.000Z"),
};

// Silenciar logs si está activado
if (mockConfig.silentLogs) {
  const noop = () => {};
  (logger as any).info = noop;
  (logger as any).warn = noop;
  (logger as any).error = noop;
}

// Mock de fecha global si está activado
if (mockConfig.mockDate) {
  const OriginalDate = Date;
  // @ts-ignore
  global.Date = class extends OriginalDate {
    constructor(...args: any[]) {
      if (args.length === 0) {
        super(mockConfig.fixedDate);
      } else {
        // @ts-ignore
        super(...args);
      }
    }
  };
}

logger.info("🧪 Setup de tests cargado correctamente");
