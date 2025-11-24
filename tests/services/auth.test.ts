// src/services/auth.service.test.ts (CORREGIDO CON AISLAMIENTO REAL)

import { test, expect, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { JWTService } from "../../src/services/jwt";
import { AuthService } from "../../src/services/auth";
import { AuthErrorType } from "../../src/types/auth";

describe("AuthService", () => {
  let authService: AuthService;
  // NO inicializamos la DB aquí, solo declaramos la variable.

  // beforeEach se ejecutará ANTES DE CADA UNO de los tests de abajo.
  beforeEach(async () => {
    // 1. Crear una base de datos EN MEMORIA NUEVA para CADA test.
    // Esto garantiza un estado 100% limpio y aislado.
    const db = new Database(":memory:");

    // 2. Inicializar el esquema en esta base de datos fresca.
    const dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize();

    // 3. Crear nuevas instancias de los servicios para CADA test.
    const jwtService = new JWTService("test-secret-for-testing", "1h");
    authService = new AuthService(dbInitializer, jwtService);
  });

  // --- AHORA los tests son independientes ---

  test("should register a new user successfully", async () => {
    const userData = {
      email: "test@example.com",
      password: "password123",
      username: "testuser",
      first_name: "Test",
    };
    const result = await authService.register(userData);

    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.user?.email).toBe(userData.email);
    expect(result.user?.username).toBe(userData.username);
    expect(result.user?.first_name).toBe("Test");
    expect(result.token).toBeString();
    expect(result.error).toBeUndefined();
  });

  test("should log in an existing user successfully", async () => {
    const userData = {
      email: "login@example.com",
      password: "securepassword",
      username: "loginuser",
    };

    // El beforeEach ya nos dio una DB limpia, así que podemos registrar sin miedo.
    await authService.register(userData);

    const result = await authService.login({
      email: userData.email,
      password: userData.password,
    });

    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.user?.email).toBe(userData.email);
    expect(result.user?.username).toBe(userData.username);
    expect(result.token).toBeString();
    expect(result.error).toBeUndefined();
  });

  test("should fail to log in with incorrect password", async () => {
    const userData = {
      email: "fail@example.com",
      password: "correctpassword",
      username: "failuser",
    };
    await authService.register(userData);
    const result = await authService.login({
      email: userData.email,
      password: "wrongpassword",
    });

    expect(result.success).toBe(false);
    expect(result.user).toBeUndefined();
    expect(result.token).toBeUndefined();
    // Ajustado para esperar un objeto, como devuelve el servicio
    expect(result.error).toEqual({
      type: AuthErrorType.INVALID_CREDENTIALS,
      message: "Invalid credentials",
    });
  });

  test("should fail to register a user with a duplicate email", async () => {
    const userData = {
      email: "duplicate@example.com",
      password: "password123",
      username: "duplicateuser",
    };

    // Primer registro en una DB limpia. Debe funcionar.
    const firstAttempt = await authService.register(userData);
    expect(firstAttempt.success).toBe(true);

    // Segundo registro en la MISMA DB (dentro de este test). Debe fallar.
    const secondAttempt = await authService.register(userData);

    expect(secondAttempt.success).toBe(false);
    expect(secondAttempt.user).toBeUndefined();
    expect(secondAttempt.token).toBeUndefined();
    expect(secondAttempt.error).toEqual({
      type: AuthErrorType.USER_ALREADY_EXISTS,
      message: "A user with this email already exists",
    });
  });
});
