import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { Database } from "bun:sqlite";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { JWTService } from "../../src/services/jwt";
import { AuthService } from "../../src/services/auth";
import { PermissionService } from "../../src/services/permissions";
import { SecurityService } from "../../src/services/security";
import { EnhancedUserService } from "../../src/services/enhanced-user";
import {
  OAuthGrantType,
  OAuthResponseType,
  PKCEMethod,
  BiometricType,
  MFAType,
} from "../../src/types/oauth";
import {
  registerOAuthSchemaExtensions,
  getOAuthSchemaExtensions,
  getOAuthSchemas,
} from "../../src/database/schema/oauth-schema-extensions";

describe("OAuth 2.0 Basic Service Tests", () => {
  let db: Database;
  let dbInitializer: DatabaseInitializer;
  let jwtService: JWTService;
  let authService: AuthService;
  let permissionService: PermissionService;
  let securityService: SecurityService;
  let enhancedUserService: EnhancedUserService;

  beforeAll(async () => {
    // Register OAuth schema extensions first
    registerOAuthSchemaExtensions();

    // Initialize database with basic schemas and OAuth extensions
    db = new Database(":memory:");
    dbInitializer = new DatabaseInitializer({ database: db });

    // Get OAuth schemas and register them with the database initializer
    const oauthSchemas = getOAuthSchemas();
    dbInitializer.registerSchemas(oauthSchemas);

    await dbInitializer.initialize();
    await dbInitializer.seedDefaults();

    // Initialize services
    jwtService = new JWTService("test-secret-key", "1h");
    authService = new AuthService(dbInitializer, jwtService);
    permissionService = new PermissionService(dbInitializer);
    securityService = new SecurityService();
    enhancedUserService = new EnhancedUserService(
      dbInitializer,
      securityService,
    );
  });

  afterAll(() => {
    db.close();
  });

  describe("PKCE Support", () => {
    test("should generate and verify PKCE challenge", () => {
      const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

      expect(challenge.code_challenge).toBeDefined();
      expect(challenge.code_challenge_method).toBe(PKCEMethod.S256);
      expect(challenge.code_verifier).toBeDefined();

      const isValid = securityService.verifyPKCEChallenge(
        challenge.code_verifier,
        challenge.code_challenge,
        challenge.code_challenge_method,
      );

      expect(isValid).toBe(true);
    });

    test("should reject invalid PKCE verifier", () => {
      const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

      const isValid = securityService.verifyPKCEChallenge(
        "invalid-verifier",
        challenge.code_challenge,
        challenge.code_challenge_method,
      );

      expect(isValid).toBe(false);
    });
  });

  describe("Enhanced User Features", () => {
    test("should create anonymous user", async () => {
      const sessionData = { preferences: { theme: "dark" } };
      const result = await enhancedUserService.createAnonymousUser(sessionData);

      expect(result.success).toBe(true);
      expect(result.anonymousUser).toBeDefined();
      expect(result.anonymousUser!.anonymous_id).toBeDefined();
    });

    test("should promote anonymous user to full user", async () => {
      // Create anonymous user first
      const sessionData = { preferences: { theme: "dark" } };
      const anonymousResult =
        await enhancedUserService.createAnonymousUser(sessionData);
      expect(anonymousResult.success).toBe(true);

      // Promote to full user
      const userData = {
        first_name: "Promoted",
        last_name: "User",
        email: "promoted@example.com",
        password: "password123",
      };

      const promoteResult = await enhancedUserService.promoteAnonymousUser(
        anonymousResult.anonymousUser!.anonymous_id,
        userData,
      );

      expect(promoteResult.success).toBe(true);
      expect(promoteResult.user).toBeDefined();
      expect(promoteResult.user!.email).toBe(userData.email);
    });

    test("should register device for user", async () => {
      // First create a user
      const userResult = await authService.register({
        first_name: "Device",
        last_name: "User",
        email: "device@example.com",
        password: "password123",
      });
      expect(userResult.success).toBe(true);

      // Register device
      const deviceResult = await enhancedUserService.registerDevice(
        userResult.user!.id,
        "device-123",
        "Test Device",
        "desktop" as any,
      );

      expect(deviceResult.success).toBe(true);
      expect(deviceResult.device).toBeDefined();
      expect(deviceResult.device!.device_id).toBe("device-123");
    });
  });

});
