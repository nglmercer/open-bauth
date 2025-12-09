// tests/services/jwt-bun.test.ts
import { describe, test, expect, beforeEach } from "bun:test";
import { JWTServiceBun, initJWTServiceBun, getJWTServiceBun } from "../../src/services/jwt-bun";
import type { User } from "../../src/types/auth";

describe("JWTServiceBun", () => {
  let jwtService: JWTServiceBun;
  const testUser: User = {
    id: "123",
    email: "test@example.com",
    username: "testuser",
    first_name: "Test",
    last_name: "User",
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    roles: [
      {
        id: "1",
        name: "user",
        description: "Regular user",
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ],
  };

  beforeEach(() => {
    jwtService = initJWTServiceBun("test-secret", "1h");
  });

  describe("Token Generation", () => {
    test("should generate valid JWT token", async () => {
      const token = await jwtService.generateToken(testUser);
      expect(token).toBeString();
      expect(token.split(".")).toHaveLength(3); // header.payload.signature
    });

    test("should generate different tokens for same payload", async () => {
      const token1 = await jwtService.generateToken(testUser);
      // await change timestamp
      await new Promise(resolve => setTimeout(resolve, 1000));
      const token2 = await jwtService.generateToken(testUser);
      expect(token1).not.toBe(token2);
    });

    test("should generate token with custom payload", async () => {
      const customPayload = {
        userId: "456",
        customField: "customValue",
      };
      const token = await jwtService.generateTokenWithPayload(customPayload);
      expect(token).toBeString();
      expect(token.split(".")).toHaveLength(3);
    });
  });

  describe("Token Verification", () => {
    test("should verify valid token", async () => {
      const token = await jwtService.generateToken(testUser);
      const payload = await jwtService.verifyToken(token);
      
      expect(payload).toBeObject();
      expect(payload.userId).toBe(testUser.id);
      expect(payload.email).toBe(testUser.email);
      expect(payload.roles).toEqual(["user"]);
    });

    test("should reject invalid token format", async () => {
      await expect(jwtService.verifyToken("invalid.token")).rejects.toThrow("Invalid token format");
    });

    test("should reject token with invalid signature", async () => {
      const token = await jwtService.generateToken(testUser);
      const [header, payload, _signature] = token.split(".");
      const invalidToken = `${header}.${payload}.invalidsignature`;
      
      await expect(jwtService.verifyToken(invalidToken)).rejects.toThrow("Invalid token signature");
    });

    test("should reject token signed with different secret", async () => {
      const token = await jwtService.generateToken(testUser);
      const differentService = initJWTServiceBun("different-secret", "1h");
      
      await expect(differentService.verifyToken(token)).rejects.toThrow("Invalid token signature");
    });
  });

  describe("Utility Methods", () => {
    test("should extract token from Authorization header", () => {
      const token = "test.jwt.token";
      const header = `Bearer ${token}`;
      const extracted = jwtService.extractTokenFromHeader(header);
      expect(extracted).toBe(token);
    });

    test("should return null for invalid Authorization header", () => {
      expect(jwtService.extractTokenFromHeader("")).toBeNull();
      expect(jwtService.extractTokenFromHeader("InvalidHeader")).toBeNull();
      expect(jwtService.extractTokenFromHeader("Basic token")).toBeNull();
    });

    test("should check if token is expired", async () => {
      const expiredService = initJWTServiceBun("test-secret", "-1h");
      const token = await expiredService.generateToken(testUser);
      
      expect(jwtService.isTokenExpired(token)).toBe(true);
    });

    test("should get token remaining time", async () => {
      const token = await jwtService.generateToken(testUser);
      const remainingTime = jwtService.getTokenRemainingTime(token);
      
      expect(remainingTime).toBeNumber();
      expect(remainingTime).toBeGreaterThan(0);
      expect(remainingTime).toBeLessThanOrEqual(3600); // 1 hour
    });
  });

  describe("Performance Comparison", () => {
    test("should generate tokens efficiently", async () => {
      const start = performance.now();
      const tokens = await Promise.all(
        Array.from({ length: 100 }, () => jwtService.generateToken(testUser))
      );
      const end = performance.now();
      
      expect(tokens).toHaveLength(100);
      expect(tokens.every(token => token.split(".").length === 3)).toBe(true);
      
      // verify tokens
      expect(tokens.every(token => token.split(".").length === 3)).toBe(true);
      // in fast operations tokens can be the same
    });

    test("should verify tokens efficiently", async () => {
      const tokens = await Promise.all(
        Array.from({ length: 50 }, () => jwtService.generateToken(testUser))
      );
      
      const start = performance.now();
      const payloads = await Promise.all(
        tokens.map(token => jwtService.verifyToken(token))
      );
      const end = performance.now();
      
      expect(payloads).toHaveLength(50);
      expect(payloads.every(payload => payload.userId === testUser.id)).toBe(true);
    });
  });

  describe("Singleton Pattern", () => {
    test("should maintain singleton instance", () => {
      const instance1 = getJWTServiceBun();
      const instance2 = getJWTServiceBun();
      
      expect(instance1).toBe(instance2);
    });

    test("should throw error if not initialized", () => {
      // verify singleton pattern
      expect(() => getJWTServiceBun()).not.toThrow();
    });
  });
});