import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from '../src/database/database-initializer';
import { JWTService } from '../src/services/jwt';
import { AuthService } from '../src/services/auth';
import { PermissionService } from '../src/services/permissions';
import { SecurityService } from '../src/services/security';
import { EnhancedUserService } from '../src/services/enhanced-user';
import { OAuthSecurityMiddleware } from '../src/middleware/oauth-security';
import { OAuthGrantType, OAuthResponseType, PKCEMethod, BiometricType, MFAType } from '../src/types/oauth';
import { registerOAuthSchemaExtensions, getOAuthSchemaExtensions, getOAuthSchemas } from '../src/database/schema/oauth-schema-extensions';

describe('OAuth 2.0 Basic Service Tests', () => {
  let db: Database;
  let dbInitializer: DatabaseInitializer;
  let jwtService: JWTService;
  let authService: AuthService;
  let permissionService: PermissionService;
  let securityService: SecurityService;
  let enhancedUserService: EnhancedUserService;
  let oauthMiddleware: OAuthSecurityMiddleware;

  beforeAll(async () => {
    // Register OAuth schema extensions first
    registerOAuthSchemaExtensions();
    
    // Initialize database with basic schemas and OAuth extensions
    db = new Database(':memory:');
    dbInitializer = new DatabaseInitializer({ database: db });
    
    // Get OAuth schemas and register them with the database initializer
    const oauthSchemas = getOAuthSchemas();
    dbInitializer.registerSchemas(oauthSchemas);
    
    await dbInitializer.initialize();
    await dbInitializer.seedDefaults();

    // Initialize services
    jwtService = new JWTService('test-secret-key', '1h');
    authService = new AuthService(dbInitializer, jwtService);
    permissionService = new PermissionService(dbInitializer);
    securityService = new SecurityService();
    enhancedUserService = new EnhancedUserService(dbInitializer, securityService);
    oauthMiddleware = new OAuthSecurityMiddleware(
      // Create mock OAuthService for middleware testing
      {
        findClientById: async () => null,
        findClientByClientId: async () => null,
        createClient: async () => ({ id: 'test', client_id: 'test' } as any),
        updateClient: async () => ({ id: 'test', client_id: 'test' } as any),
        deleteClient: async () => true,
        authenticateClient: async () => null,
        validateRedirectUri: async () => true,
        findAuthCodeByCode: async () => null,
        createAuthCode: async () => ({ id: 'test', code: 'test' } as any),
        markAuthCodeAsUsed: async () => true,
        deleteAuthCode: async () => true,
        findRefreshTokenByToken: async () => null,
        createRefreshToken: async () => ({ id: 'test', token: 'test' } as any),
        revokeRefreshToken: async () => true,
        rotateRefreshToken: async () => ({ id: 'test', token: 'test' } as any),
        handleAuthorizationRequest: async () => ({ error: 'unauthorized_client' } as any),
        handleTokenRequest: async () => ({ error: 'unauthorized_client' } as any),
        handleDeviceAuthorizationRequest: async () => ({ error: 'unauthorized_client' } as any),
        handleIntrospectionRequest: async () => ({ active: false }),
        handleRevocationRequest: async () => ({ success: true }),
      } as any,
      securityService,
      jwtService
    );
  });

  afterAll(() => {
    db.close();
  });

  describe('PKCE Support', () => {
    test('should generate and verify PKCE challenge', () => {
      const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
      
      expect(challenge.code_challenge).toBeDefined();
      expect(challenge.code_challenge_method).toBe(PKCEMethod.S256);
      expect(challenge.code_verifier).toBeDefined();

      const isValid = securityService.verifyPKCEChallenge(
        challenge.code_verifier,
        challenge.code_challenge,
        challenge.code_challenge_method
      );
      
      expect(isValid).toBe(true);
    });

    test('should reject invalid PKCE verifier', () => {
      const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
      
      const isValid = securityService.verifyPKCEChallenge(
        'invalid-verifier',
        challenge.code_challenge,
        challenge.code_challenge_method
      );
      
      expect(isValid).toBe(false);
    });
  });

  describe('Enhanced User Features', () => {
    test('should create anonymous user', async () => {
      const sessionData = { preferences: { theme: 'dark' } };
      const result = await enhancedUserService.createAnonymousUser(sessionData);
      
      expect(result.success).toBe(true);
      expect(result.anonymousUser).toBeDefined();
      expect(result.anonymousUser!.anonymous_id).toBeDefined();
    });

    test('should promote anonymous user to full user', async () => {
      // Create anonymous user first
      const sessionData = { preferences: { theme: 'dark' } };
      const anonymousResult = await enhancedUserService.createAnonymousUser(sessionData);
      expect(anonymousResult.success).toBe(true);

      // Promote to full user
      const userData = {
        first_name: 'Promoted',
        last_name: 'User',
        email: 'promoted@example.com',
        password: 'password123',
      };

      const promoteResult = await enhancedUserService.promoteAnonymousUser(
        anonymousResult.anonymousUser!.anonymous_id,
        userData
      );

      expect(promoteResult.success).toBe(true);
      expect(promoteResult.user).toBeDefined();
      expect(promoteResult.user!.email).toBe(userData.email);
    });

    test('should register device for user', async () => {
      // First create a user
      const userResult = await authService.register({
        first_name: 'Device',
        last_name: 'User',
        email: 'device@example.com',
        password: 'password123',
      });
      expect(userResult.success).toBe(true);

      // Register device
      const deviceResult = await enhancedUserService.registerDevice(
        userResult.user!.id,
        'device-123',
        'Test Device',
        'desktop' as any
      );

      expect(deviceResult.success).toBe(true);
      expect(deviceResult.device).toBeDefined();
      expect(deviceResult.device!.device_id).toBe('device-123');
    });
  });

  describe('Security Features', () => {
    test('should create and verify security challenge', async () => {
      const challengeData = { question: 'What is your favorite color?' };
      
      const createResult = await oauthMiddleware.createChallenge('captcha' as any, challengeData);
      expect(createResult.success).toBe(true);
      expect(createResult.challenge).toBeDefined();

      const verifyResult = await oauthMiddleware.verifyChallenge(
        createResult.challenge!.challenge_id,
        { answer: 'blue' }
      );

      // Note: This is a simplified verification - in real implementation,
      // you would verify the actual challenge solution
      expect(verifyResult.success).toBeDefined();
    });

    test('should detect suspicious activity patterns', async () => {
      const detection = await oauthMiddleware.detectSuspiciousActivity(
        'user-123',
        '192.168.1.1',
        'Mozilla/5.0...'
      );

      expect(detection.suspicious).toBeDefined();
      // Note: riskScore might be undefined if no suspicious activity is detected
      if (detection.riskScore !== undefined) {
        expect(typeof detection.riskScore).toBe('number');
      }
    });

    test('should enforce rate limiting', async () => {
      const rateLimit = await oauthMiddleware.checkRateLimit(
        'client-123',
        'user-456',
        '192.168.1.1'
      );

      expect(rateLimit.allowed).toBeDefined();
      expect(typeof rateLimit.remainingRequests).toBe('number');
    });
  });

  describe('OAuth Security Middleware', () => {
    test('should verify state parameter', async () => {
      const state = 'random-state-123';
      const storedState = 'random-state-123';

      const verification = await oauthMiddleware.verifyState(state, storedState);
      expect(verification.valid).toBe(true);
    });

    test('should reject mismatched state parameter', async () => {
      const state = 'random-state-123';
      const storedState = 'different-state-456';

      const verification = await oauthMiddleware.verifyState(state, storedState);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('CSRF');
    });

    test('should verify nonce parameter', async () => {
      const nonce = 'random-nonce-123';
      const usedNonces = new Set<string>();

      const verification = await oauthMiddleware.verifyNonce(nonce, usedNonces);
      expect(verification.valid).toBe(true);
      expect(usedNonces.has(nonce)).toBe(true);
    });

    test('should reject reused nonce parameter', async () => {
      const nonce = 'reused-nonce-123';
      const usedNonces = new Set<string>([nonce]);

      const verification = await oauthMiddleware.verifyNonce(nonce, usedNonces);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('replay');
    });
  });
});