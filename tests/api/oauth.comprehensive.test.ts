import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { getServiceFactory } from "../../src/services/service-factory";
import { OAuthGrantType, OAuthResponseType, OAuthErrorType, PKCEMethod } from "../../src/types/oauth";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import { OAuthService } from "../../src/services/oauth";
import { SecurityService } from "../../src/services/security";
import { JWTService } from "../../src/services/jwt";
import { AuthService } from "../../src/services/auth";
import { TEST_TIMEOUTS } from "../setup";

describe("OAuth API - Comprehensive Tests", () => {
    let oauthService: OAuthService;
    let securityService: SecurityService;
    let jwtService: JWTService;
    let authService: AuthService;
    let testClient: any;

    beforeEach(async () => {
        // Initialize database and services
        const db = new Database(":memory:");
        
        // Get OAuth schemas
        const { getOAuthSchemas } = await import("../../src/database/schema/oauth-schema-extensions");
        const oauthSchemas = getOAuthSchemas();
        
        const dbInitializer = new DatabaseInitializer({
            database: db,
            externalSchemas: oauthSchemas
        });
        
        // Initialize the database
        await dbInitializer.initialize();

        jwtService = new JWTService("test-secret");
        securityService = new SecurityService();
        authService = new AuthService(dbInitializer, jwtService);
        oauthService = new OAuthService(dbInitializer, securityService, jwtService, authService);

        // Create a test OAuth client
        const clientSecret = "test-secret-key";
        const hashedSecret = await Bun.password.hash(clientSecret, {
            algorithm: "bcrypt",
            cost: 10
        });

        testClient = await oauthService.createClient({
            client_id: `test-client-${Date.now()}`,
            client_secret: hashedSecret,
            client_name: "Test OAuth Client",
            redirect_uris: ["https://example.com/callback", "https://test.com/oauth/callback"],
            grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN, OAuthGrantType.CLIENT_CREDENTIALS, OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS],
            response_types: [OAuthResponseType.CODE, OAuthResponseType.TOKEN],
            scope: "read write profile email",
            is_public: false,
            is_active: true
        });

        testClient.plainSecret = clientSecret;
    });

    async function createTestUser() {
        const userData = {
            email: `test-${Date.now()}@example.com`,
            password: "test-password-123",
            username: `test-user-${Date.now()}`,
            first_name: "Test",
            last_name: "User"
        };

        const signupResult = await authService.register(userData);
        if (!signupResult.success || !signupResult.user) {
            throw new Error("Failed to create test user");
        }

        return {
            user: signupResult.user,
            userData
        };
    }

    describe("Authorization Code Grant", () => {
        test("should exchange authorization code for tokens", async () => {
            // 1. Create authorization request
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                scope: "read write",
                state: "test-state"
            };

            // 2. Handle authorization request (simulate user authentication)
            const { user } = await createTestUser();
            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);

            expect(authResponse.code).toBeDefined();
            expect(authResponse.state).toBe("test-state");

            // 3. Exchange code for token
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: authResponse.code!,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);

            expect(tokenResponse.access_token).toBeDefined();
            expect(tokenResponse.token_type).toBe("Bearer");
            expect(tokenResponse.expires_in).toBe(3600);
            expect(tokenResponse.refresh_token).toBeDefined();
            expect(tokenResponse.error).toBeUndefined();
        });

        test("should reject reused authorization code", async () => {
            // 1. Create authorization request
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                scope: "read"
            };

            const { user } = await createTestUser();
            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const code = authResponse.code!;

            // 2. Exchange code first time
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const firstResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(firstResponse.access_token).toBeDefined();
            expect(firstResponse.error).toBeUndefined();

            // 3. Try to reuse code - should fail
            const secondResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(secondResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
            expect(secondResponse.error_description).toContain("Authorization code has already been used");
            expect(secondResponse.access_token).toBe("");
        });

        test("should verify PKCE challenge correctly", async () => {
            // Generate PKCE challenge
            const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

            // 1. Create authorization request with PKCE
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                code_challenge: pkceChallenge.code_challenge,
                code_challenge_method: "S256" as any
            };

            const { user } = await createTestUser();
            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const code = authResponse.code!;

            // 2. Exchange code with verifier
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback",
                code_verifier: pkceChallenge.code_verifier
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.access_token).toBeDefined();
            expect(tokenResponse.error).toBeUndefined();
        });

        test("should reject wrong PKCE verifier", async () => {
            // Generate PKCE challenge
            const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

            // 1. Create authorization request with PKCE
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                code_challenge: pkceChallenge.code_challenge,
                code_challenge_method: "S256" as any
            };

            const { user } = await createTestUser();
            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const code = authResponse.code!;

            // 2. Exchange code with wrong verifier
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback",
                code_verifier: "wrong-verifier"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid PKCE verifier");
            expect(tokenResponse.access_token).toBe("");
        });

        test("should reject invalid authorization code", async () => {
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: "invalid-code",
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid authorization code");
            expect(tokenResponse.access_token).toBe("");
        });
    });

    describe("Refresh Token Grant", () => {
        test("should exchange refresh token for new access token", async () => {
            // 1. Get initial tokens via authorization code
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                scope: "read write"
            };

            const { user } = await createTestUser();
            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const code = authResponse.code!;

            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const initialTokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            const refreshToken = initialTokenResponse.refresh_token!;

            // 2. Use refresh token to get new access token
            const refreshRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret
            };

            const newTokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            expect(newTokenResponse.access_token).toBeDefined();
            expect(newTokenResponse.token_type).toBe("Bearer");
            expect(newTokenResponse.refresh_token).toBeDefined(); // New refresh token
            expect(newTokenResponse.error).toBeUndefined();
        });

        test("should reject invalid refresh token", async () => {
            const refreshRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: "invalid-refresh-token",
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            expect(tokenResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid refresh token");
            expect(tokenResponse.access_token).toBe("");
        });
    });

    describe("Client Credentials Grant", () => {
        test("should issue token for client credentials", async () => {
            const tokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                scope: "read"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.access_token).toBeDefined();
            expect(tokenResponse.token_type).toBe("Bearer");
            expect(tokenResponse.expires_in).toBe(3600);
            expect(tokenResponse.error).toBeUndefined();
        });

        test("should reject client credentials for public clients", async () => {
            // Create public client
            const publicClient = await oauthService.createClient({
                client_id: `public-client-${Date.now()}`,
                client_name: "Public Client",
                redirect_uris: ["https://example.com/callback"],
                grant_types: [OAuthGrantType.AUTHORIZATION_CODE],
                response_types: [OAuthResponseType.CODE],
                is_public: true,
                is_active: true
            });

            const tokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: publicClient.client_id,
                scope: "read"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.error).toBe(OAuthErrorType.UNAUTHORIZED_CLIENT);
            expect(tokenResponse.error_description).toContain("Public clients cannot use client credentials grant");
            expect(tokenResponse.access_token).toBe("");
        });
    });

    describe("Password Grant", () => {
        test("should issue token for password grant", async () => {
            const { user, userData } = await createTestUser();

            const tokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                username: userData.email,
                password: userData.password,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.access_token).toBeDefined();
            expect(tokenResponse.refresh_token).toBeDefined();
            expect(tokenResponse.token_type).toBe("Bearer");
            expect(tokenResponse.error).toBeUndefined();
        });

        test("should reject invalid credentials in password grant", async () => {
            const tokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                username: "nonexistent@example.com",
                password: "wrongpassword",
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            expect(tokenResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid user credentials");
            expect(tokenResponse.access_token).toBe("");
        });
    });

    describe("Token Introspection", () => {
        test("should introspect valid access token", async () => {
            // Get a valid token first
            const { user } = await createTestUser();
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                scope: "read write"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: authResponse.code!,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            const accessToken = tokenResponse.access_token;

            // Introspect the token
            const introspectRequest = {
                token: accessToken,
                token_type_hint: "access_token" as const
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(true);
            expect(introspectResponse.token_type).toBe("Bearer");
            expect(introspectResponse.sub).toBeDefined();
        });

        test("should return inactive for invalid token", async () => {
            const introspectRequest = {
                token: "invalid-token",
                token_type_hint: "access_token" as const
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(false);
        });
    });

    describe("Token Revocation", () => {
        test("should revoke refresh token", async () => {
            // Get a refresh token first
            const { user } = await createTestUser();
            const authRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: testClient.client_id,
                redirect_uri: "https://example.com/callback",
                scope: "read write"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, user);
            const tokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: authResponse.code!,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            const refreshToken = tokenResponse.refresh_token!;

            // Revoke the token
            const revokeRequest = {
                token: refreshToken,
                token_type_hint: "refresh_token" as const
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);

            // Verify token is revoked by trying to use it
            const refreshRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: testClient.client_id,
                client_secret: testClient.plainSecret
            };

            const refreshResponse = await oauthService.handleTokenRequest(refreshRequest);
            expect(refreshResponse.error).toBe(OAuthErrorType.INVALID_GRANT);
        });

        test("should return success even for invalid token (per OAuth spec)", async () => {
            const revokeRequest = {
                token: "invalid-token",
                token_type_hint: "access_token" as const
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);
        });
    });
});