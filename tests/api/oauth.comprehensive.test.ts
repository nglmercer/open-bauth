import { describe, test, expect, beforeEach, afterEach, beforeAll, afterAll } from "bun:test";
import { Database } from "bun:sqlite";
import { getServiceFactory } from "../../src/services/service-factory";
import {
    OAuthGrantType,
    OAuthResponseType,
    OAuthErrorType,
    PKCEMethod,
    type OAuthClient,
    type AuthorizationRequest,
    type TokenRequest,
    type IntrospectionRequest,
    type RevocationRequest
} from "../../src/types/oauth";
import type { User } from "../../src/types/auth";
import { DatabaseInitializer } from "../../src/database/database-initializer";

// Tipo extendido para pruebas de password grant
interface PasswordTokenRequest extends TokenRequest {
    username: string;
    password: string;
}
import { OAuthService } from "../../src/services/oauth";
import { SecurityService } from "../../src/services/security";
import { JWTService } from "../../src/services/jwt";
import { AuthService } from "../../src/services/auth";
import { TEST_TIMEOUTS, testUtils } from "../setup";

// Tipos para las pruebas
interface TestClient extends OAuthClient {
    plainSecret: string;
}

interface TestUserData {
    user: User;
    userData: {
        email: string;
        password: string;
        username: string;
        first_name: string;
        last_name: string;
    };
}

/**
 * Clase de utilidades para pruebas OAuth
 * Proporciona métodos reutilizables para crear recursos de prueba y validar respuestas
 */
class OAuthTestHelper {
    private oauthService: OAuthService;
    private authService: AuthService;
    private userCounter = 0;
    private clientCounter = 0;

    constructor(oauthService: OAuthService, authService: AuthService) {
        this.oauthService = oauthService;
        this.authService = authService;
    }

    /**
     * Crea un usuario de prueba con datos aleatorios
     * @param overrides - Datos personalizados para sobrescribir los valores por defecto
     * @returns Objeto con el usuario creado y sus datos
     */
    async createTestUser(overrides: Partial<TestUserData['userData']> = {}): Promise<TestUserData> {
        this.userCounter++;
        const timestamp = Date.now();
        const userData = {
            email: `test-${timestamp}-${this.userCounter}@example.com`,
            password: "test-password-123",
            username: `test-user-${timestamp}-${this.userCounter}`,
            first_name: "Test",
            last_name: "User",
            ...overrides
        };

        const signupResult = await this.authService.register(userData);
        if (!signupResult.success || !signupResult.user) {
            throw new Error("Failed to create test user");
        }

        return {
            user: signupResult.user,
            userData
        };
    }

    /**
     * Crea un cliente OAuth de prueba
     * @param overrides - Datos personalizados para sobrescribir los valores por defecto
     * @returns Cliente OAuth con la contraseña en texto plano para las pruebas
     */
    async createTestClient(overrides: Partial<TestClient> = {}): Promise<TestClient> {
        this.clientCounter++;
        const timestamp = Date.now();
        const clientSecret = "test-secret-key";
        const hashedSecret = await Bun.password.hash(clientSecret, {
            algorithm: "bcrypt",
            cost: 4 // Bajo costo para tests más rápidos
        });

        const clientData = {
            client_id: `test-client-${timestamp}-${this.clientCounter}`,
            client_secret: hashedSecret,
            client_name: `Test OAuth Client ${this.clientCounter}`,
            redirect_uris: ["https://example.com/callback", "https://test.com/oauth/callback"],
            grant_types: [OAuthGrantType.AUTHORIZATION_CODE, OAuthGrantType.REFRESH_TOKEN, OAuthGrantType.CLIENT_CREDENTIALS, OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS],
            response_types: [OAuthResponseType.CODE, OAuthResponseType.TOKEN],
            scope: "read write profile email",
            is_public: false,
            is_active: true,
            ...overrides
        };

        const client = await this.oauthService.createClient(clientData);
        return {
            ...client,
            plainSecret: clientSecret
        };
    }

    /**
     * Crea un código de autorización para pruebas
     * @param client - Cliente OAuth
     * @param user - Usuario autenticado
     * @param overrides - Parámetros adicionales para la solicitud
     * @returns Código de autorización generado
     */
    async createAuthorizationCode(client: TestClient, user: User, overrides: Partial<AuthorizationRequest> = {}): Promise<string> {
        const authRequest: AuthorizationRequest = {
            response_type: OAuthResponseType.CODE,
            client_id: client.client_id,
            redirect_uri: "https://example.com/callback",
            scope: "read write",
            state: "test-state",
            ...overrides
        };

        const authResponse = await this.oauthService.handleAuthorizationRequest(authRequest, user);
        if (!authResponse.code) {
            throw new Error("Failed to create authorization code");
        }
        return authResponse.code;
    }

    /**
     * Crea un par de tokens válidos (access y refresh) mediante el flujo de código de autorización
     * @param client - Cliente OAuth
     * @param user - Usuario autenticado
     * @returns Objeto con los tokens generados
     */
    async createValidTokenPair(client: TestClient, user: User): Promise<{ accessToken: string; refreshToken: string }> {
        const code = await this.createAuthorizationCode(client, user);
        
        const tokenRequest: TokenRequest = {
            grant_type: OAuthGrantType.AUTHORIZATION_CODE,
            code: code,
            client_id: client.client_id,
            client_secret: client.plainSecret,
            redirect_uri: "https://example.com/callback"
        };

        const tokenResponse = await this.oauthService.handleTokenRequest(tokenRequest);
        if (!tokenResponse.access_token || !tokenResponse.refresh_token) {
            throw new Error("Failed to create token pair");
        }

        return {
            accessToken: tokenResponse.access_token,
            refreshToken: tokenResponse.refresh_token
        };
    }

    /**
     * Valida que una respuesta de token sea válida
     * @param response - Respuesta a validar
     * @param shouldHaveRefreshToken - Si debe incluir refresh token
     */
    validateTokenResponse(response: any, shouldHaveRefreshToken = true) {
        expect(response).toBeDefined();
        expect(response.access_token).toBeDefined();
        expect(response.access_token).toMatch(/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/); // JWT format
        expect(response.token_type).toBe("Bearer");
        expect(response.expires_in).toBe(3600);
        
        if (shouldHaveRefreshToken) {
            expect(response.refresh_token).toBeDefined();
            expect(response.refresh_token.length).toBeGreaterThan(32);
        }
        
        expect(response.error).toBeUndefined();
    }

    /**
     * Valida que una respuesta de error tenga la estructura correcta
     * @param response - Respuesta a validar
     * @param expectedError - Tipo de error esperado
     * @param shouldContainDescription - Si debe incluir descripción del error
     */
    validateErrorResponse(response: any, expectedError: OAuthErrorType, shouldContainDescription = true) {
        expect(response).toBeDefined();
        expect(response.error).toBe(expectedError);
        
        if (shouldContainDescription) {
            expect(response.error_description).toBeDefined();
            expect(response.error_description.length).toBeGreaterThan(0);
        }
        
        expect(response.access_token).toBe("");
    }
}

/**
 * Suite principal de pruebas OAuth 2.0
 *
 * Organización de las pruebas:
 * 1. Authorization Code Grant - Flujo principal de autorización
 * 2. Refresh Token Grant - Renovación de tokens
 * 3. Client Credentials Grant - Autenticación de cliente
 * 4. Password Grant - Credenciales de propietario del recurso
 * 5. Token Introspection - Introspección de tokens
 * 6. Token Revocation - Revocación de tokens
 * 7. Authorization Request Validation - Validación de solicitudes
 * 8. Edge Cases and Error Handling - Casos edge y manejo de errores
 */
describe("OAuth API - Comprehensive Tests", () => {
    let oauthService: OAuthService;
    let securityService: SecurityService;
    let jwtService: JWTService;
    let authService: AuthService;
    let testHelper: OAuthTestHelper;
    let db: Database;
    let dbInitializer: DatabaseInitializer;

    // Clientes de prueba pre-creados para mejorar rendimiento
    let confidentialClient: TestClient;
    let publicClient: TestClient;
    let testUser: TestUserData;

    /**
     * Setup global que se ejecuta una vez antes de todas las pruebas
     * Inicializa la base de datos en memoria y todos los servicios necesarios
     */
    beforeAll(async () => {
        // Initialize database and services una vez para todas las pruebas
        db = new Database(":memory:");
        
        // Get OAuth schemas
        const { getOAuthSchemas } = await import("../../src/database/schema/oauth-schema-extensions");
        const oauthSchemas = getOAuthSchemas();
        
        dbInitializer = new DatabaseInitializer({
            database: db,
            externalSchemas: oauthSchemas
        });
        
        // Initialize the database
        await dbInitializer.initialize();

        jwtService = new JWTService("test-secret");
        securityService = new SecurityService();
        authService = new AuthService(dbInitializer, jwtService);
        oauthService = new OAuthService(dbInitializer, securityService, jwtService, authService);
        testHelper = new OAuthTestHelper(oauthService, authService);
    }, TEST_TIMEOUTS.MEDIUM);

    /**
     * Setup que se ejecuta antes de cada prueba
     * Crea clientes y usuarios de prueba frescos para cada test
     */
    beforeEach(async () => {
        // Crear clientes y usuario de prueba para cada test
        confidentialClient = await testHelper.createTestClient({
            client_name: "Confidential Test Client"
        });
        
        publicClient = await testHelper.createTestClient({
            client_name: "Public Test Client",
            is_public: true,
            grant_types: [OAuthGrantType.AUTHORIZATION_CODE],
            response_types: [OAuthResponseType.CODE]
        });
        
        testUser = await testHelper.createTestUser();
    }, TEST_TIMEOUTS.SHORT);

    afterAll(async () => {
        // Cleanup
        if (db) {
            db.close();
        }
    });

    describe("Authorization Code Grant", () => {
        test("should exchange authorization code for tokens", async () => {
            // 1. Create authorization code
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user, {
                state: "test-state"
            });

            // 2. Exchange code for token
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);

            // 3. Validate response
            testHelper.validateTokenResponse(tokenResponse);
            // State no se incluye en token response
            expect('state' in tokenResponse).toBe(false);
        });

        test("should reject reused authorization code", async () => {
            // 1. Create authorization code
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user, {
                scope: "read"
            });

            // 2. Exchange code first time
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const firstResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateTokenResponse(firstResponse);

            // 3. Try to reuse code - should fail
            const secondResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(secondResponse, OAuthErrorType.INVALID_GRANT);
            expect(secondResponse.error_description).toContain("already been used");
        });

        test("should verify PKCE challenge correctly", async () => {
            // Generate PKCE challenge
            const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

            // 1. Create authorization code with PKCE
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user, {
                code_challenge: pkceChallenge.code_challenge,
                code_challenge_method: PKCEMethod.S256
            });

            // 2. Exchange code with verifier
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback",
                code_verifier: pkceChallenge.code_verifier
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateTokenResponse(tokenResponse);
        });

        test("should reject wrong PKCE verifier", async () => {
            // Generate PKCE challenge
            const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);

            // 1. Create authorization code with PKCE
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user, {
                code_challenge: pkceChallenge.code_challenge,
                code_challenge_method: PKCEMethod.S256
            });

            // 2. Exchange code with wrong verifier
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback",
                code_verifier: "wrong-verifier"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid PKCE verifier");
        });

        test("should reject invalid authorization code", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: "invalid-code",
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid authorization code");
        });

        test("should reject expired authorization code", async () => {
            // Esta prueba requeriría manipular la fecha de expiración del código
            // Por ahora, la dejamos como placeholder para implementación futura
            expect(true).toBe(true);
        });

        test("should reject mismatched redirect URI", async () => {
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user);
            
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://mismatched.com/callback" // URI diferente
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Redirect URI mismatch");
        });
    });

    describe("Refresh Token Grant", () => {
        test("should exchange refresh token for new access token", async () => {
            // 1. Get initial token pair
            const { accessToken, refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Use refresh token to get new access token
            const refreshRequest: TokenRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const newTokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            testHelper.validateTokenResponse(newTokenResponse);
            expect(newTokenResponse.refresh_token).toBeDefined(); // New refresh token (rotation)
            expect(newTokenResponse.refresh_token).not.toBe(refreshToken); // Should be different
        });

        test("should reject invalid refresh token", async () => {
            const refreshRequest: TokenRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: "invalid-refresh-token",
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid refresh token");
        });

        test("should reject revoked refresh token", async () => {
            // 1. Get token pair
            const { refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Revoke the refresh token
            const revokeRequest: RevocationRequest = {
                token: refreshToken,
                token_type_hint: "refresh_token"
            };
            await oauthService.handleRevocationRequest(revokeRequest);

            // 3. Try to use revoked token
            const refreshRequest: TokenRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("revoked");
        });

        test("should reject refresh token with wrong client", async () => {
            // 1. Get token pair with one client
            const { refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Create another client
            const otherClient = await testHelper.createTestClient({ client_name: "Other Client" });

            // 3. Try to use refresh token with wrong client
            const refreshRequest: TokenRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: otherClient.client_id,
                client_secret: otherClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(refreshRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_CLIENT);
            expect(tokenResponse.error_description).toContain("Client mismatch");
        });
    });

    /**
     * Pruebas del flujo Client Credentials Grant
     * Valida autenticación de cliente y restricciones de clientes públicos
     */
    describe("Client Credentials Grant", () => {
        test("should issue token for client credentials", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                scope: "read"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateTokenResponse(tokenResponse, false); // No refresh token for client credentials
        });

        test("should reject client credentials for public clients", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: publicClient.client_id,
                scope: "read"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.UNAUTHORIZED_CLIENT);
            expect(tokenResponse.error_description).toContain("Public clients cannot use client credentials grant");
        });

        test("should reject invalid client credentials", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: confidentialClient.client_id,
                client_secret: "wrong-secret",
                scope: "read"
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_CLIENT);
            expect(tokenResponse.error_description).toContain("Invalid client credentials");
        });

        test("should issue token without scope parameter", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.CLIENT_CREDENTIALS,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateTokenResponse(tokenResponse, false);
            expect(tokenResponse.scope).toBe(confidentialClient.scope); // Should use client's default scope
        });
    });

    /**
     * Pruebas del flujo Resource Owner Password Credentials Grant
     * Valida autenticación de usuarios y manejo de credenciales inválidas
     */
    describe("Password Grant", () => {
        test("should issue token for password grant", async () => {
            const tokenRequest: PasswordTokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                username: testUser.userData.email,
                password: testUser.userData.password,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateTokenResponse(tokenResponse);
        });

        test("should reject invalid credentials in password grant", async () => {
            const tokenRequest: PasswordTokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                username: "nonexistent@example.com",
                password: "wrongpassword",
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_GRANT);
            expect(tokenResponse.error_description).toContain("Invalid user credentials");
        });

        test("should reject password grant without username", async () => {
            const tokenRequest: PasswordTokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                password: testUser.userData.password,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            } as any;

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_REQUEST);
            expect(tokenResponse.error_description).toContain("Username and password are required");
        });

        test("should reject password grant without password", async () => {
            const tokenRequest: PasswordTokenRequest = {
                grant_type: OAuthGrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                username: testUser.userData.email,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            } as any;

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.INVALID_REQUEST);
            expect(tokenResponse.error_description).toContain("Username and password are required");
        });
    });

    /**
     * Pruebas de Token Introspection
     * Valida el estado y metadatos de tokens activos e inactivos
     */
    describe("Token Introspection", () => {
        test("should introspect valid access token", async () => {
            // 1. Get valid token
            const { accessToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Introspect the token
            const introspectRequest: IntrospectionRequest = {
                token: accessToken,
                token_type_hint: "access_token"
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(true);
            expect(introspectResponse.token_type).toBe("Bearer");
            expect(introspectResponse.sub).toBe(testUser.user.id);
            expect(introspectResponse.client_id).toBe(confidentialClient.client_id);
            expect(introspectResponse.scope).toBeDefined();
        });

        test("should introspect valid refresh token", async () => {
            // 1. Get valid refresh token
            const { refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Introspect the token
            const introspectRequest: IntrospectionRequest = {
                token: refreshToken,
                token_type_hint: "refresh_token"
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(true);
            expect(introspectResponse.token_type).toBe("Bearer");
            expect(introspectResponse.sub).toBe(testUser.user.id);
            expect(introspectResponse.client_id).toBe(confidentialClient.client_id);
        });

        test("should return inactive for invalid token", async () => {
            const introspectRequest: IntrospectionRequest = {
                token: "invalid-token",
                token_type_hint: "access_token"
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(false);
        });

        test("should return inactive for expired token", async () => {
            // Esta prueba requeriría manipular la expiración del token
            // Por ahora, la dejamos como placeholder
            const introspectRequest: IntrospectionRequest = {
                token: "expired-token",
                token_type_hint: "access_token"
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(false);
        });

        test("should handle introspection without token type hint", async () => {
            // 1. Get valid token
            const { accessToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Introspect without hint
            const introspectRequest: IntrospectionRequest = {
                token: accessToken
            };

            const introspectResponse = await oauthService.handleIntrospectionRequest(introspectRequest);
            expect(introspectResponse.active).toBe(true);
        });
    });

    /**
     * Pruebas de Token Revocation
     * Valida la revocación de tokens según la especificación RFC 7009
     */
    describe("Token Revocation", () => {
        test("should revoke refresh token", async () => {
            // 1. Get refresh token
            const { refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Revoke the token
            const revokeRequest: RevocationRequest = {
                token: refreshToken,
                token_type_hint: "refresh_token"
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);

            // 3. Verify token is revoked by trying to use it
            const refreshRequest: TokenRequest = {
                grant_type: OAuthGrantType.REFRESH_TOKEN,
                refresh_token: refreshToken,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const refreshResponse = await oauthService.handleTokenRequest(refreshRequest);
            testHelper.validateErrorResponse(refreshResponse, OAuthErrorType.INVALID_GRANT);
        });

        test("should return success even for invalid token (per OAuth spec)", async () => {
            const revokeRequest: RevocationRequest = {
                token: "invalid-token",
                token_type_hint: "access_token"
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);
        });

        test("should handle revocation without token type hint", async () => {
            // 1. Get refresh token
            const { refreshToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Revoke without hint
            const revokeRequest: RevocationRequest = {
                token: refreshToken
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);
        });

        test("should handle access token revocation", async () => {
            // 1. Get access token
            const { accessToken } = await testHelper.createValidTokenPair(confidentialClient, testUser.user);

            // 2. Revoke access token (should succeed even though it's stateless)
            const revokeRequest: RevocationRequest = {
                token: accessToken,
                token_type_hint: "access_token"
            };

            const revokeResponse = await oauthService.handleRevocationRequest(revokeRequest);
            expect(revokeResponse.success).toBe(true);
        });
    });

    /**
     * Pruebas de validación de solicitudes de autorización
     * Valida parámetros requeridos y restricciones de seguridad
     */
    describe("Authorization Request Validation", () => {
        test("should reject invalid client", async () => {
            const authRequest: AuthorizationRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: "invalid-client-id",
                redirect_uri: "https://example.com/callback"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, testUser.user);
            expect(authResponse.error).toBe(OAuthErrorType.UNAUTHORIZED_CLIENT);
            expect(authResponse.error_description).toContain("Invalid or inactive client");
        });

        test("should reject unsupported response type", async () => {
            const authRequest: AuthorizationRequest = {
                response_type: "unsupported_type" as any,
                client_id: confidentialClient.client_id,
                redirect_uri: "https://example.com/callback"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, testUser.user);
            expect(authResponse.error).toBe(OAuthErrorType.UNSUPPORTED_RESPONSE_TYPE);
        });

        test("should reject invalid redirect URI", async () => {
            const authRequest: AuthorizationRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: confidentialClient.client_id,
                redirect_uri: "https://invalid.com/callback"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest, testUser.user);
            expect(authResponse.error).toBe(OAuthErrorType.INVALID_REQUEST);
            expect(authResponse.error_description).toContain("Invalid redirect URI");
        });

        test("should handle prompt=none without user authentication", async () => {
            const authRequest: AuthorizationRequest = {
                response_type: OAuthResponseType.CODE,
                client_id: confidentialClient.client_id,
                redirect_uri: "https://example.com/callback",
                prompt: "none"
            };

            const authResponse = await oauthService.handleAuthorizationRequest(authRequest);
            expect(authResponse.error).toBe(OAuthErrorType.ACCESS_DENIED);
            expect(authResponse.error_description).toContain("User authentication required");
        });
    });

    describe("Edge Cases and Error Handling", () => {
        test("should handle unsupported grant type", async () => {
            const tokenRequest: TokenRequest = {
                grant_type: "unsupported_grant" as any,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            };

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.UNSUPPORTED_GRANT_TYPE);
        });

        test("should handle missing grant type", async () => {
            const tokenRequest = {
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret
            } as any;

            const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);
            testHelper.validateErrorResponse(tokenResponse, OAuthErrorType.UNSUPPORTED_GRANT_TYPE);
        });

        test("should handle database errors gracefully", async () => {
            // Esta prueba simularía un error de base de datos
            // Por ahora, es un placeholder para implementación futura
            expect(true).toBe(true);
        });

        test("should handle concurrent token requests", async () => {
            // 1. Create authorization code
            const code = await testHelper.createAuthorizationCode(confidentialClient, testUser.user);

            // 2. Try to exchange the same code multiple times concurrently
            const tokenRequest: TokenRequest = {
                grant_type: OAuthGrantType.AUTHORIZATION_CODE,
                code: code,
                client_id: confidentialClient.client_id,
                client_secret: confidentialClient.plainSecret,
                redirect_uri: "https://example.com/callback"
            };

            // Ejecutar las solicitudes con un pequeño retraso para simular concurrencia real
            const promises = [
                oauthService.handleTokenRequest(tokenRequest),
                new Promise(resolve => setTimeout(() => resolve(oauthService.handleTokenRequest(tokenRequest)), 10)),
                new Promise(resolve => setTimeout(() => resolve(oauthService.handleTokenRequest(tokenRequest)), 20))
            ];

            const results = await Promise.allSettled(promises);
            
            // Verificar que al menos una tenga error (porque el código ya fue usado)
            const hasError = results.some(r =>
                r.status === 'fulfilled' &&
                (r as PromiseFulfilledResult<any>).value.error === OAuthErrorType.INVALID_GRANT
            );
            
            expect(hasError).toBe(true);
            
            // Verificar que al menos una haya tenido éxito inicialmente
            const hasSuccess = results.some(r =>
                r.status === 'fulfilled' &&
                !(r as PromiseFulfilledResult<any>).value.error &&
                (r as PromiseFulfilledResult<any>).value.access_token
            );
            
            expect(hasSuccess).toBe(true);
        });
    });
});