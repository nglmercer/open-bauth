// examples/oauth-usage-example.ts

/**
 * Ejemplo de uso completo de OAuth 2.0 con las nuevas funcionalidades
 * Demuestra cómo configurar y utilizar el sistema OAuth 2.0 extendido
 */

import { DatabaseInitializer } from "../src/database/database-initializer";
import { Database } from "bun:sqlite";
import { AuthService, JWTService, PermissionService } from "../src/services";
import {
  OAuthService,
  SecurityService,
  EnhancedUserService,
} from "../src/services";
import {
  OAuthGrantType,
  OAuthResponseType,
  PKCEMethod,
  MFAType,
  BiometricType,
  DeviceType,
} from "../src/types/oauth";

async function main() {
  console.log("🚀 Iniciando ejemplo de OAuth 2.0 extendido...");

  // 1. Inicializar base de datos
  const db = new Database(":memory:");
  const dbInitializer = new DatabaseInitializer({ database: db });

  // 2. Inicializar servicios
  const jwtService = new JWTService(
    "your-super-secret-jwt-key",
    "1h",
    "https://your-auth-server.com",
    "your-api",
  );
  const securityService = new SecurityService();
  const authService = new AuthService(dbInitializer, jwtService);
  const permissionService = new PermissionService(dbInitializer);
  const oauthService = new OAuthService(
    dbInitializer,
    securityService,
    jwtService,
    authService,
  );
  const enhancedUserService = new EnhancedUserService(
    dbInitializer,
    securityService,
  );


  // 3. Inicializar base de datos con esquemas OAuth
  await dbInitializer.initialize();

  console.log("✅ Base de datos inicializada");

  // 4. Crear cliente OAuth 2.0
  const oauthClient = await oauthService.createClient({
    client_id: "demo-client-id",
    client_secret: "demo-client-secret",
    client_name: "Demo Application",
    redirect_uris: [
      "https://demo-app.com/callback",
      "http://localhost:3000/callback",
    ],
    grant_types: [
      OAuthGrantType.AUTHORIZATION_CODE,
      OAuthGrantType.REFRESH_TOKEN,
    ],
    response_types: [OAuthResponseType.CODE],
    scope: "read write profile",
    is_public: false,
  });

  console.log("✅ Cliente OAuth 2.0 creado:", oauthClient.client_name);

  // 5. Crear usuario de ejemplo
  const userResult = await authService.register({
    email: "user@example.com",
    password: "SecurePassword123!",
    first_name: "John",
    last_name: "Doe",
  });

  if (!userResult.success) {
    console.error("❌ Error creando usuario:", userResult.error);
    return;
  }

  const user = userResult.user!;
  console.log("✅ Usuario creado:", user.email);

  // 6. Configurar MFA para el usuario
  const mfaResult = await enhancedUserService.setupMFA(user.id, MFAType.TOTP, {
    secret: "JBSWY3DPEHPK3PXP", // En producción, generar con TOTP library
    is_primary: true,
  });

  if (mfaResult.success) {
    console.log("MFA TOTP configurado para el usuario");
  }

  // 7. Registrar dispositivo biométrico
  const biometricResult = await enhancedUserService.registerBiometricCredential(
    user.id,
    BiometricType.FINGERPRINT,
    "encrypted-biometric-template-data", // En producción, datos biométricos encriptados
    "device-123",
  );

  if (biometricResult.success) {
    console.log("Credencial biométrica registrada");
  }

  // 8. Registrar dispositivo para SSO
  const deviceResult = await enhancedUserService.registerDevice(
    user.id,
    "device-unique-id",
    "iPhone 14 Pro",
    DeviceType.MOBILE,
    "iOS",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15",
  );

  if (deviceResult.success) {
    console.log("✅ Dispositivo registrado para SSO");
  }

  // 9. Confianza en dispositivo para SSO sin contraseña
  await enhancedUserService.trustDevice(user.id, "device-unique-id");
  console.log("✅ Dispositivo marcado como confiable para SSO");

  // 10. Demostrar flujo de Authorization Code con PKCE
  console.log("\n🔐 Demostrando flujo de Authorization Code con PKCE...");

  // Generar PKCE challenge
  const pkceChallenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
  console.log("📋 PKCE Challenge generado:", {
    code_challenge: pkceChallenge.code_challenge,
    code_challenge_method: pkceChallenge.code_challenge_method,
  });

  // Crear solicitud de autorización
  const authRequest = {
    response_type: OAuthResponseType.CODE,
    client_id: oauthClient.client_id,
    redirect_uri: "https://demo-app.com/callback",
    scope: "read write profile",
    state: securityService.generateState(),
    nonce: securityService.generateNonce(),
    code_challenge: pkceChallenge.code_challenge,
    code_challenge_method: pkceChallenge.code_challenge_method,
  };

  // Simular usuario autenticado y consentimiento dado
  const authResponse = await oauthService.handleAuthorizationRequest(
    authRequest,
    user,
  );

  if (authResponse.code) {
    console.log("✅ Authorization code generado:", authResponse.code);

    // 11. Demostrar intercambio de código por token
    console.log("\n🔄 Demostrando intercambio de código por token...");

    const tokenRequest = {
      grant_type: OAuthGrantType.AUTHORIZATION_CODE,
      code: authResponse.code,
      redirect_uri: "https://demo-app.com/callback",
      client_id: oauthClient.client_id,
      client_secret: "demo-client-secret",
      code_verifier: pkceChallenge.code_verifier,
    };

    const tokenResponse = await oauthService.handleTokenRequest(tokenRequest);

    if (tokenResponse.access_token) {
      console.log("✅ Access token generado:", tokenResponse.access_token);
      console.log("📋 Token info:", {
        token_type: tokenResponse.token_type,
        expires_in: tokenResponse.expires_in,
        scope: tokenResponse.scope,
      });

      if (tokenResponse.refresh_token) {
        console.log("🔄 Refresh token generado:", tokenResponse.refresh_token);
      }

      // 12. Demostrar verificación de token
      console.log("\n🔍 Demostrando verificación de token...");

      try {
        const payload = await jwtService.verifyToken(
          tokenResponse.access_token,
        );
        console.log("✅ Token verificado:", {
          userId: payload.userId,
          email: payload.email,
          roles: payload.roles,
        });
      } catch (error) {
        console.error("❌ Error verificando token:", error);
      }

      // 13. Demostrar refresh token
      if (tokenResponse.refresh_token) {
        console.log("\n🔄 Demostrando refresh token...");

        const refreshRequest = {
          grant_type: OAuthGrantType.REFRESH_TOKEN,
          refresh_token: tokenResponse.refresh_token,
          client_id: oauthClient.client_id,
          client_secret: "demo-client-secret",
        };

        const refreshResponse =
          await oauthService.handleTokenRequest(refreshRequest);

        if (refreshResponse.access_token) {
          console.log("✅ Nuevo access token generado via refresh");
          console.log("🔄 Nuevo refresh token:", refreshResponse.refresh_token);
        }
      }

      // 14. Demostrar introspección de token
      console.log("\n🔍 Demostrando introspección de token...");

      const introspectionRequest = {
        token: tokenResponse.access_token,
      };

      const introspectionResponse =
        await oauthService.handleIntrospectionRequest(introspectionRequest);

      console.log("📋 Introspección:", {
        active: introspectionResponse.active,
        scope: introspectionResponse.scope,
        client_id: introspectionResponse.client_id,
        username: introspectionResponse.username,
      });

      // 15. Demostrar revocación de token
      console.log("\n🗑️ Demostrando revocación de token...");

      const revocationRequest = {
        token: tokenResponse.access_token,
        client_id: oauthClient.client_id,
        client_secret: "demo-client-secret",
      };

      const revocationResult =
        await oauthService.handleRevocationRequest(revocationRequest);

      if (revocationResult.success) {
        console.log("✅ Token revocado exitosamente");
      }
    }
  }

  // 16. Demostrar Device Authorization Flow
  console.log("\n📱 Demostrando Device Authorization Flow...");

  const deviceAuthRequest = {
    client_id: oauthClient.client_id,
    scope: "read write profile",
  };

  const deviceAuthResponse =
    await oauthService.handleDeviceAuthorizationRequest(deviceAuthRequest);

  if (deviceAuthResponse.device_code) {
    console.log("✅ Device authorization generado:", {
      device_code: deviceAuthResponse.device_code,
      user_code: deviceAuthResponse.user_code,
      verification_uri: deviceAuthResponse.verification_uri,
      expires_in: deviceAuthResponse.expires_in,
    });

    console.log(
      "📱 Usuario debe visitar:",
      deviceAuthResponse.verification_uri_complete,
    );
    console.log("📱 E ingresar código:", deviceAuthResponse.user_code);
  }

  // 17. Demostrar autenticación biométrica
  console.log("\n👆 Demostrando autenticación biométrica...");

  const biometricAuthResult =
    await enhancedUserService.verifyBiometricCredential(
      user.id,
      BiometricType.FINGERPRINT,
      "provided-biometric-data", // En producción, datos biométricos del dispositivo
    );

  if (biometricAuthResult.success) {
    console.log("✅ Autenticación biométrica exitosa");
  } else {
    console.error(
      "❌ Autenticación biométrica fallida:",
      biometricAuthResult.error,
    );
  }

  // 18. Demostrar SSO con device secret
  console.log("\n🔐 Demostrando SSO con device secret...");

  const deviceSecretResult = await enhancedUserService.verifyDeviceSecret(
    "device-unique-id",
    "provided-device-secret", // En producción, secreto almacenado en dispositivo
  );

  if (deviceSecretResult.success) {
    console.log("✅ SSO exitoso con device secret");
  } else {
    console.error("❌ SSO fallido:", deviceSecretResult.error);
  }

  // Cerrar conexión de base de datos
  db.close();
}

// Ejecutar ejemplo
if (import.meta.main) {
  main().catch(console.error);
}
