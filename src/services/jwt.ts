// src/services/jwt.ts
import type { JWTPayload, User } from "../types/auth";
import type { OAuthJWTPayload } from "../types/oauth";
import type { IJWTServiceExtended } from "../types/jwt-service";
import { ServiceErrors } from "./constants";

/**
 * Servicio para manejar operaciones JWT
 * Utiliza Web Crypto API nativo para firmas HMAC
 * Soporta DPoP (RFC 9449), tokens OIDC y rotación de refresh tokens
 */
export class JWTService implements IJWTServiceExtended {
  private secret: string;
  private expiresIn: string;
  private issuer: string;
  private audience: string;
  private dpopNonceCache: Map<string, number> = new Map();

  constructor(
    secret: string,
    expiresIn: string = "24h",
    issuer: string = "http://localhost",
    audience: string = "audience",
  ) {
    if (!secret) {
      throw new Error(ServiceErrors.JWT_SECRET_REQUIRED);
    }
    this.secret = secret;
    this.expiresIn = expiresIn;
    this.issuer = issuer;
    this.audience = audience;
  }

  /**
   * Genera un token JWT para un usuario
   * @param user Usuario para el cual generar el token
   * @returns Token JWT
   */
  async generateToken(user: User): Promise<string> {
    // FIX: Añadir validación de entrada para el objeto de usuario.
    if (!user || !user.id || !user.email) {
      throw new Error(
        ServiceErrors.INVALID_USER_OBJECT,
      );
    }

    try {
      const now = Math.floor(Date.now() / 1000);
      const expirationTime = this.parseExpirationTime(this.expiresIn);

      const payload: JWTPayload = {
        id: user.id,
        userId: user.id,
        email: user.email,
        roles: user.roles?.map((role) => role.name) || [],
        iat: now,
        exp: now + expirationTime,
      };

      // Implementar JWT usando Web Crypto API nativo
      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      const signature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating JWT token:", error);
      throw new Error(ServiceErrors.TOKEN_GEN_FAILED);
    }
  }

  /**
   * Generate token with custom payload (for OAuth 2.0)
   * @param payload Custom payload for token
   * @returns Token JWT
   */
  async generateTokenWithPayload(payload: any): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const expirationTime = this.parseExpirationTime(this.expiresIn);

      const fullPayload = {
        ...payload,
        iat: now,
        exp: payload.exp || now + expirationTime,
        iss: payload.iss || this.issuer,
        aud: payload.aud || this.audience,
      };

      // Implementar JWT usando Web Crypto API nativo
      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(fullPayload));

      const signature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating JWT token:", error);
      throw new Error(ServiceErrors.TOKEN_GEN_FAILED);
    }
  }

  /**
   * Generate ID token for OpenID Connect
   * @param user User for which to generate ID token
   * @param nonce Nonce from the authorization request
   * @param clientId Client ID
   * @returns ID token JWT
   */
  async generateIdToken(
    user: User,
    nonce?: string,
    clientId?: string,
  ): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const expirationTime = this.parseExpirationTime(this.expiresIn);

      const payload = {
        iss: this.issuer,
        sub: user.id,
        aud: clientId || this.audience,
        exp: now + expirationTime,
        iat: now,
        auth_time: now,
        nonce: nonce,
        name: `${user.first_name || ""} ${user.last_name || ""}`.trim(),
        email: user.email,
        email_verified: true, // In a real implementation, check if email is verified
        picture: (user as any).avatar_url || undefined,
      };

      // Implementar JWT usando Web Crypto API nativo
      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      const signature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating ID token:", error);
      throw new Error(ServiceErrors.ID_TOKEN_GEN_FAILED);
    }
  }

  /**
   * Verify DPoP proof header
   * @param dpopProof DPoP proof header
   * @param httpMethod HTTP method
   * @param httpUri HTTP URI
   * @returns Verification result
   */
  async verifyDPoPProof(
    dpopProof: string,
    httpMethod: string,
    httpUri: string,
  ): Promise<{
    valid: boolean;
    payload?: any;
    error?: string;
    jti?: string;
  }> {
    try {
      const parts = dpopProof.split(".");
      if (parts.length !== 3) {
        return { valid: false, error: ServiceErrors.DPOP_INVALID_FORMAT };
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const header = JSON.parse(this.base64UrlDecode(encodedHeader));
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));

      // Verify required fields
      if (!payload.htu || !payload.htm || !payload.iat || !payload.jti) {
        return { valid: false, error: ServiceErrors.DPOP_MISSING_FIELDS };
      }

      // Verify HTTP method and URI match
      if (payload.htm !== httpMethod.toUpperCase()) {
        return { valid: false, error: ServiceErrors.DPOP_METHOD_MISMATCH };
      }

      if (payload.htu !== httpUri) {
        return { valid: false, error: ServiceErrors.DPOP_URI_MISMATCH };
      }

      // Verify timestamp (should be recent, within 5 minutes)
      const now = Math.floor(Date.now() / 1000);
      const maxAge = 300; // 5 minutes
      if (payload.iat < now - maxAge || payload.iat > now + maxAge) {
        return { valid: false, error: ServiceErrors.DPOP_TIMESTAMP_RANGE };
      }

      // Check for replay attacks using JTI (JWT ID)
      if (this.dpopNonceCache.has(payload.jti)) {
        const cachedTime = this.dpopNonceCache.get(payload.jti)!;
        if (now - cachedTime < maxAge) {
          return { valid: false, error: ServiceErrors.DPOP_REPLAY_DETECTED };
        }
      }

      // Cache the JTI to prevent replay
      this.dpopNonceCache.set(payload.jti, now);

      // Clean up old entries from cache
      for (const [jti, time] of this.dpopNonceCache.entries()) {
        if (now - time > maxAge * 2) {
          this.dpopNonceCache.delete(jti);
        }
      }

      // Verify signature
      const expectedSignature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );
      if (signature !== expectedSignature) {
        return { valid: false, error: ServiceErrors.DPOP_INVALID_SIGNATURE };
      }

      return { valid: true, payload, jti: payload.jti };
    } catch (error: any) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Verifica y decodifica un token JWT
   * @param token Token JWT a verificar
   * @returns Payload del token si es válido
   * @throws Error si el token es inválido
   */
  async verifyToken(token: string): Promise<JWTPayload> {
    return Promise.resolve()
      .then(async () => {
        if (!token) {
          throw new Error(ServiceErrors.TOKEN_REQUIRED);
        }

        const parts = token.split(".");
        if (parts.length !== 3) {
          throw new Error(ServiceErrors.INVALID_TOKEN_FORMAT);
        }

        const [encodedHeader, encodedPayload, signature] = parts;

        // Verificar la firma
        const expectedSignature = await this.createSignature(
          `${encodedHeader}.${encodedPayload}`,
        );
        if (signature !== expectedSignature) {
          throw new Error(ServiceErrors.INVALID_TOKEN_SIGNATURE);
        }

        // Decodificar el payload con manejo de errores mejorado
        let payload: JWTPayload;
        try {
          const decodedPayload = this.base64UrlDecode(encodedPayload);
          payload = JSON.parse(decodedPayload);
        } catch (parseError) {
          throw new Error(ServiceErrors.INVALID_TOKEN_PAYLOAD);
        }

        // Verificar expiración
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
          console.log("Token expired check:", {
            now,
            payloadExp: payload.exp,
            timeDiff: now - payload.exp,
            isExpired: payload.exp < now,
          });
          throw new Error(ServiceErrors.TOKEN_EXPIRED);
        }

        return payload;
      })
      .catch((error: any) => {
        throw new Error(`Invalid token: ${error.message}`);
      });
  }

  /**
   * Extrae el token del header Authorization
   * @param authHeader Header de autorización
   * @returns Token JWT o null si no se encuentra
   */
  extractTokenFromHeader(authHeader: string): string | null {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.trim().split(" ");
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
      return null;
    }

    return parts[1];
  }

  /**
   * Verifica si un token está expirado sin verificar la firma
   * @param token Token JWT
   * @returns true si está expirado
   */
  isTokenExpired(token: string): boolean {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return true;
      }

      const decodedPayload = this.base64UrlDecode(parts[1]);
      const payload: JWTPayload = JSON.parse(decodedPayload);
      const now = Math.floor(Date.now() / 1000);

      return payload.exp ? payload.exp < now : false;
    } catch (error: any) {
      // Si hay cualquier error de decodificación o parsing, consideramos el token como expirado
      return true;
    }
  }

  /**
   * Obtiene el tiempo restante de un token en segundos
   * @param token Token JWT
   * @returns Segundos restantes o 0 si está expirado
   */
  getTokenRemainingTime(token: string): number {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return 0;
      }

      const payload: JWTPayload = JSON.parse(this.base64UrlDecode(parts[1]));
      const now = Math.floor(Date.now() / 1000);

      if (!payload.exp) {
        return Infinity;
      }

      const remaining = payload.exp - now;
      return Math.max(0, remaining);
    } catch (error: any) {
      return 0;
    }
  }

  /**
   * Refresca un token si está próximo a expirar
   * @param token Token actual
   * @param user Usuario asociado al token
   * @param refreshThreshold Umbral en segundos para refrescar (default: 1 hora)
   * @returns Nuevo token o el mismo si no necesita refresh
   */
  async refreshTokenIfNeeded(
    token: string,
    user: User,
    refreshThreshold: number = 3600,
  ): Promise<string> {
    const remainingTime = this.getTokenRemainingTime(token);

    if (remainingTime <= refreshThreshold) {
      return await this.generateToken(user);
    }

    return token;
  }

  /**
   * Rotate refresh token with security checks
   * @param oldRefreshToken Old refresh token
   * @param user User associated with the token
   * @returns New refresh token
   */
  async rotateRefreshToken(
    oldRefreshToken: string,
    user: User,
  ): Promise<string> {
    try {
      // Verify old refresh token
      const oldPayload = await this.verifyRefreshToken(oldRefreshToken);

      // Generate new refresh token with shorter lifetime for security
      const now = Math.floor(Date.now() / 1000);
      const newExpirationTime = Math.min(
        this.parseExpirationTime("7d"),
        (oldPayload as any).exp - now,
      );

      const newPayload = {
        userId: user.id,
        type: "refresh",
        iat: now,
        exp: now + newExpirationTime,
        rotatedFrom: oldRefreshToken, // Track rotation for security
      };

      // Usar la misma estructura JWT estándar (header.payload.signature)
      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(newPayload));

      const signature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error rotating refresh token:", error);
      throw new Error(ServiceErrors.REFRESH_TOKEN_ROTATE_FAILED);
    }
  }

  /**
   * Verify refresh token with additional security checks
   * @param refreshToken Refresh token to verify
   * @returns User ID if valid
   */
  async verifyRefreshTokenWithSecurity(refreshToken: string): Promise<any> {
    try {
      if (!refreshToken) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_REQUIRED);
      }

      const parts = refreshToken.split(".");
      if (parts.length !== 3) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_FORMAT);
      }

      const [encodedHeader, encodedPayload, signature] = parts;

      // Verificar la firma usando la misma lógica que el JWT normal
      const expectedSignature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );
      if (signature !== expectedSignature) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_SIGNATURE);
      }

      // Decodificar y validar el payload con manejo de errores mejorado
      let payload;
      try {
        const decodedPayload = this.base64UrlDecode(encodedPayload);
        payload = JSON.parse(decodedPayload);
      } catch (parseError) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_PAYLOAD);
      }

      // Verificar que sea un token de refresh
      if (payload.type !== "refresh") {
        throw new Error(ServiceErrors.INVALID_TOKEN_TYPE);
      }

      // Verificar expiración
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_EXPIRED);
      }

      // Verificar que tenga userId
      if (!payload.userId) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_MISSING_USER);
      }

      return payload;
    } catch (error: any) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }

  /**
   * Codifica en Base64 URL-safe
   * @param str String a codificar
   * @returns String codificado
   */
  private base64UrlEncode(str: string): string {
    const base64 = Buffer.from(str).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  /**
   * Decodifica de Base64 URL-safe
   * @param str String a decodificar
   * @returns String decodificado
   */
  private base64UrlDecode(str: string): string {
    // Agregar padding si es necesario
    let padded = str;
    while (padded.length % 4) {
      padded += "=";
    }

    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");

    return Buffer.from(base64, "base64").toString("utf-8");
  }

  /**
   * Crea una firma HMAC SHA-256
   * @param data Datos a firmar
   * @returns Firma en base64 URL-safe
   */
  private async createSignature(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    const messageData = encoder.encode(data);

    // Importar la clave
    const key = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    // Crear la firma
    const signature = await crypto.subtle.sign("HMAC", key, messageData);
    const signatureArray = new Uint8Array(signature);

    // Convertir a base64 URL-safe
    const base64 = Buffer.from(signatureArray).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  /**
   * Parsea el tiempo de expiración a segundos
   * @param expiresIn String de tiempo (ej: '24h', '7d', '30m')
   * @returns Segundos
   */
  private parseExpirationTime(expiresIn: string): number {
    const units: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
      w: 604800,
      ms: 0.001, // Add milliseconds support
    };

    const match = expiresIn.match(/^(-?\d+)([smhdw]|ms)$/);
    if (!match) {
      throw new Error(`Invalid expiration format: ${expiresIn}`);
    }

    const [, value, unit] = match;
    const multiplier = units[unit];

    if (!multiplier) {
      throw new Error(`Invalid time unit: ${unit}`);
    }

    return parseFloat(value) * multiplier;
  }

  /**
   * Genera un token de refresh
   * @param userId ID del usuario
   * @returns Token de refresh
   */
  async generateRefreshToken(userId: string | number): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);

      const payload = {
        userId,
        type: "refresh",
        iat: now,
        exp: now + 30 * 24 * 60 * 60, // 30 días
      };

      console.log("Generating refresh token with payload:", {
        now,
        exp: payload.exp,
        userId,
      });

      // Usar la misma estructura JWT estándar (header.payload.signature)
      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      const signature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating refresh token:", error);
      throw new Error(ServiceErrors.REFRESH_TOKEN_GEN_FAILED);
    }
  }

  /**
   * Verifica un token de refresh
   * @param refreshToken Token de refresh
   * @returns User ID si es válido
   */
  async verifyRefreshToken(refreshToken: string): Promise<string | number> {
    try {
      if (!refreshToken) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_REQUIRED);
      }

      const parts = refreshToken.split(".");
      if (parts.length !== 3) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_FORMAT);
      }

      const [encodedHeader, encodedPayload, signature] = parts;

      // Verificar la firma usando la misma lógica que el JWT normal
      const expectedSignature = await this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
      );
      if (signature !== expectedSignature) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_SIGNATURE);
      }

      // Decodificar y validar el payload con manejo de errores mejorado
      let payload;
      try {
        const decodedPayload = this.base64UrlDecode(encodedPayload);
        payload = JSON.parse(decodedPayload);
      } catch (parseError) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_PAYLOAD);
      }

      // Verificar que sea un token de refresh
      if (payload.type !== "refresh") {
        throw new Error(ServiceErrors.INVALID_TOKEN_TYPE);
      }

      // Verificar expiración
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        console.log("Refresh token expired:", {
          now,
          payloadExp: payload.exp,
          timeDiff: now - payload.exp,
          isExpired: payload.exp < now,
        });
        throw new Error(ServiceErrors.REFRESH_TOKEN_EXPIRED);
      }

      // Verificar que tenga userId
      if (!payload.userId) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_MISSING_USER);
      }

      return payload.userId;
    } catch (error: any) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }
}

/**
 * Instancia singleton del servicio JWT
 */
let jwtServiceInstance: JWTService | null = null;

/**
 * Inicializa el servicio JWT
 * @param secret Secreto para firmar tokens
 * @param expiresIn Tiempo de expiración
 * @returns Instancia del servicio JWT
 */
export function initJWTService(secret: string, expiresIn?: string): JWTService {
  jwtServiceInstance = new JWTService(secret, expiresIn);
  return jwtServiceInstance;
}

/**
 * Obtiene la instancia del servicio JWT
 * @returns Instancia del servicio JWT
 * @throws Error si no ha sido inicializado
 */
export function getJWTService(): JWTService {
  if (!jwtServiceInstance) {
    throw new Error(
      "JWT Service not initialized. Call initJWTService() first.",
    );
  }
  return jwtServiceInstance;
}
