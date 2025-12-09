// src/services/jwt-bun.ts
// Versión optimizada usando Bun.CryptoHasher para mejor rendimiento

import type { JWTPayload, User } from "../types/auth";
import type { OAuthJWTPayload } from "../types/oauth";
import type { IJWTServiceExtended } from "../types/jwt-service";
import { ServiceErrors } from "./constants";

/**
 * JWT with Bun.CryptoHasher
 */
export class JWTServiceBun implements IJWTServiceExtended {
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
   * Generate a JWT token for a user (optimized version)
   */
  async generateToken(user: User): Promise<string> {
    if (!user || !user.id || !user.email) {
      throw new Error(ServiceErrors.INVALID_USER_OBJECT);
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

      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      // Usar Bun.CryptoHasher para mejor rendimiento
      const signature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating JWT token:", error);
      throw new Error(ServiceErrors.TOKEN_GEN_FAILED);
    }
  }

  /**
   * Generate token with custom payload (optimized version)
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

      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(fullPayload));

      const signature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating JWT token:", error);
      throw new Error(ServiceErrors.TOKEN_GEN_FAILED);
    }
  }

  /**
   * Generate ID token for OpenID Connect (optimized version)
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
        email_verified: true,
        picture: (user as any).avatar_url || undefined,
      };

      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      const signature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating ID token:", error);
      throw new Error(ServiceErrors.ID_TOKEN_GEN_FAILED);
    }
  }

  /**
   * Verify and decode a JWT token (optimized version)
   */
  async verifyToken(token: string): Promise<JWTPayload> {
    try {
      if (!token) {
        throw new Error(ServiceErrors.TOKEN_REQUIRED);
      }

      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error(ServiceErrors.INVALID_TOKEN_FORMAT);
      }

      const [encodedHeader, encodedPayload, signature] = parts;

      // Verificar la firma con Bun.CryptoHasher
      const expectedSignature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );
      if (signature !== expectedSignature) {
        throw new Error(ServiceErrors.INVALID_TOKEN_SIGNATURE);
      }

      // Decodificar el payload
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
        throw new Error(ServiceErrors.TOKEN_EXPIRED);
      }

      return payload;
    } catch (error: any) {
      throw new Error(`Invalid token: ${error.message}`);
    }
  }

  /**
   * Create a HMAC SHA-256 signature using Bun.CryptoHasher
   */
  private createSignatureBun(data: string): string {
    const hasher = new Bun.CryptoHasher("sha256", this.secret);
    hasher.update(data);
    const signature = hasher.digest("base64");
    return signature.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  /**
   * Base64 URL-safe encoding
   */
  private base64UrlEncode(str: string): string {
    const base64 = Buffer.from(str).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  /**
   * Base64 URL-safe decoding
   */
  private base64UrlDecode(str: string): string {
    let padded = str;
    while (padded.length % 4) {
      padded += "=";
    }

    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(base64, "base64").toString("utf-8");
  }

  /**
   * Parse expiration time to seconds
   */
  private parseExpirationTime(expiresIn: string): number {
    const units: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
      w: 604800,
      ms: 0.001,
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

  // Métodos adicionales para compatibilidad
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
      return true;
    }
  }

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
   * Verify DPoP proof header (Optimized for Bun)
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
      
      // Decodificación directa
      let header, payload;
      try {
        header = JSON.parse(this.base64UrlDecode(encodedHeader));
        payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      } catch (e) {
         return { valid: false, error: ServiceErrors.INVALID_TOKEN_PAYLOAD };
      }

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

      // Verify signature using Bun.CryptoHasher (Síncrono, no requiere await)
      const expectedSignature = this.createSignatureBun(
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
   * Refresca un token si está próximo a expirar
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
   * Genera un token de refresh (Optimized for Bun)
   */
  async generateRefreshToken(userId: string | number): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);

      const payload = {
        userId,
        type: "refresh",
        iat: now,
        exp: now + 30 * 24 * 60 * 60, // 30 días fijo
      };

      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

      // Bun.CryptoHasher es síncrono
      const signature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error generating refresh token:", error);
      throw new Error(ServiceErrors.REFRESH_TOKEN_GEN_FAILED);
    }
  }

  /**
   * Verifica un token de refresh (Optimized for Bun)
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

      // Verificación síncrona con Bun
      const expectedSignature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );
      
      if (signature !== expectedSignature) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_SIGNATURE);
      }

      let payload;
      try {
        const decodedPayload = this.base64UrlDecode(encodedPayload);
        payload = JSON.parse(decodedPayload);
      } catch (parseError) {
        throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_PAYLOAD);
      }

      if (payload.type !== "refresh") {
        throw new Error(ServiceErrors.INVALID_TOKEN_TYPE);
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_EXPIRED);
      }

      if (!payload.userId) {
        throw new Error(ServiceErrors.REFRESH_TOKEN_MISSING_USER);
      }

      return payload.userId;
    } catch (error: any) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }

  /**
   * Verify refresh token with additional security checks
   */
  async verifyRefreshTokenWithSecurity(refreshToken: string): Promise<any> {
    // Reutilizamos la lógica base pero retornamos el payload completo
    // Nota: Podrías refactorizar verifyRefreshToken para llamar a este método
    try {
       // ... Validaciones básicas igual que verifyRefreshToken ...
       // Para no repetir código excesivo aquí, asumo que copias la lógica de validación
       // de firma y estructura de verifyRefreshToken, o extraes un método privado `validateJwtSignature`.
       
       // Validación rápida re-implementada para completitud:
       if (!refreshToken) throw new Error(ServiceErrors.REFRESH_TOKEN_REQUIRED);
       const parts = refreshToken.split(".");
       if (parts.length !== 3) throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_FORMAT);
       const [encodedHeader, encodedPayload, signature] = parts;
       
       const expectedSignature = this.createSignatureBun(`${encodedHeader}.${encodedPayload}`);
       if (signature !== expectedSignature) throw new Error(ServiceErrors.INVALID_REFRESH_TOKEN_SIGNATURE);
       
       const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
       
       if (payload.type !== "refresh") throw new Error(ServiceErrors.INVALID_TOKEN_TYPE);
       const now = Math.floor(Date.now() / 1000);
       if (payload.exp && payload.exp < now) throw new Error(ServiceErrors.REFRESH_TOKEN_EXPIRED);
       if (!payload.userId) throw new Error(ServiceErrors.REFRESH_TOKEN_MISSING_USER);

       return payload;
    } catch (error: any) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }

  /**
   * Rotate refresh token with security checks (Optimized for Bun)
   */
  async rotateRefreshToken(
    oldRefreshToken: string,
    user: User,
  ): Promise<string> {
    try {
      // Verify old refresh token
      const oldPayload = await this.verifyRefreshTokenWithSecurity(oldRefreshToken);

      const now = Math.floor(Date.now() / 1000);
      // Calcular nueva expiración (menor entre 7 días o lo que le quedaba al anterior)
      const sevenDays = this.parseExpirationTime("7d");
      const remainingOld = (oldPayload as any).exp - now;
      
      const newExpirationTime = Math.min(sevenDays, remainingOld);

      const newPayload = {
        userId: user.id,
        type: "refresh",
        iat: now,
        exp: now + newExpirationTime,
        rotatedFrom: oldRefreshToken, // Track rotation for security
      };

      const header = {
        alg: "HS256",
        typ: "JWT",
      };

      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this.base64UrlEncode(JSON.stringify(newPayload));

      const signature = this.createSignatureBun(
        `${encodedHeader}.${encodedPayload}`,
      );

      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error: any) {
      console.error("Error rotating refresh token:", error);
      throw new Error(ServiceErrors.REFRESH_TOKEN_ROTATE_FAILED);
    }
  }
}

/**
 * Instancia singleton del servicio JWT optimizado
 */
let jwtServiceBunInstance: JWTServiceBun | null = null;

/**
 * Inicializa el servicio JWT optimizado con Bun.CryptoHasher
 */
export function initJWTServiceBun(secret: string, expiresIn?: string): JWTServiceBun {
  jwtServiceBunInstance = new JWTServiceBun(secret, expiresIn);
  return jwtServiceBunInstance;
}

/**
 * Obtiene la instancia del servicio JWT optimizado
 */
export function getJWTServiceBun(): JWTServiceBun {
  if (!jwtServiceBunInstance) {
    throw new Error(
      "JWT Service (Bun) not initialized. Call initJWTServiceBun() first.",
    );
  }
  return jwtServiceBunInstance;
}