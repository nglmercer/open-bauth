// src/services/security.ts

import { createHash, randomBytes, createHmac } from "crypto";
import type {
  PKCEChallenge,
  DPoPProof,
  SecurityChallenge,
  ChallengeType,
} from "../types/oauth";
import { PKCEMethod } from "../types/oauth";

/**
 * Security Service for handling OAuth 2.0 security features
 * PKCE, DPoP, state/nonce management, and security challenges
 */
export class SecurityService {
  private readonly CHALLENGE_EXPIRY_MINUTES = 10;
  private readonly STATE_LENGTH = 32;
  private readonly NONCE_LENGTH = 32;
  private readonly CODE_VERIFIER_LENGTH = 128;
  private readonly CODE_CHALLENGE_LENGTH = 128;

  /**
   * Generate a PKCE (Proof Key for Code Exchange) challenge
   * RFC 7636 implementation
   */
  generatePKCEChallenge(method: PKCEMethod = PKCEMethod.S256): PKCEChallenge {
    const codeVerifier = this.generateRandomString(this.CODE_VERIFIER_LENGTH);
    let codeChallenge: string;

    if (method === PKCEMethod.S256) {
      codeChallenge = this.base64UrlEncode(
        createHash("sha256").update(codeVerifier).digest()
      );
    } else {
      codeChallenge = codeVerifier;
    }

    return {
      code_challenge: codeChallenge,
      code_challenge_method: method,
      code_verifier: codeVerifier,
    };
  }

  /**
   * Verify a PKCE code verifier against the challenge
   */
  verifyPKCEChallenge(
    codeVerifier: string,
    codeChallenge: string,
    method: PKCEMethod
  ): boolean {
    let expectedChallenge: string;

    if (method === PKCEMethod.S256) {
      expectedChallenge = this.base64UrlEncode(
        createHash("sha256").update(codeVerifier).digest()
      );
    } else {
      expectedChallenge = codeVerifier;
    }

    return expectedChallenge === codeChallenge;
  }

  /**
   * Generate a cryptographically secure random string
   */
  generateRandomString(length: number): string {
    return randomBytes(length).toString("base64url");
  }

  /**
   * Generate a state parameter for OAuth 2.0 authorization requests
   */
  generateState(): string {
    return this.generateRandomString(this.STATE_LENGTH);
  }

  /**
   * Generate a nonce parameter for OpenID Connect
   */
  generateNonce(): string {
    return this.generateRandomString(this.NONCE_LENGTH);
  }

  /**
   * Generate a DPoP (Demonstrating Proof of Possession) proof header
   * RFC 9449 implementation
   */
  async generateDPoPProof(
    httpMethod: string,
    httpUri: string,
    privateKey: CryptoKey,
    jkt?: string
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jti = this.generateRandomString(16);

    const payload = {
      htu: httpUri,
      htm: httpMethod.toUpperCase(),
      jkt: jkt,
      iat: now,
      jti: jti,
    };

    // Create JWT header
    const header = {
      alg: "ES256", // Default to ES256, should be configurable
      typ: "dpop+jwt",
      jwk: await this.cryptoKeyToJWK(privateKey),
    };

    // Create JWT
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

    const signature = await this.signJWT(
      `${encodedHeader}.${encodedPayload}`,
      privateKey
    );

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Verify a DPoP proof header
   */
  async verifyDPoPProof(
    dpopProof: string,
    httpMethod: string,
    httpUri: string,
    publicKey?: CryptoKey
  ): Promise<{
    valid: boolean;
    payload?: DPoPProof;
    error?: string;
  }> {
    try {
      const parts = dpopProof.split(".");
      if (parts.length !== 3) {
        return { valid: false, error: "Invalid DPoP proof format" };
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const header = JSON.parse(this.base64UrlDecode(encodedHeader));
      const payload: DPoPProof = JSON.parse(this.base64UrlDecode(encodedPayload));

      // Verify required fields
      if (!payload.htu || !payload.htm || !payload.iat || !payload.jti) {
        return { valid: false, error: "Missing required DPoP fields" };
      }

      // Verify HTTP method and URI match
      if (payload.htm !== httpMethod.toUpperCase()) {
        return { valid: false, error: "HTTP method mismatch" };
      }

      if (payload.htu !== httpUri) {
        return { valid: false, error: "HTTP URI mismatch" };
      }

      // Verify timestamp (should be recent, within 5 minutes)
      const now = Math.floor(Date.now() / 1000);
      const maxAge = 300; // 5 minutes
      if (payload.iat < now - maxAge || payload.iat > now + maxAge) {
        return { valid: false, error: "DPoP proof timestamp out of range" };
      }

      // Verify signature if public key is provided
      if (publicKey) {
        const isValid = await this.verifyJWTSignature(
          `${encodedHeader}.${encodedPayload}`,
          signature,
          publicKey
        );

        if (!isValid) {
          return { valid: false, error: "Invalid DPoP signature" };
        }
      }

      return { valid: true, payload };
    } catch (error: any) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Create a security challenge
   */
  createChallenge(
    type: ChallengeType,
    data: any,
    expiresInMinutes: number = this.CHALLENGE_EXPIRY_MINUTES
  ): Omit<SecurityChallenge, "id" | "created_at"> {
    const challengeId = this.generateRandomString(32);
    const expiresAt = new Date(
      Date.now() + expiresInMinutes * 60 * 1000
    ).toISOString();

    return {
      challenge_id: challengeId,
      challenge_type: type,
      challenge_data: JSON.stringify(data),
      expires_at: expiresAt,
      is_solved: false,
    };
  }

  /**
   * Verify a security challenge solution
   */
  verifyChallenge(
    challenge: SecurityChallenge,
    solution: any
  ): { valid: boolean; error?: string } {
    // Check if challenge is expired
    if (new Date() > new Date(challenge.expires_at)) {
      return { valid: false, error: "Challenge has expired" };
    }

    // Check if challenge is already solved
    if (challenge.is_solved) {
      return { valid: false, error: "Challenge has already been solved" };
    }

    // Verify solution based on challenge type
    try {
      const challengeData = JSON.parse(challenge.challenge_data);
      
      switch (challenge.challenge_type) {
        case "captcha":
          return this.verifyCaptchaChallenge(challengeData, solution);
        case "biometric":
          return this.verifyBiometricChallenge(challengeData, solution);
        case "device_verification":
          return this.verifyDeviceChallenge(challengeData, solution);
        case "email_verification":
          return this.verifyEmailChallenge(challengeData, solution);
        case "sms_verification":
          return this.verifySMSChallenge(challengeData, solution);
        case "mfa":
          return this.verifyMFAChallenge(challengeData, solution);
        default:
          return { valid: false, error: "Unknown challenge type" };
      }
    } catch (error: any) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Generate a secure random token
   */
  generateSecureToken(length: number = 32): string {
    return randomBytes(length).toString("hex");
  }

  /**
   * Hash a password using a secure algorithm
   */
  async hashPassword(password: string, salt?: string): Promise<{
    hash: string;
    salt: string;
  }> {
    const passwordSalt = salt || randomBytes(32).toString("hex");
    const hash = createHmac("sha512", passwordSalt)
      .update(password)
      .digest("hex");
    
    return { hash, salt: passwordSalt };
  }

  /**
   * Verify a password against its hash
   */
  async verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
    const { hash: computedHash } = await this.hashPassword(password, salt);
    return computedHash === hash;
  }

  /**
   * Encrypt sensitive data
   */
  async encrypt(data: string, key: string): Promise<string> {
    const iv = randomBytes(16);
    // Ensure we have a 32-byte key for AES-256
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
    const finalKey = keyBuffer.length < 32 ?
      Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)]) :
      keyBuffer.slice(0, 32);
    
    const cipher = require("crypto").createCipheriv("aes-256-gcm", finalKey, iv);
    cipher.setAAD(Buffer.from("additional-data"));
    
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    
    const authTag = cipher.getAuthTag();
    return iv.toString("hex") + ":" + authTag.toString("hex") + ":" + encrypted;
  }

  /**
   * Decrypt sensitive data
   */
  async decrypt(encryptedData: string, key: string): Promise<string> {
    const parts = encryptedData.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }
    
    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const encrypted = parts[2];
    
    // Ensure we have a 32-byte key for AES-256
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
    const finalKey = keyBuffer.length < 32 ?
      Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)]) :
      keyBuffer.slice(0, 32);
    
    const decipher = require("crypto").createDecipheriv("aes-256-gcm", finalKey, iv);
    decipher.setAAD(Buffer.from("additional-data"));
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    
    return decrypted;
  }

  /**
   * Base64 URL-safe encoding
   */
  private base64UrlEncode(data: string | Buffer): string {
    const base64 = Buffer.isBuffer(data) 
      ? data.toString("base64")
      : Buffer.from(data).toString("base64");
    
    return base64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  /**
   * Base64 URL-safe decoding
   */
  private base64UrlDecode(data: string): string {
    // Add padding if needed
    let padded = data;
    while (padded.length % 4) {
      padded += "=";
    }
    
    const base64 = padded
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    
    return Buffer.from(base64, "base64").toString("utf8");
  }

  /**
   * Convert CryptoKey to JWK format
   */
  private async cryptoKeyToJWK(privateKey: CryptoKey): Promise<any> {
    return await crypto.subtle.exportKey("jwk", privateKey);
  }

  /**
   * Sign JWT with private key
   */
  private async signJWT(data: string, privateKey: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      encoder.encode(data)
    );
    
    return this.base64UrlEncode(Buffer.from(signature));
  }

  /**
   * Verify JWT signature with public key
   */
  private async verifyJWTSignature(
    data: string,
    signature: string,
    publicKey: CryptoKey
  ): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const signatureBuffer = Buffer.from(this.base64UrlDecode(signature), "base64");
      
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signatureBuffer,
        encoder.encode(data)
      );
      
      return isValid;
    } catch (error) {
      return false;
    }
  }

  /**
   * Challenge verification methods
   */
  private verifyCaptchaChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    // Implementation would depend on the captcha service used
    // This is a placeholder for demonstration
    if (!solution || typeof solution !== "string") {
      return { valid: false, error: "Invalid captcha solution" };
    }
    
    // In a real implementation, you would verify with the captcha service
    return { valid: true };
  }

  private verifyBiometricChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    // Implementation would depend on the biometric service used
    // This is a placeholder for demonstration
    if (!solution || !solution.biometricData) {
      return { valid: false, error: "Invalid biometric data" };
    }
    
    // In a real implementation, you would verify the biometric data
    return { valid: true };
  }

  private verifyDeviceChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    // Implementation would verify device signature or certificate
    if (!solution || !solution.deviceSignature) {
      return { valid: false, error: "Invalid device signature" };
    }
    
    // In a real implementation, you would verify the device signature
    return { valid: true };
  }

  private verifyEmailChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    if (!solution || !solution.code) {
      return { valid: false, error: "Invalid verification code" };
    }
    
    if (solution.code !== challengeData.expectedCode) {
      return { valid: false, error: "Incorrect verification code" };
    }
    
    return { valid: true };
  }

  private verifySMSChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    if (!solution || !solution.code) {
      return { valid: false, error: "Invalid verification code" };
    }
    
    if (solution.code !== challengeData.expectedCode) {
      return { valid: false, error: "Incorrect verification code" };
    }
    
    return { valid: true };
  }

  private verifyMFAChallenge(challengeData: any, solution: any): { valid: boolean; error?: string } {
    if (!solution || !solution.token) {
      return { valid: false, error: "Invalid MFA token" };
    }
    
    // In a real implementation, you would verify the TOTP token
    // This is a placeholder for demonstration
    return { valid: true };
  }
}

// Create cipher and decipher functions (Node.js crypto compatibility)
// Note: createCipher/createDecipher are deprecated, using createCipheriv/createDecipheriv instead