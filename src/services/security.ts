// src/services/security.ts

import { randomBytes, scrypt, createCipheriv, createDecipheriv } from "crypto";
import type {
  PKCEChallenge,
  DPoPProof,
  SecurityChallenge,
} from "../types/oauth";
import { PKCEMethod, ChallengeType } from "../types/oauth";
import { TOTPVerifier } from "./verifiers/totp";
import { SecureCodeVerifier } from "./verifiers/code";
import { VerifierMessages } from "./verifiers/constants";
import { BackupCodeVerifier } from "./verifiers/backup-code";

export { PKCEMethod, ChallengeType };
export type { PKCEChallenge, DPoPProof, SecurityChallenge };

/**
 * Result of a challenge verification
 */
export interface ChallengeVerificationResult<T = any> {
  valid: boolean;
  error?: string;
  data?: T;
}

/**
 * Interface for implementing custom security challenge verifiers
 */
export interface ChallengeVerifier<T = any, S = any> {
  verify(challengeData: T, solution: S): Promise<ChallengeVerificationResult> | ChallengeVerificationResult;
}

/**
 * Security Service for handling OAuth 2.0 security features
 * PKCE, DPoP, state/nonce management, and pluggable security challenges.
 * 
 * Supports a flexible challenge-response system using the Strategy pattern.
 * Default verifiers are provided for common types (MFA, Email, SMS),
 * and custom verifiers can be registered for other needs (CAPTCHA, Biometric, etc.).
 */
export class SecurityService {
  private readonly CHALLENGE_EXPIRY_MINUTES = 10;
  private readonly STATE_LENGTH = 32;
  private readonly NONCE_LENGTH = 32;
  private readonly CODE_VERIFIER_LENGTH = 128;
  private readonly CODE_CHALLENGE_LENGTH = 128;

  private verifiers: Map<string, ChallengeVerifier> = new Map();

  constructor() {
    this.registerDefaultVerifiers();
  }

  /**
   * Register a custom challenge verifier.
   * 
   * @param type - The challenge type identifier (e.g., 'biometric', 'captcha', or a ChallengeType enum value)
   * @param verifier - The verifier implementation matching the ChallengeVerifier interface
   * 
   * @example
   * ```typescript
   * securityService.registerVerifier('math_puzzle', {
   *   verify: (data, solution) => {
   *     return { valid: parseInt(solution.answer) === data.expected };
   *   }
   * });
   * ```
   */
  registerVerifier(type: ChallengeType | string, verifier: ChallengeVerifier) {
    this.verifiers.set(type.toString(), verifier);
  }

  /**
   * Register default verifiers for standard challenge types
   */

  private registerDefaultVerifiers() {
    // Real TOTP implementation
    this.registerVerifier(ChallengeType.MFA, new TOTPVerifier());

    // Secure Code implementation for Email/SMS
    // Note: This verifies the CODE, validation of delivery is external
    const codeVerifier = new SecureCodeVerifier();
    this.registerVerifier(ChallengeType.EMAIL_VERIFICATION, codeVerifier);
    this.registerVerifier(ChallengeType.SMS_VERIFICATION, codeVerifier);

    // Backup Code implementation
    this.registerVerifier(ChallengeType.BACKUP_CODE, new BackupCodeVerifier());

    // Placeholders that throw errors to force implementation
    this.registerVerifier(ChallengeType.CAPTCHA, {
      verify: () => ({ valid: false, error: VerifierMessages.CAPTCHA_NOT_CONFIGURED })
    });
    this.registerVerifier(ChallengeType.BIOMETRIC, {
      verify: () => ({ valid: false, error: VerifierMessages.BIOMETRIC_NOT_CONFIGURED })
    });
    this.registerVerifier(ChallengeType.DEVICE_VERIFICATION, {
      verify: () => ({ valid: false, error: VerifierMessages.DEVICE_NOT_CONFIGURED })
    });
  }

  /**
   * Generate a PKCE (Proof Key for Code Exchange) challenge
   * RFC 7636 implementation
   */
  generatePKCEChallenge(method: PKCEMethod = PKCEMethod.S256): PKCEChallenge {
    const codeVerifier = this.generateRandomString(this.CODE_VERIFIER_LENGTH);
    let codeChallenge: string;

    if (method === PKCEMethod.S256) {
      const hasher = new Bun.CryptoHasher("sha256");
      hasher.update(codeVerifier);
      codeChallenge = this.base64UrlEncode(hasher.digest());
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
    method: PKCEMethod,
  ): boolean {
    let expectedChallenge: string;

    if (method === PKCEMethod.S256) {
      const hasher = new Bun.CryptoHasher("sha256");
      hasher.update(codeVerifier);
      expectedChallenge = this.base64UrlEncode(hasher.digest());
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
    jkt?: string,
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
      privateKey,
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
    publicKey?: CryptoKey,
  ): Promise<{
    valid: boolean;
    payload?: DPoPProof;
    error?: string;
  }> {
    try {
      const parts = dpopProof.split(".");
      if (parts.length !== 3) {
        return { valid: false, error: VerifierMessages.DPOP_INVALID_FORMAT };
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const header = JSON.parse(this.base64UrlDecode(encodedHeader).toString("utf8"));
      const payload: DPoPProof = JSON.parse(
        this.base64UrlDecode(encodedPayload).toString("utf8"),
      );

      // Verify required fields
      if (!payload.htu || !payload.htm || !payload.iat || !payload.jti) {
        return { valid: false, error: VerifierMessages.DPOP_MISSING_FIELDS };
      }

      // Verify HTTP method and URI match
      if (payload.htm !== httpMethod.toUpperCase()) {
        return { valid: false, error: VerifierMessages.DPOP_METHOD_MISMATCH };
      }

      if (payload.htu !== httpUri) {
        return { valid: false, error: VerifierMessages.DPOP_URI_MISMATCH };
      }

      // Verify timestamp (should be recent, within 5 minutes)
      const now = Math.floor(Date.now() / 1000);
      const maxAge = 300; // 5 minutes
      if (payload.iat < now - maxAge || payload.iat > now + maxAge) {
        return { valid: false, error: VerifierMessages.DPOP_TIMESTAMP_RANGE };
      }

      // Verify signature if public key is provided
      if (publicKey) {
        const isValid = await this.verifyJWTSignature(
          `${encodedHeader}.${encodedPayload}`,
          signature,
          publicKey,
        );

        if (!isValid) {
          return { valid: false, error: VerifierMessages.DPOP_INVALID_SIGNATURE };
        }
      }

      return { valid: true, payload };
    } catch (error: unknown) {
      return { valid: false, error: (error as Error).message };
    }
  }

  /**
   * Create a security challenge.
   * 
   * @param type - The type of challenge to create (e.g., ChallengeType.MFA)
   * @param data - The data required for the challenge (e.g., secret for TOTP, expected code for Email)
   * @param expiresInMinutes - Duration in minutes before the challenge expires (default: 10)
   * @returns The created challenge object (without ID or timestamps, which are handled by the caller/DB)
   */
  createChallenge(
    type: ChallengeType | string,
    data: any,
    expiresInMinutes: number = this.CHALLENGE_EXPIRY_MINUTES,
  ): Omit<SecurityChallenge, "id" | "created_at" | "updated_at"> {
    const challengeId = this.generateRandomString(32);
    const expiresAt = new Date(
      Date.now() + expiresInMinutes * 60 * 1000,
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
   * Verify a security challenge solution.
   * 
   * Delegates the verification logic to the registered verifier for the challenge's type.
   * 
   * @param challenge - The challenge object to be verified
   * @param solution - The user-provided solution (e.g., code, token, answer)
   * @returns A result object indicating if the solution was valid and any associated data or errors
   */
  async verifyChallenge(
    challenge: SecurityChallenge,
    solution: any,
  ): Promise<ChallengeVerificationResult> {
    // Check if challenge is expired
    if (new Date() > new Date(challenge.expires_at)) {
      return { valid: false, error: VerifierMessages.CHALLENGE_EXPIRED };
    }

    // Check if challenge is already solved
    if (challenge.is_solved) {
      return { valid: false, error: VerifierMessages.CHALLENGE_SOLVED };
    }

    // Verify solution based on challenge type
    try {
      const challengeData = JSON.parse(challenge.challenge_data);
      const handler = this.verifiers.get(challenge.challenge_type.toString());

      if (!handler) {
        return { valid: false, error: `${VerifierMessages.UNKNOWN_TYPE}: ${challenge.challenge_type}` };
      }

      return await handler.verify(challengeData, solution);
    } catch (error: unknown) {
      return { valid: false, error: (error as Error).message };
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
  /**
   * Hash a password using Bun.password (Argon2id default)
   */
  async hashPassword(
    password: string,
    _salt?: string, // Salt is handled internally by Bun.password/Argon2
  ): Promise<{
    hash: string;
    salt: string;
  }> {
    // Bun.password.hash generates a salted hash in PHC string format
    // processing is much heavier and secure than simple HMAC
    const hash = await Bun.password.hash(password);
    return { hash, salt: "" }; // Salt is embedded in the hash string
  }

  /**
   * Verify a password against its hash
   */
  async verifyPassword(
    password: string,
    hash: string,
    salt: string,
  ): Promise<boolean> {
    // Check if it's a PHC string (Argon2 or Bcrypt) supported by Bun
    if (hash.startsWith("$argon2") || hash.startsWith("$2") || hash.startsWith("$scrypt")) {
      return await Bun.password.verify(password, hash);
    }

    // Legacy fallback for HMAC-SHA512 hashes
    // This allows existing hashes to still work while new ones use Argon2
    const passwordSalt = salt;
    const hasher = new Bun.CryptoHasher("sha512", passwordSalt);
    hasher.update(password);
    const computedHash = hasher.digest("hex");

    return computedHash === hash;
  }

  /**
   * Encrypt sensitive data
   */
  async encrypt(data: string, key: string): Promise<string> {
    const iv = randomBytes(16);
    // Ensure we have a 32-byte key for AES-256
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
    const finalKey =
      keyBuffer.length < 32
        ? Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)])
        : keyBuffer.slice(0, 32);

    const cipher = createCipheriv(
      "aes-256-gcm",
      finalKey,
      iv,
    );
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
      throw new Error(VerifierMessages.ENCRYPTION_INVALID_FORMAT);
    }

    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const encrypted = parts[2];

    // Ensure we have a 32-byte key for AES-256
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
    const finalKey =
      keyBuffer.length < 32
        ? Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)])
        : keyBuffer.slice(0, 32);

    const decipher = createDecipheriv(
      "aes-256-gcm",
      finalKey,
      iv,
    );
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

    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  /**
   * Base64 URL-safe decoding
   */
  private base64UrlDecode(data: string): Buffer {
    // Add padding if needed
    let padded = data;
    while (padded.length % 4) {
      padded += "=";
    }

    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");

    return Buffer.from(base64, "base64");
  }

  /**
   * Convert CryptoKey to JWK format
   */
  private async cryptoKeyToJWK(privateKey: CryptoKey): Promise<unknown> {
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
      encoder.encode(data),
    );

    return this.base64UrlEncode(Buffer.from(signature));
  }

  /**
   * Verify JWT signature with public key
   */
  private async verifyJWTSignature(
    data: string,
    signature: string,
    publicKey: CryptoKey,
  ): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const signatureBuffer = this.base64UrlDecode(signature);

      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        new Uint8Array(signatureBuffer),
        encoder.encode(data),
      );

      return isValid;
    } catch (error) {
      return false;
    }
  }

  /**
   * Encrypt data using a password (derives key using scrypt)
   * This replaces the deprecated createCipher by using createCipheriv with a derived key
   */
  async encryptWithPassword(data: string, password: string): Promise<string> {
    const salt = randomBytes(16);

    // Derive key using scrypt (secure key derivation)
    const key = (await new Promise<Buffer>((resolve, reject) => {
      scrypt(password, salt, 32, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey as Buffer);
      });
    })) as Buffer;

    const iv = randomBytes(16);
    const cipher = createCipheriv("aes-256-gcm", key, iv);

    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    // Format: salt:iv:authTag:encryptedData
    return `${salt.toString("hex")}:${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
  }

  /**
   * Decrypt data using a password
   * This replaces the deprecated createDecipher by using createDecipheriv with a derived key
   */
  async decryptWithPassword(encryptedData: string, password: string): Promise<string> {
    const parts = encryptedData.split(":");
    if (parts.length !== 4) {
      throw new Error(VerifierMessages.ENCRYPTION_INVALID_FORMAT);
    }

    const [saltHex, ivHex, authTagHex, encryptedHex] = parts;
    const salt = Buffer.from(saltHex, "hex");
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");

    // Derive same key using scrypt
    const key = (await new Promise<Buffer>((resolve, reject) => {
      scrypt(password, salt, 32, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey as Buffer);
      });
    })) as Buffer;

    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedHex, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }
}
