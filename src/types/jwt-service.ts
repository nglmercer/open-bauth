/**
 * Common interface for JWT services
 * Defines the contract that both JWTService and JWTServiceBun must implement
 */
export interface IJWTService {
  /**
   * Generates a JWT token for a user
   */
  generateToken(user: any): Promise<string>;
  /**
   * Generates a token with custom payload
   */
  generateTokenWithPayload(payload: any): Promise<string>;
  /**
   * Generates an ID token for OpenID Connect
   */
  generateIdToken(user: any, nonce?: string, clientId?: string): Promise<string>;
  /**
   * Verifies and decodes a JWT token
   */
  verifyToken(token: string): Promise<any>;
  /**
   * Extracts the token from the Authorization header
   */
  extractTokenFromHeader(authHeader: string): string | null;
  /**
   * Checks if a token is expired
   */
  isTokenExpired(token: string): boolean;
  /**
   * Gets the remaining time of a token in seconds
   */
  getTokenRemainingTime(token: string): number;
}
/**
 * Extended interface for JWT services with additional capabilities
 * Includes Web Crypto API specific methods
 */
export interface IJWTServiceExtended extends IJWTService {
  /**
   * Verifies a DPoP proof (Demonstration of Proof of Possession)
   */
  verifyDPoPProof?(
    dpopProof: string,
    httpMethod: string,
    httpUri: string,
  ): Promise<{
    valid: boolean;
    payload?: any;
    error?: string;
    jti?: string;
  }>;
  /**
   * Refreshes a token if it's close to expiring
   */
  refreshTokenIfNeeded?(
    token: string,
    user: any,
    refreshThreshold?: number,
  ): Promise<string>;
  /**
   * Rotates a refresh token with security checks
   */
  rotateRefreshToken?(
    oldRefreshToken: string,
    user: any,
  ): Promise<string>;
  /**
   * Verifies a refresh token with additional security checks
   */
  verifyRefreshTokenWithSecurity?(refreshToken: string): Promise<any>;
  /**
   * Generates a refresh token
   */
  generateRefreshToken?(userId: string | number): Promise<string>;
  /**
   * Verifies a refresh token
   */
  verifyRefreshToken?(refreshToken: string): Promise<string | number>;
}
/**
 * Type that represents any JWT service implementation
 */
export type JWTServiceImplementation = IJWTService | IJWTServiceExtended;
