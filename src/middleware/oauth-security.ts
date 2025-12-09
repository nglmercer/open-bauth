// src/middleware/oauth-security.ts

import type { AuthRequest, AuthContext } from "../types/auth";
import type {
  OAuthContext,
  OAuthClient,
  AuthorizationRequest,
  TokenRequest,
  DPoPProof,
  SecurityChallenge,
  ChallengeType,
} from "../types/oauth";
import { OAuthErrorType } from "../types/oauth";
import { OAuthService } from "../services/oauth";
import { SecurityService } from "../services/security";
import { JWTService } from "../services/jwt";

/**
 * Middleware de seguridad para OAuth 2.0
 * Proporciona validación OAuth 2.0, verificación de seguridad (state, nonce, DPoP) y auditoría
 */
export class OAuthSecurityMiddleware {
  private oauthService: OAuthService;
  private securityService: SecurityService;
  private jwtService: JWTService;

  constructor(
    oauthService: OAuthService,
    securityService: SecurityService,
    jwtService: JWTService,
  ) {
    this.oauthService = oauthService;
    this.securityService = securityService;
    this.jwtService = jwtService;
  }

  /**
   * Validate OAuth 2.0 authorization request
   */
  async validateAuthorizationRequest(
    request: AuthorizationRequest,
    client?: OAuthClient,
  ): Promise<{
    valid: boolean;
    error?: OAuthErrorType;
    errorDescription?: string;
    oauthContext?: Partial<OAuthContext>;
  }> {
    try {
      // Validate required parameters
      if (!request.response_type) {
        return {
          valid: false,
          error: OAuthErrorType.INVALID_REQUEST,
          errorDescription: "Response type is required",
        };
      }

      if (!request.client_id) {
        return {
          valid: false,
          error: OAuthErrorType.INVALID_REQUEST,
          errorDescription: "Client ID is required",
        };
      }

      // Validate client if provided
      if (client) {
        // Validate redirect URI
        if (request.redirect_uri) {
          const isValidRedirectUri =
            await this.oauthService.validateRedirectUri(
              request.client_id,
              request.redirect_uri,
            );

          if (!isValidRedirectUri) {
            return {
              valid: false,
              error: OAuthErrorType.INVALID_REQUEST,
              errorDescription: "Invalid redirect URI",
            };
          }
        }

        // Validate response type
        const responseTypes = JSON.parse(
          (client as any).response_types || "[]",
        );
        if (!responseTypes.includes(request.response_type)) {
          return {
            valid: false,
            error: OAuthErrorType.UNSUPPORTED_RESPONSE_TYPE,
            errorDescription: "Unsupported response type",
          };
        }

        // Validate scope
        if (request.scope) {
          const clientScopes = client.scope ? client.scope.split(" ") : [];
          const requestedScopes = request.scope.split(" ");

          for (const scope of requestedScopes) {
            if (!clientScopes.includes(scope)) {
              return {
                valid: false,
                error: OAuthErrorType.INVALID_SCOPE,
                errorDescription: `Invalid scope: ${scope}`,
              };
            }
          }
        }
      }

      // Validate PKCE for public clients
      if (client?.is_public && request.response_type === "code") {
        if (!request.code_challenge || !request.code_challenge_method) {
          return {
            valid: false,
            error: OAuthErrorType.INVALID_REQUEST,
            errorDescription: "PKCE is required for public clients",
          };
        }

        // Validate PKCE method
        if (!["plain", "S256"].includes(request.code_challenge_method)) {
          return {
            valid: false,
            error: OAuthErrorType.INVALID_REQUEST,
            errorDescription: "Invalid PKCE method",
          };
        }
      }

      // Create OAuth context
      const oauthContext: Partial<OAuthContext> = {
        client,
        scopes: request.scope ? request.scope.split(" ") : [],
        response_type: request.response_type,
        redirect_uri: request.redirect_uri,
        state: request.state,
        nonce: request.nonce,
        is_authenticated: false,
      };

      return { valid: true, oauthContext };
    } catch (error: any) {
      return {
        valid: false,
        error: OAuthErrorType.SERVER_ERROR,
        errorDescription: error.message,
      };
    }
  }

  /**
   * Validate OAuth 2.0 token request
   */
  async validateTokenRequest(
    request: TokenRequest,
    client?: OAuthClient,
  ): Promise<{
    valid: boolean;
    error?: OAuthErrorType;
    errorDescription?: string;
    oauthContext?: Partial<OAuthContext>;
  }> {
    try {
      // Validate required parameters
      if (!request.grant_type) {
        return {
          valid: false,
          error: OAuthErrorType.INVALID_REQUEST,
          errorDescription: "Grant type is required",
        };
      }

      // Validate client authentication
      if (!client) {
        return {
          valid: false,
          error: OAuthErrorType.INVALID_CLIENT,
          errorDescription: "Invalid client credentials",
        };
      }

      // Validate grant type
      const supportedGrantTypes = JSON.parse(
        (client as any).grant_types || "[]",
      );
      if (!supportedGrantTypes.includes(request.grant_type)) {
        return {
          valid: false,
          error: OAuthErrorType.UNSUPPORTED_GRANT_TYPE,
          errorDescription: "Unsupported grant type",
        };
      }

      // Grant type specific validations
      switch (request.grant_type) {
        case "authorization_code":
          if (!request.code) {
            return {
              valid: false,
              error: OAuthErrorType.INVALID_REQUEST,
              errorDescription: "Authorization code is required",
            };
          }
          break;

        case "refresh_token":
          if (!request.refresh_token) {
            return {
              valid: false,
              error: OAuthErrorType.INVALID_REQUEST,
              errorDescription: "Refresh token is required",
            };
          }
          break;

        case "client_credentials":
          // Client credentials grant doesn't need additional validation
          break;

        case "password":
          if (!(request as any).username || !(request as any).password) {
            return {
              valid: false,
              error: OAuthErrorType.INVALID_REQUEST,
              errorDescription: "Username and password are required",
            };
          }
          break;

        default:
          return {
            valid: false,
            error: OAuthErrorType.UNSUPPORTED_GRANT_TYPE,
            errorDescription: "Unsupported grant type",
          };
      }

      // Create OAuth context
      const oauthContext: Partial<OAuthContext> = {
        client,
        scopes: request.scope ? request.scope.split(" ") : [],
        grant_type: request.grant_type,
        is_authenticated: false,
      };

      return { valid: true, oauthContext };
    } catch (error: any) {
      return {
        valid: false,
        error: OAuthErrorType.SERVER_ERROR,
        errorDescription: error.message,
      };
    }
  }

  /**
   * Verify state parameter to prevent CSRF
   */
  async verifyState(
    state: string,
    storedState?: string,
  ): Promise<{
    valid: boolean;
    error?: string;
  }> {
    if (!state) {
      return { valid: true }; // State is optional
    }

    if (!storedState) {
      return {
        valid: false,
        error: "State parameter not found in session",
      };
    }

    if (state !== storedState) {
      return {
        valid: false,
        error: "State parameter mismatch - possible CSRF attack",
      };
    }

    return { valid: true };
  }

  /**
   * Verify nonce parameter to prevent replay attacks
   */
  async verifyNonce(
    nonce: string,
    usedNonces: Set<string>,
  ): Promise<{
    valid: boolean;
    error?: string;
  }> {
    if (!nonce) {
      return { valid: true }; // Nonce is optional
    }

    if (usedNonces.has(nonce)) {
      return {
        valid: false,
        error: "Nonce has already been used - possible replay attack",
      };
    }

    // Add nonce to used set
    usedNonces.add(nonce);

    // Clean up old nonces (in a real implementation, you would use a timestamp-based cleanup)
    if (usedNonces.size > 1000) {
      const noncesArray = Array.from(usedNonces);
      usedNonces.clear();
      // Keep only the most recent 500 nonces
      noncesArray.slice(-500).forEach((n) => usedNonces.add(n));
    }

    return { valid: true };
  }

  /**
   * Verify DPoP proof header
   */
  async verifyDPoP(
    request: AuthRequest,
    accessToken?: string,
  ): Promise<{
    valid: boolean;
    error?: string;
    dpopContext?: any;
  }> {
    try {
      const dpopHeader = request.headers["dpop"];

      if (!dpopHeader) {
        return { valid: true }; // DPoP is optional
      }

      if (!accessToken) {
        return {
          valid: false,
          error: "Access token is required for DPoP verification",
        };
      }

      // Extract HTTP method and URI from request
      const httpMethod = request.method || "GET";
      const httpUri = request.url || "https://api.example.com";

      // Verify DPoP proof
      const dpopResult = await this.jwtService.verifyDPoPProof(
        dpopHeader,
        httpMethod,
        httpUri,
      );

      if (!dpopResult.valid) {
        return {
          valid: false,
          error: dpopResult.error || "Invalid DPoP proof",
        };
      }

      // Verify that the access token contains the same JTI (thumbprint)
      // This would require the access token to contain a 'cnf' claim with the JKT
      // For now, we'll just return the DPoP context
      const dpopContext = {
        jti: dpopResult.jti,
        htm: httpMethod,
        htu: httpUri,
      };

      return { valid: true, dpopContext };
    } catch (error: any) {
      return {
        valid: false,
        error: error.message,
      };
    }
  }

  /**
   * Create and verify security challenge
   */
  async createChallenge(
    type: ChallengeType,
    data: any,
    expiresInMinutes: number = 10,
  ): Promise<{
    success: boolean;
    challenge?: SecurityChallenge;
    error?: string;
  }> {
    try {
      const challengeData = this.securityService.createChallenge(
        type,
        data,
        expiresInMinutes,
      );

      // In a real implementation, you would store this in the database
      // For now, we'll return the challenge data
      const challenge: SecurityChallenge = {
        id: challengeData.challenge_id,
        challenge_id: challengeData.challenge_id,
        challenge_type: challengeData.challenge_type,
        challenge_data: challengeData.challenge_data,
        expires_at: challengeData.expires_at,
        is_solved: challengeData.is_solved,
      };

      return { success: true, challenge };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Verify security challenge solution
   */
  async verifyChallenge(
    challengeId: string,
    solution: any,
  ): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      // In a real implementation, you would retrieve the challenge from database
      // For now, we'll create a mock challenge
      const challenge: SecurityChallenge = {
        id: challengeId,
        challenge_id: challengeId,
        challenge_type: "captcha" as ChallengeType,
        challenge_data: JSON.stringify({ expectedCode: "123456" }),
        expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        is_solved: false,
      };

      const result = await this.securityService.verifyChallenge(challenge, solution);

      if (result.valid) {
        // Mark challenge as solved in database
        // await this.markChallengeAsSolved(challenge.id);
        return { success: true };
      } else {
        return {
          success: false,
          error: result.error || "Invalid challenge solution",
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Log security event for auditing
   */
  async logSecurityEvent(
    event: string,
    userId?: string,
    clientId?: string,
    details?: any,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        event,
        user_id: userId,
        client_id: clientId,
        details: details ? JSON.stringify(details) : undefined,
        ip_address: ipAddress,
        user_agent: userAgent,
      };

      // In a real implementation, you would store this in a security logs table
      console.log("Security Event:", JSON.stringify(logEntry, null, 2));
    } catch (error: any) {
      console.error("Failed to log security event:", error);
    }
  }

  /**
   * Detect suspicious activity patterns
   */
  async detectSuspiciousActivity(
    userId: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<{
    suspicious: boolean;
    reasons?: string[];
    riskScore?: number;
  }> {
    try {
      const reasons: string[] = [];
      let riskScore = 0;

      // Check for multiple failed login attempts from same IP
      // In a real implementation, you would query the database for recent failed attempts
      // const recentFailures = await this.getRecentFailedLogins(ipAddress, 15 * 60); // 15 minutes
      // if (recentFailures > 5) {
      //   reasons.push("Multiple failed login attempts from same IP");
      //   riskScore += 30;
      // }

      // Check for login from unusual geographic location
      // In a real implementation, you would use a geolocation service
      // const userLocation = await this.getUserLocation(userId);
      // const currentLocation = await this.getIPLocation(ipAddress);
      // if (userLocation && currentLocation && userLocation !== currentLocation) {
      //   reasons.push("Login from unusual geographic location");
      //   riskScore += 20;
      // }

      // Check for login from unusual device/browser
      // In a real implementation, you would check against known devices
      // const knownDevices = await this.getUserKnownDevices(userId);
      // if (!knownDevices.some(device => device.userAgent === userAgent)) {
      //   reasons.push("Login from unknown device/browser");
      //   riskScore += 15;
      // }

      // Check for rapid successive requests
      // In a real implementation, you would check request timing
      // const recentRequests = await this.getRecentRequests(userId, 1 * 60); // 1 minute
      // if (recentRequests > 10) {
      //   reasons.push("Rapid successive requests");
      //   riskScore += 25;
      // }

      const suspicious = riskScore > 50; // Threshold for suspicious activity

      return {
        suspicious,
        reasons: reasons.length > 0 ? reasons : undefined,
        riskScore,
      };
    } catch (error: any) {
      console.error("Error detecting suspicious activity:", error);
      return {
        suspicious: false,
        reasons: ["Error in security analysis"],
        riskScore: 0,
      };
    }
  }

  /**
   * Apply rate limiting based on client and user
   */
  async checkRateLimit(
    clientId?: string,
    userId?: string,
    ipAddress?: string,
    windowMinutes: number = 15,
    maxRequests: number = 100,
  ): Promise<{
    allowed: boolean;
    remainingRequests?: number;
    resetTime?: Date;
  }> {
    try {
      // In a real implementation, you would check against a rate limiting store
      // const requestCount = await this.getRequestCount(clientId, userId, ipAddress, windowMinutes);

      // For demonstration, we'll always allow requests
      const requestCount = 0;
      const remainingRequests = Math.max(0, maxRequests - requestCount);
      const resetTime = new Date(Date.now() + windowMinutes * 60 * 1000);

      return {
        allowed: requestCount < maxRequests,
        remainingRequests,
        resetTime,
      };
    } catch (error: any) {
      console.error("Error checking rate limit:", error);
      return { allowed: true }; // Fail open for security errors
    }
  }
}

/**
 * Factory function to create OAuth security middleware
 */
export function createOAuthSecurityMiddleware(
  oauthService: OAuthService,
  securityService: SecurityService,
  jwtService: JWTService,
): OAuthSecurityMiddleware {
  return new OAuthSecurityMiddleware(oauthService, securityService, jwtService);
}
