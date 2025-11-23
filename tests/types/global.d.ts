// tests/types/global.d.ts

import { JWTService } from "../../src/services/jwt";
import { SecurityService } from "../../src/services/security";
import { OAuthService } from "../../src/services/oauth";

declare global {
  namespace globalThis {
    var testContext: {
      jwtService: JWTService;
      securityService: SecurityService;
      oauthService: OAuthService;
    };
  }
}

export {};
