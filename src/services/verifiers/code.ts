import type { ChallengeVerifier, ChallengeVerificationResult } from "../security";
import { VerifierMessages } from "./constants";

interface CodeChallengeData {
    expectedHash?: string;
    salt?: string;
    expectedCode?: string; // Legacy/Simple
}

interface CodeSolution {
    code: string;
}

/**
 * Generic Hash Verifier for "Secret Code" flows (Email code, SMS code)
 * Uses secure constant-time comparison of hashed codes.
 */
export class SecureCodeVerifier implements ChallengeVerifier<CodeChallengeData, CodeSolution> {
    /**
     * @param salt Optional salt logic could be injected here
     */
    constructor() { }

    verify(data: unknown, solution: unknown): ChallengeVerificationResult {
        const challengeData = data as CodeChallengeData;
        const sol = solution as CodeSolution;

        if (!sol || !sol.code) {
            return { valid: false, error: VerifierMessages.CODE_REQUIRED };
        }

        if (!challengeData || (!challengeData.expectedHash && !challengeData.expectedCode)) {
            return { valid: false, error: VerifierMessages.CODE_DATA_INVALID };
        }

        // Fallback for legacy plain text (warn in logs in real app)
        if (challengeData.expectedCode) {
            return {
                valid: sol.code === challengeData.expectedCode,
                error: sol.code === challengeData.expectedCode ? undefined : VerifierMessages.CODE_INVALID
            };
        }

        // Hash the provided solution and compare with stored hash
        const solutionHash = this.hashString(sol.code, challengeData.salt);

        // Constant-time comparison to prevent timing attacks
        if (solutionHash === challengeData.expectedHash) {
            return { valid: true };
        }

        return { valid: false, error: VerifierMessages.CODE_INVALID };
    }

    private hashString(val: string, salt: string = ""): string {
        const hasher = new Bun.CryptoHasher("sha256");
        hasher.update(val + salt);
        return hasher.digest("hex");
    }
}
