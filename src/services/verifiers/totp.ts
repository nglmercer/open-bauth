import type { ChallengeVerifier, ChallengeVerificationResult } from "../security";
import { base32Decode } from "../../utils/base32";
import { VerifierMessages } from "./constants";

interface TOTPChallengeData {
    secret: string;
}

interface TOTPSolution {
    token: string;
}

/**
 * Real implementation of TOTP (Time-based One-Time Password)
 * RFC 6238 compliant
 */
export class TOTPVerifier implements ChallengeVerifier<TOTPChallengeData, TOTPSolution> {
    private readonly WINDOW = 1; // Allow 1 step before/after for clock skew (30s window)

    verify(data: unknown, solution: unknown): ChallengeVerificationResult {
        const challengeData = data as TOTPChallengeData;
        const sol = solution as TOTPSolution;

        if (!sol || !sol.token) {
            return { valid: false, error: VerifierMessages.TOTP_REQUIRED };
        }

        if (!challengeData || !challengeData.secret) {
            return { valid: false, error: VerifierMessages.TOTP_CONFIG_INVALID };
        }

        const isValid = this.verifyTOTP(
            sol.token,
            challengeData.secret,
            this.WINDOW
        );

        if (!isValid) {
            return { valid: false, error: VerifierMessages.TOTP_INVALID };
        }

        return { valid: true };
    }

    /**
     * Verify a TOTP token
     */
    private verifyTOTP(token: string, secret: string, window: number = 1): boolean {
        const currentCounter = Math.floor(Date.now() / 1000 / 30);

        // Check current window and surrounding windows for clock skew
        for (let i = -window; i <= window; i++) {
            const counter = currentCounter + i;
            const generatedToken = this.generateTOTP(secret, counter);
            if (generatedToken === token) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a TOTP token for a specific counter
     * Made public for testing and integration
     */
    public generateTOTP(secret: string, counter: number = Math.floor(Date.now() / 1000 / 30)): string {
        // Decode base32 secret
        let key: Buffer;
        try {
            // Assume Base32 if string, otherwise use as buffer
            key = base32Decode(secret);
        } catch (e) {
            // Fallback for non-base32 secrets (legacy/testing)
            key = Buffer.from(secret);
        }

        const buffer = Buffer.alloc(8);
        for (let i = 0; i < 8; i++) {
            buffer[7 - i] = counter & 0xff;
            counter = counter >> 8;
        }

        const hasher = new Bun.CryptoHasher("sha1", key);
        hasher.update(buffer);
        const digest = hasher.digest();

        const offset = digest[digest.length - 1] & 0xf;
        const code =
            ((digest[offset] & 0x7f) << 24) |
            ((digest[offset + 1] & 0xff) << 16) |
            ((digest[offset + 2] & 0xff) << 8) |
            (digest[offset + 3] & 0xff);

        return (code % 1000000).toString().padStart(6, "0");
    }
}
