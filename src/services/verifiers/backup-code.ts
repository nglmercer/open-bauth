import type { ChallengeVerifier, ChallengeVerificationResult } from "../security";
import { createHash } from "crypto";
import { VerifierMessages } from "./constants";

interface BackupChallengeData {
    hashedCodes: string[];
    salt?: string;
}

interface BackupSolution {
    code: string;
}

interface BackupResultData {
    usedCodeHash: string;
    index: number;
}

/**
 * Verifier for Recovery/Backup Codes
 * Users are provided with a list of one-time use codes.
 * This verifier checks if the provided code matches one of the valid hashed codes.
 */
export class BackupCodeVerifier implements ChallengeVerifier<BackupChallengeData, BackupSolution> {

    verify(data: unknown, solution: unknown): ChallengeVerificationResult<BackupResultData> {
        const challengeData = data as BackupChallengeData;
        const sol = solution as BackupSolution;

        if (!sol || !sol.code) {
            return { valid: false, error: VerifierMessages.BACKUP_CODE_REQUIRED };
        }

        if (!challengeData || !Array.isArray(challengeData.hashedCodes)) {
            return { valid: false, error: VerifierMessages.BACKUP_CONFIG_INVALID };
        }

        const inputCode = sol.code.trim();

        // Hash the input code to compare with stored hashes
        // We assume SHA-256 for backup codes as they are high entropy
        // salt is optional but recommended. If salt is global per user, it should be in challengeData.
        const salt = challengeData.salt || "";
        const hashedInput = this.hashString(inputCode, salt);

        const matchIndex = challengeData.hashedCodes.indexOf(hashedInput);

        if (matchIndex !== -1) {
            return {
                valid: true,
                data: {
                    usedCodeHash: hashedInput,
                    index: matchIndex
                }
            };
        }

        return { valid: false, error: VerifierMessages.BACKUP_CODE_INVALID };
    }

    private hashString(val: string, salt: string): string {
        return createHash("sha256").update(val + salt).digest("hex");
    }
}
