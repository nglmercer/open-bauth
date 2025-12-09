import { describe, expect, test } from "bun:test";
import { TOTPVerifier } from "../../src/services/verifiers/totp";
import { SecureCodeVerifier } from "../../src/services/verifiers/code";
import { BackupCodeVerifier } from "../../src/services/verifiers/backup-code";
import { base32Decode } from "../../src/utils/base32";
import { createHash } from "crypto";
import { VerifierMessages } from "../../src/services/verifiers/constants";

describe("Security Verifiers", () => {

    describe("TOTP Verifier", () => {
        const totp = new TOTPVerifier();
        // A standard base32 secret
        const secretBase32 = "JBSWY3DPEHPK3PXP"; // "Hello!DEADBEEF" basically
        // A plain text secret (fallback)
        const secretPlain = "secret123";

        test("should generate valid TOTP for base32 secret", () => {
            const token = totp.generateTOTP(secretBase32);
            expect(token).toBeDefined();
            expect(token.length).toBe(6);
            expect(/^\d+$/.test(token)).toBe(true);
        });

        test("should generate valid TOTP for plain secret", () => {
            const token = totp.generateTOTP(secretPlain);
            expect(token).toBeDefined();
            expect(token.length).toBe(6);
        });

        test("should verify valid token", () => {
            const token = totp.generateTOTP(secretBase32);
            const result = totp.verify({ secret: secretBase32 }, { token });
            expect(result.valid).toBe(true);
        });

        test("should verify token within window", () => {
            // Generate token for previous step
            const pastCounter = Math.floor(Date.now() / 1000 / 30) - 1;
            const token = totp.generateTOTP(secretBase32, pastCounter);

            const result = totp.verify({ secret: secretBase32 }, { token });
            expect(result.valid).toBe(true);
        });

        test("should reject token outside window", () => {
            // Generate token for way past
            const pastCounter = Math.floor(Date.now() / 1000 / 30) - 2; // Window is 1
            const token = totp.generateTOTP(secretBase32, pastCounter);

            const result = totp.verify({ secret: secretBase32 }, { token });
            expect(result.valid).toBe(false);
        });

        test("should reject invalid token", () => {
            const result = totp.verify({ secret: secretBase32 }, { token: "000000" });
            expect(result.valid).toBe(false);
        });

        test("should reject if secret is missing", () => {
            // @ts-ignore - testing runtime safety
            const result = totp.verify({}, { token: "123456" });
            expect(result.valid).toBe(false);
            expect(result.error).toContain(VerifierMessages.TOTP_CONFIG_INVALID);
        });
    });

    describe("Secure Code Verifier", () => {
        const verifier = new SecureCodeVerifier();
        const code = "123456";
        const salt = "somesalt";
        // Simulate database stored hash
        const expectedHash = createHash("sha256").update(code + salt).digest("hex");

        test("should verify valid code", () => {
            const result = verifier.verify(
                { expectedHash, salt },
                { code }
            );
            expect(result.valid).toBe(true);
        });

        test("should reject invalid code", () => {
            const result = verifier.verify(
                { expectedHash, salt },
                { code: "654321" }
            );
            expect(result.valid).toBe(false);
        });

        test("should reject missing code", () => {
            // @ts-ignore - testing runtime safety
            const result = verifier.verify({ expectedHash, salt }, {});
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        test("should verify legacy plain text code (fallback)", () => {
            const result = verifier.verify(
                { expectedCode: "999999" },
                { code: "999999" }
            );
            expect(result.valid).toBe(true);
        });

        test("should reject wrong legacy plain text code", () => {
            const result = verifier.verify(
                { expectedCode: "999999" },
                { code: "111111" }
            );
            expect(result.valid).toBe(false);
        });
    });

    describe("Backup Code Verifier", () => {
        const verifier = new BackupCodeVerifier();
        const salt = "recovery-salt";

        const rawCodes = ["code1", "code2", "code3"];
        const hashedCodes = rawCodes.map(c =>
            createHash("sha256").update(c + salt).digest("hex")
        );

        test("should verify valid backup code", () => {
            const result = verifier.verify(
                { hashedCodes, salt },
                { code: "code2" }
            );

            expect(result.valid).toBe(true);
            expect(result.data).toBeDefined();
            expect(result.data?.index).toBe(1); // Index of "code2"
            expect(result.data?.usedCodeHash).toBe(hashedCodes[1]);
        });

        test("should reject invalid backup code", () => {
            const result = verifier.verify(
                { hashedCodes, salt },
                { code: "code999" }
            );
            expect(result.valid).toBe(false);
        });

        test("should handle whitespace trimming", () => {
            const result = verifier.verify(
                { hashedCodes, salt },
                { code: " code1 " }
            );
            expect(result.valid).toBe(true);
        });

        test("should handle empty backup codes list", () => {
            const result = verifier.verify(
                { hashedCodes: [], salt },
                { code: "code1" }
            );
            expect(result.valid).toBe(false);
        });

        test("should reject if hashedCodes is missing", () => {
            // @ts-ignore
            const result = verifier.verify(
                { salt },
                { code: "code1" }
            );
            expect(result.valid).toBe(false);
        });
    });

    describe("Base32 Utils", () => {
        test("should decode standard test vectors", () => {
            // RFC 4648 test vectors
            const vectors = [
                ["MY======", "f"],
                ["MZXQ====", "fo"],
                ["MZXW6===", "foo"],
                ["MZXW6YQ=", "foob"],
                ["MZXW6YTB", "fooba"],
                ["MZXW6YTBOI======", "foobar"]
            ];

            for (const [input, expected] of vectors) {
                const decoded = base32Decode(input);
                expect(decoded.toString()).toBe(expected);
            }
        });

        test("should handle empty string", () => {
            const decoded = base32Decode("");
            expect(decoded.length).toBe(0);
        });
    });

});
