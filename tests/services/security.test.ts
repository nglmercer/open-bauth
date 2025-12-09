import { describe, expect, test, beforeAll } from "bun:test";
import { SecurityService } from "../../src/services/security";
import { PKCEMethod, ChallengeType } from "../../src/types/oauth";
import { TOTPVerifier } from "../../src/services/verifiers/totp";

describe("SecurityService", () => {
    let securityService: SecurityService;

    beforeAll(() => {
        securityService = new SecurityService();
    });

    describe("PKCE", () => {
        test("should generate and verify S256 challenge", () => {
            const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
            expect(challenge.code_challenge_method).toBe(PKCEMethod.S256);
            expect(challenge.code_verifier).toBeDefined();
            expect(challenge.code_challenge).toBeDefined();

            const isValid = securityService.verifyPKCEChallenge(
                challenge.code_verifier,
                challenge.code_challenge,
                PKCEMethod.S256
            );
            expect(isValid).toBe(true);
        });

        test("should generate and verify plain challenge", () => {
            const challenge = securityService.generatePKCEChallenge(PKCEMethod.PLAIN);
            expect(challenge.code_challenge_method).toBe(PKCEMethod.PLAIN);
            expect(challenge.code_verifier).toBe(challenge.code_challenge);

            const isValid = securityService.verifyPKCEChallenge(
                challenge.code_verifier,
                challenge.code_challenge,
                PKCEMethod.PLAIN
            );
            expect(isValid).toBe(true);
        });

        test("should fail verification with wrong verifier", () => {
            const challenge = securityService.generatePKCEChallenge(PKCEMethod.S256);
            const isValid = securityService.verifyPKCEChallenge(
                "wrong-verifier",
                challenge.code_challenge,
                PKCEMethod.S256
            );
            expect(isValid).toBe(false);
        });
    });

    describe("Random Strings", () => {
        test("should generate state", () => {
            const state = securityService.generateState();
            expect(state.length).toBeGreaterThan(0);
        });

        test("should generate nonce", () => {
            const nonce = securityService.generateNonce();
            expect(nonce.length).toBeGreaterThan(0);
        });
    });

    describe("Password Hashing", () => {
        test("should hash and verify password using Bun.password (Argon2)", async () => {
            const password = "my-secret-password";
            const { hash, salt } = await securityService.hashPassword(password);

            expect(hash).toBeDefined();
            // Argon2 hashes start with $argon2
            expect(hash.startsWith("$argon2")).toBe(true);
            // Salt is embedded in the hash, so returned salt is empty
            expect(salt).toBe("");

            const isValid = await securityService.verifyPassword(password, hash, salt);
            expect(isValid).toBe(true);
        });

        test("should fail with wrong password (Argon2)", async () => {
            const password = "correct-password";
            const { hash, salt } = await securityService.hashPassword(password);

            const isValid = await securityService.verifyPassword("wrong-password", hash, salt);
            expect(isValid).toBe(false);
        });

        test("should verify legacy HMAC-SHA512 hashes", async () => {
            // Manually create a legacy hash
            const { createHmac } = await import("crypto");
            const password = "legacy-password";
            const salt = "legacy-salt";

            // This replicates the old logic
            const hash = createHmac("sha512", salt)
                .update(password)
                .digest("hex");

            const isValid = await securityService.verifyPassword(password, hash, salt);
            expect(isValid).toBe(true);
        });
    });

    describe("Encryption", () => {
        test("should encrypt and decrypt data", async () => {
            const data = "sensitive-data";
            const key = securityService.generateSecureToken(32); // 32 bytes for AES-256

            const encrypted = await securityService.encrypt(data, key);
            expect(encrypted).not.toBe(data);

            const decrypted = await securityService.decrypt(encrypted, key);
            expect(decrypted).toBe(data);
        });

        test("should fail to decrypt with wrong key", async () => {
            const data = "sensitive-data";
            const key = securityService.generateSecureToken(32);
            const wrongKey = securityService.generateSecureToken(32);

            const encrypted = await securityService.encrypt(data, key);

            try {
                await securityService.decrypt(encrypted, wrongKey);
                // Should throw
                expect(true).toBe(false);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
    });

    describe("DPoP", () => {
        test("should generate and verify DPoP proof", async () => {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                true,
                ["sign", "verify"]
            );

            const method = "POST";
            const uri = "https://server.example.com/token";

            const proof = await securityService.generateDPoPProof(
                method,
                uri,
                keyPair.privateKey
            );

            const verification = await securityService.verifyDPoPProof(
                proof,
                method,
                uri,
                keyPair.publicKey
            );

            if (!verification.valid) {
                console.error("DPoP Verification Error:", verification.error);
            }
            expect(verification.valid).toBe(true);
            expect(verification.payload).toBeDefined();
            expect(verification.payload?.htm).toBe(method);
            expect(verification.payload?.htu).toBe(uri);
        });
    });

    describe("Security Challenges", () => {
        // 1. Email Verification (using SecureCodeVerifier)
        test("should create and verify email challenge", async () => {
            const challenge = securityService.createChallenge(ChallengeType.EMAIL_VERIFICATION, {
                expectedCode: "123456"
            });
            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { code: "123456" }
            );
            expect(result.valid).toBe(true);
        });

        // 2. SMS Verification (using SecureCodeVerifier)
        test("should create and verify SMS challenge", async () => {
            const challenge = securityService.createChallenge(ChallengeType.SMS_VERIFICATION, {
                expectedCode: "987654"
            });
            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { code: "987654" }
            );
            expect(result.valid).toBe(true);
        });

        // 3. MFA Verification (using TOTPVerifier)
        test("should verify MFA challenge", async () => {
            const secret = "XYZSECRET";
            const challenge = securityService.createChallenge(ChallengeType.MFA, {
                secret
            });

            // Generate valid token to verify
            const totpVerifier = new TOTPVerifier();
            const token = totpVerifier.generateTOTP(secret);

            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { token }
            );
            expect(result.valid).toBe(true);
        });

        // 4. CAPTCHA Verification (Mock Implementation)
        test("should allow registering and verifying CAPTCHA challenge", async () => {
            // Register a simple Math Captcha for testing (No libraries needed)
            securityService.registerVerifier(ChallengeType.CAPTCHA, {
                verify: (data, solution) => {
                    const expected = data.num1 + data.num2;
                    if (parseInt(solution.answer) === expected) {
                        return { valid: true };
                    }
                    return { valid: false, error: "Incorrect Captcha" };
                }
            });

            const challenge = securityService.createChallenge(ChallengeType.CAPTCHA, {
                num1: 5,
                num2: 3
            });

            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { answer: "8" }
            );

            expect(result.valid).toBe(true);
        });

        // 5. Biometric Verification (Mock Implementation using Crypto)
        test("should allow registering and verifying Biometric challenge", async () => {
            // Mock a WebAuthn-like signature check using native crypto
            securityService.registerVerifier(ChallengeType.BIOMETRIC, {
                verify: async (data, solution) => {
                    const { signature, publicKeyJwk } = solution;
                    const { challengeId } = data;

                    try {
                        const key = await crypto.subtle.importKey(
                            "jwk",
                            publicKeyJwk,
                            { name: "ECDSA", namedCurve: "P-256" },
                            false,
                            ["verify"]
                        );

                        const isValid = await crypto.subtle.verify(
                            { name: "ECDSA", hash: "SHA-256" },
                            key,
                            Buffer.from(signature, "hex"),
                            Buffer.from(challengeId)
                        );

                        return { valid: isValid };
                    } catch (e) {
                        return { valid: false, error: "Signature verification failed" };
                    }
                }
            });

            // Setup keys for test
            const keyPair = await crypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["sign", "verify"]
            );
            const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

            // Create challenge
            const challengeId = "random-challenge-string";
            const challenge = securityService.createChallenge(ChallengeType.BIOMETRIC, {
                challengeId
            });

            // User signs the challengeId
            const signatureBuffer = await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                keyPair.privateKey,
                Buffer.from(challengeId)
            );
            const signature = Buffer.from(signatureBuffer).toString("hex");

            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { signature, publicKeyJwk }
            );

            expect(result.valid).toBe(true);
        });

        // 6. Device Verification (Mock Implementation)
        test("should allow registering and verifying Device challenge", async () => {
            // Simple "Known Device ID" check
            securityService.registerVerifier(ChallengeType.DEVICE_VERIFICATION, {
                verify: (data, solution) => {
                    if (data.allowedDevices.includes(solution.deviceId)) {
                        return { valid: true };
                    }
                    return { valid: false, error: "Unknown Device" };
                }
            });

            const challenge = securityService.createChallenge(ChallengeType.DEVICE_VERIFICATION, {
                allowedDevices: ["device-1", "device-2"]
            });

            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { deviceId: "device-1" }
            );

            expect(result.valid).toBe(true);

            const failResult = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { deviceId: "device-3" }
            );
            expect(failResult.valid).toBe(false);
        });

        test("should fail verification with wrong code", async () => {
            const challenge = securityService.createChallenge(ChallengeType.EMAIL_VERIFICATION, {
                expectedCode: "123456"
            });
            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { code: "wrong" }
            );
            expect(result.valid).toBe(false);
        });

        test("should register and verify custom challenge (Puzzle)", async () => {
            const customType = "puzzle";
            securityService.registerVerifier(customType, {
                verify: (data, solution) => {
                    return { valid: solution.answer === data.expected };
                }
            });
            const challenge = securityService.createChallenge(customType, { expected: "42" });
            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { answer: "42" }
            );
            expect(result.valid).toBe(true);
        });

        test("should register and verify complex Proof of Work challenge", async () => {
            // Example of a complex "Proof of Work" challenge
            const powType = "proof_of_work_2";

            securityService.registerVerifier(powType, {
                verify: async (data, solution) => {
                    const { createHash } = await import("crypto");
                    const { prefix, difficulty } = data;
                    const { nonce } = solution;

                    const hash = createHash("sha256")
                        .update(prefix + nonce)
                        .digest("hex");

                    const target = "0".repeat(difficulty);
                    if (hash.startsWith(target)) {
                        return { valid: true };
                    } else {
                        return { valid: false, error: "Invalid Proof of Work" };
                    }
                }
            });

            const difficulty = 1;
            const prefix = "test-prefix-2-";
            const challenge = securityService.createChallenge(powType, { prefix, difficulty });

            let nonce = 0;
            const { createHash } = await import("crypto");
            while (true) {
                const hash = createHash("sha256")
                    .update(prefix + nonce.toString())
                    .digest("hex");
                if (hash.startsWith("0")) break;
                nonce++;
            }

            const result = await securityService.verifyChallenge(
                { ...challenge, id: "test", created_at: new Date().toISOString() },
                { nonce: nonce.toString() }
            );

            expect(result.valid).toBe(true);
        });
    });

    describe("Password Based Encryption", () => {
        test("should encrypt and decrypt with password", async () => {
            const data = "super-secret-text";
            const password = "my-strong-password";

            const encrypted = await securityService.encryptWithPassword(data, password);
            expect(encrypted).toBeDefined();
            expect(encrypted).not.toBe(data);
            expect(encrypted.split(":").length).toBe(4); // salt:iv:tag:data

            const decrypted = await securityService.decryptWithPassword(encrypted, password);
            expect(decrypted).toBe(data);
        });

        test("should fail to decrypt with wrong password", async () => {
            const data = "secret";
            const password = "password123";
            const wrongPassword = "password456";

            const encrypted = await securityService.encryptWithPassword(data, password);

            try {
                await securityService.decryptWithPassword(encrypted, wrongPassword);
                expect(true).toBe(false);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
    });
});
