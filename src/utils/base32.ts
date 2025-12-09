/**
 * Simple Base32 decoder for TOTP secrets
 * RFC 4648 compliant
 */
export function base32Decode(input: string): Buffer {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const padding = "=";

    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array((input.length * 5) / 8 | 0);

    for (let i = 0; i < input.length; i++) {
        const char = input[i].toUpperCase();
        if (char === padding) break;

        const val = alphabet.indexOf(char);
        if (val === -1) continue; // Skip invalid chars

        value = (value << 5) | val;
        bits += 5;

        if (bits >= 8) {
            output[index++] = (value >>> (bits - 8)) & 255;
            bits -= 8;
        }
    }

    return Buffer.from(output.slice(0, index));
}
