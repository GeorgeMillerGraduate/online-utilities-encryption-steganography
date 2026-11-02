/**
 * ============================================================
 * AESUtils
 * ============================================================
 *
 * Utility functions and lookup tables used by AES-128.
 *
 * Contains:
 *
 *      AES S-Box
 *      AES Inverse S-Box
 *      AES Round Constants
 *      GF(2^8) multiplication
 *      Byte / hexadecimal conversion helpers
 *
 * AES128.js depends on this class.
 *
 * ============================================================
 */

class AESUtils {


    /**
     * ========================================================
     * AES S-BOX
     * ========================================================
     *
     * Used during:
     *
     *      SubBytes
     *      Key Expansion / SubWord
     *
     * Index = input byte
     * Value = substituted byte
     *
     * ========================================================
     */

    static SBOX = new Uint8Array([

        0x63, 0x7C, 0x77, 0x7B,
        0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B,
        0xFE, 0xD7, 0xAB, 0x76,

        0xCA, 0x82, 0xC9, 0x7D,
        0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF,
        0x9C, 0xA4, 0x72, 0xC0,

        0xB7, 0xFD, 0x93, 0x26,
        0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1,
        0x71, 0xD8, 0x31, 0x15,

        0x04, 0xC7, 0x23, 0xC3,
        0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75,

        0x09, 0x83, 0x2C, 0x1A,
        0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3,
        0x29, 0xE3, 0x2F, 0x84,

        0x53, 0xD1, 0x00, 0xED,
        0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39,
        0x4A, 0x4C, 0x58, 0xCF,

        0xD0, 0xEF, 0xAA, 0xFB,
        0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F,
        0x50, 0x3C, 0x9F, 0xA8,

        0x51, 0xA3, 0x40, 0x8F,
        0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21,
        0x10, 0xFF, 0xF3, 0xD2,

        0xCD, 0x0C, 0x13, 0xEC,
        0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D,
        0x64, 0x5D, 0x19, 0x73,

        0x60, 0x81, 0x4F, 0xDC,
        0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14,
        0xDE, 0x5E, 0x0B, 0xDB,

        0xE0, 0x32, 0x3A, 0x0A,
        0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62,
        0x91, 0x95, 0xE4, 0x79,

        0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA,
        0x65, 0x7A, 0xAE, 0x08,

        0xBA, 0x78, 0x25, 0x2E,
        0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F,
        0x4B, 0xBD, 0x8B, 0x8A,

        0x70, 0x3E, 0xB5, 0x66,
        0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9,
        0x86, 0xC1, 0x1D, 0x9E,

        0xE1, 0xF8, 0x98, 0x11,
        0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9,
        0xCE, 0x55, 0x28, 0xDF,

        0x8C, 0xA1, 0x89, 0x0D,
        0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F,
        0xB0, 0x54, 0xBB, 0x16

    ]);


    /**
     * ========================================================
     * AES INVERSE S-BOX
     * ========================================================
     *
     * Used by InvSubBytes during AES decryption.
     *
     * ========================================================
     */

    static INVERSE_SBOX = new Uint8Array([

        0x52, 0x09, 0x6A, 0xD5,
        0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E,
        0x81, 0xF3, 0xD7, 0xFB,

        0x7C, 0xE3, 0x39, 0x82,
        0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44,
        0xC4, 0xDE, 0xE9, 0xCB,

        0x54, 0x7B, 0x94, 0x32,
        0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B,
        0x42, 0xFA, 0xC3, 0x4E,

        0x08, 0x2E, 0xA1, 0x66,
        0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49,
        0x6D, 0x8B, 0xD1, 0x25,

        0x72, 0xF8, 0xF6, 0x64,
        0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC,
        0x5D, 0x65, 0xB6, 0x92,

        0x6C, 0x70, 0x48, 0x50,
        0xFD, 0xED, 0xB9, 0xDA,
        0x5E, 0x15, 0x46, 0x57,
        0xA7, 0x8D, 0x9D, 0x84,

        0x90, 0xD8, 0xAB, 0x00,
        0x8C, 0xBC, 0xD3, 0x0A,
        0xF7, 0xE4, 0x58, 0x05,
        0xB8, 0xB3, 0x45, 0x06,

        0xD0, 0x2C, 0x1E, 0x8F,
        0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03,
        0x01, 0x13, 0x8A, 0x6B,

        0x3A, 0x91, 0x11, 0x41,
        0x4F, 0x67, 0xDC, 0xEA,
        0x97, 0xF2, 0xCF, 0xCE,
        0xF0, 0xB4, 0xE6, 0x73,

        0x96, 0xAC, 0x74, 0x22,
        0xE7, 0xAD, 0x35, 0x85,
        0xE2, 0xF9, 0x37, 0xE8,
        0x1C, 0x75, 0xDF, 0x6E,

        0x47, 0xF1, 0x1A, 0x71,
        0x1D, 0x29, 0xC5, 0x89,
        0x6F, 0xB7, 0x62, 0x0E,
        0xAA, 0x18, 0xBE, 0x1B,

        0xFC, 0x56, 0x3E, 0x4B,
        0xC6, 0xD2, 0x79, 0x20,
        0x9A, 0xDB, 0xC0, 0xFE,
        0x78, 0xCD, 0x5A, 0xF4,

        0x1F, 0xDD, 0xA8, 0x33,
        0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59,
        0x27, 0x80, 0xEC, 0x5F,

        0x60, 0x51, 0x7F, 0xA9,
        0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F,
        0x93, 0xC9, 0x9C, 0xEF,

        0xA0, 0xE0, 0x3B, 0x4D,
        0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C,
        0x83, 0x53, 0x99, 0x61,

        0x17, 0x2B, 0x04, 0x7E,
        0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63,
        0x55, 0x21, 0x0C, 0x7D

    ]);


    /**
     * ========================================================
     * ROUND CONSTANTS
     * ========================================================
     *
     * Rcon values used during AES-128 key expansion.
     *
     * Index zero is unused so AES128.js can access:
     *
     *      AESUtils.RCON[1]
     *
     * through:
     *
     *      AESUtils.RCON[10]
     *
     * ========================================================
     */

    static RCON = new Uint8Array([

        0x00,

        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1B,
        0x36

    ]);


    /**
     * ========================================================
     * GALOIS FIELD MULTIPLICATION
     * ========================================================
     *
     * AES arithmetic takes place in GF(2^8).
     *
     * This method performs multiplication modulo:
     *
     *      x^8 + x^4 + x^3 + x + 1
     *
     * represented by:
     *
     *      0x11B
     *
     * Because values are stored as bytes, the reduction XOR
     * uses 0x1B after the high bit has been shifted out.
     *
     * Used by:
     *
     *      MixColumns
     *      InvMixColumns
     *
     * ========================================================
     */

    static multiply(a, b) {

        a &= 0xFF;
        b &= 0xFF;

        let result = 0;


        while (b !== 0) {

            /*
             * If the current low bit of b is set,
             * include the current value of a.
             */

            if (b & 1) {
                result ^= a;
            }


            /*
             * Determine whether multiplying a by x
             * will overflow the 8-bit field.
             */

            const highBit =
                a & 0x80;


            /*
             * Multiply a by x.
             */

            a =
                (a << 1) & 0xFF;


            /*
             * Reduce modulo the AES polynomial.
             */

            if (highBit) {
                a ^= 0x1B;
            }


            /*
             * Move to the next bit of b.
             */

            b >>>= 1;
        }


        return result & 0xFF;
    }


    /**
     * ========================================================
     * XTIME
     * ========================================================
     *
     * Fast multiplication by 2 in GF(2^8).
     *
     * Not required directly by AES128.js because multiply()
     * handles arbitrary values, but useful for experimentation
     * and visualisation.
     *
     * ========================================================
     */

    static xtime(value) {

        value &= 0xFF;

        if (value & 0x80) {

            return (
                ((value << 1) ^ 0x1B)
                & 0xFF
            );
        }

        return (
            value << 1
        ) & 0xFF;
    }


    /**
     * ========================================================
     * BYTE -> HEX
     * ========================================================
     */

    static byteToHex(byte) {

        return (
            byte & 0xFF
        )
            .toString(16)
            .padStart(2, "0")
            .toUpperCase();
    }


    /**
     * ========================================================
     * BYTE ARRAY -> HEX STRING
     * ========================================================
     *
     * Example:
     *
     *      [0x00, 0x11, 0x22]
     *
     * becomes:
     *
     *      "00 11 22"
     *
     * ========================================================
     */

    static bytesToHex(bytes, separator = " ") {

        if (!bytes) {
            return "";
        }


        return Array.from(bytes)
            .map(
                byte =>
                    AESUtils.byteToHex(byte)
            )
            .join(separator);
    }


    /**
     * ========================================================
     * HEX STRING -> BYTE ARRAY
     * ========================================================
     *
     * Accepts:
     *
     *      "00112233"
     *
     * or:
     *
     *      "00 11 22 33"
     *
     * or:
     *
     *      "00:11:22:33"
     *
     * ========================================================
     */

    static hexToBytes(hex) {

        if (typeof hex !== "string") {

            throw new Error(
                "Hexadecimal input must be a string."
            );
        }


        /*
         * Remove common formatting characters.
         */

        const cleaned =
            hex.replace(
                /[\s:_-]/g,
                ""
            );


        if (cleaned.length === 0) {
            return new Uint8Array(0);
        }


        if (cleaned.length % 2 !== 0) {

            throw new Error(
                "Hexadecimal input must contain an even number of digits."
            );
        }


        if (!/^[0-9a-fA-F]+$/.test(cleaned)) {

            throw new Error(
                "Invalid hexadecimal input."
            );
        }


        const output =
            new Uint8Array(
                cleaned.length / 2
            );


        for (
            let i = 0;
            i < output.length;
            i++
        ) {

            output[i] =
                parseInt(
                    cleaned.substring(
                        i * 2,
                        (i * 2) + 2
                    ),
                    16
                );
        }


        return output;
    }


    /**
     * ========================================================
     * BYTE -> BINARY
     * ========================================================
     */

    static byteToBinary(byte) {

        return (
            byte & 0xFF
        )
            .toString(2)
            .padStart(8, "0");
    }


    /**
     * ========================================================
     * BYTE ARRAY -> BINARY STRING
     * ========================================================
     */

    static bytesToBinary(
        bytes,
        separator = " "
    ) {

        if (!bytes) {
            return "";
        }


        return Array.from(bytes)
            .map(
                byte =>
                    AESUtils.byteToBinary(byte)
            )
            .join(separator);
    }


    /**
     * ========================================================
     * XOR BYTE ARRAYS
     * ========================================================
     *
     * Both arrays must be the same length.
     *
     * ========================================================
     */

    static xorBytes(a, b) {

        if (!a || !b) {

            throw new Error(
                "Both byte arrays are required."
            );
        }


        if (a.length !== b.length) {

            throw new Error(
                "Byte arrays must have the same length."
            );
        }


        const result =
            new Uint8Array(a.length);


        for (
            let i = 0;
            i < a.length;
            i++
        ) {

            result[i] =
                (
                    a[i] ^
                    b[i]
                ) & 0xFF;
        }


        return result;
    }


    /**
     * ========================================================
     * COPY BYTE ARRAY
     * ========================================================
     */

    static copyBytes(bytes) {

        return Uint8Array.from(bytes);
    }


    /**
     * ========================================================
     * ARRAYS EQUAL
     * ========================================================
     *
     * Primarily useful for our AES test vectors.
     *
     * ========================================================
     */

    static arraysEqual(a, b) {

        if (!a || !b) {
            return false;
        }


        if (a.length !== b.length) {
            return false;
        }


        for (
            let i = 0;
            i < a.length;
            i++
        ) {

            if (a[i] !== b[i]) {
                return false;
            }
        }


        return true;
    }


    /**
     * ========================================================
     * CONCATENATE BYTE ARRAYS
     * ========================================================
     */

    static concatBytes(...arrays) {

        let totalLength = 0;


        for (const array of arrays) {

            if (array) {
                totalLength += array.length;
            }
        }


        const result =
            new Uint8Array(totalLength);


        let offset = 0;


        for (const array of arrays) {

            if (!array) {
                continue;
            }


            result.set(
                array,
                offset
            );

            offset += array.length;
        }


        return result;
    }


    /**
     * ========================================================
     * AES TEST VECTOR
     * ========================================================
     *
     * Returns the standard values we'll use to verify that
     * AES128.js is functioning correctly.
     *
     * Expected:
     *
     * Key:
     *
     * 00 01 02 03 04 05 06 07
     * 08 09 0A 0B 0C 0D 0E 0F
     *
     * Plaintext:
     *
     * 00 11 22 33 44 55 66 77
     * 88 99 AA BB CC DD EE FF
     *
     * Ciphertext:
     *
     * 69 C4 E0 D8 6A 7B 04 30
     * D8 CD B7 80 70 B4 C5 5A
     *
     * ========================================================
     */

    static getTestVector() {

        return {

            key:
                AESUtils.hexToBytes(
                    "000102030405060708090A0B0C0D0E0F"
                ),

            plaintext:
                AESUtils.hexToBytes(
                    "00112233445566778899AABBCCDDEEFF"
                ),

            ciphertext:
                AESUtils.hexToBytes(
                    "69C4E0D86A7B0430D8CDB78070B4C55A"
                )

        };
    }


    /**
     * ========================================================
     * SELF TEST
     * ========================================================
     *
     * AES128.js must already be loaded before this is called.
     *
     * This isn't run automatically. app.js can invoke it
     * during development:
     *
     *      AESUtils.runSelfTest();
     *
     * ========================================================
     */

    static runSelfTest() {

        if (
            typeof AES128 === "undefined"
        ) {

            throw new Error(
                "AES128.js must be loaded before running the AES self-test."
            );
        }


        const vector =
            AESUtils.getTestVector();


        const aes =
            new AES128(
                vector.key
            );


        const encrypted =
            aes.encryptBlock(
                vector.plaintext
            );


        const encryptionPassed =
            AESUtils.arraysEqual(
                encrypted,
                vector.ciphertext
            );


        const decrypted =
            aes.decryptBlock(
                encrypted
            );


        const decryptionPassed =
            AESUtils.arraysEqual(
                decrypted,
                vector.plaintext
            );


        const result = {

            encryptionPassed:
                encryptionPassed,

            decryptionPassed:
                decryptionPassed,

            passed:
                encryptionPassed &&
                decryptionPassed,

            expectedCiphertext:
                AESUtils.bytesToHex(
                    vector.ciphertext
                ),

            actualCiphertext:
                AESUtils.bytesToHex(
                    encrypted
                ),

            decryptedPlaintext:
                AESUtils.bytesToHex(
                    decrypted
                )

        };


        console.log(
            "AES-128 self-test:",
            result
        );


        return result;
    }

}