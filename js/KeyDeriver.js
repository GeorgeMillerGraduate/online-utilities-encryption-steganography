/**
 * ============================================================
 * KeyDeriver
 * ============================================================
 *
 * Converts an arbitrary user string into a 128-bit / 16-byte
 * key suitable for AES128.
 *
 * Two derivation modes are provided:
 *
 *      1. Experimental XOR Folding
 *      2. PBKDF2
 *
 * IMPORTANT:
 *
 * XOR Folding is an educational / experimental algorithm.
 * It is NOT a secure password-based key derivation function.
 *
 * PBKDF2 should be used when cryptographic password
 * derivation is required.
 *
 * ============================================================
 */

class KeyDeriver {


    /**
     * AES-128 requires exactly 16 bytes.
     */
    static KEY_LENGTH_BYTES = 16;

    static KEY_LENGTH_BITS = 128;


    /**
     * PBKDF2 defaults.
     *
     * Salt length:
     *      16 bytes / 128 bits
     *
     * Output:
     *      16 bytes / 128 bits
     */
    static PBKDF2_ITERATIONS = 250000;

    static PBKDF2_SALT_LENGTH = 16;


    /**
     * ========================================================
     * MAIN DERIVATION METHOD
     * ========================================================
     *
     * method:
     *
     *      "xor"
     *      "pbkdf2"
     *
     * PBKDF2 is asynchronous, so this method is async even
     * when XOR mode is selected.
     *
     * ========================================================
     */

    static async derive(
        input,
        method = "xor",
        options = {}
    ) {

        if (typeof input !== "string") {

            throw new Error(
                "Key input must be a string."
            );
        }


        if (input.length === 0) {

            throw new Error(
                "Enter a key string before generating a key."
            );
        }


        switch (method) {

            case "xor":

                return {

                    method:
                        "xor",

                    key:
                        KeyDeriver.deriveXOR(
                            input
                        ),

                    salt:
                        null

                };


            case "pbkdf2":

                return await KeyDeriver.derivePBKDF2(
                    input,
                    options
                );


            default:

                throw new Error(
                    "Unknown key derivation method: " +
                    method
                );
        }
    }


    /**
     * ========================================================
     * EXPERIMENTAL XOR DERIVATION
     * ========================================================
     *
     * The goal is to turn an arbitrary UTF-8 string into:
     *
     *      16 bytes
     *
     *      =
     *
     *      128 bits
     *
     *
     * The algorithm deliberately exposes the sort of
     * operations being performed so it can be visualised
     * by the site.
     *
     *
     * LONG INPUT
     * ----------
     *
     * Input bytes are repeatedly folded across sixteen
     * output positions:
     *
     *      output[index % 16]
     *
     * Bytes beyond the first sixteen therefore XOR back
     * into earlier positions.
     *
     *
     * SHORT INPUT
     * -----------
     *
     * If fewer than sixteen bytes were supplied, the existing
     * bytes are repeatedly extended across the remaining
     * positions.
     *
     * Position-dependent rotation and XOR mixing prevent the
     * extension from simply repeating the original text.
     *
     *
     * SECURITY
     * --------
     *
     * This is NOT a password hash or secure KDF.
     *
     * It is deliberately included as an educational
     * experiment alongside PBKDF2.
     *
     * ========================================================
     */

    static deriveXOR(input) {

        const bytes =
            KeyDeriver.stringToBytes(
                input
            );


        if (bytes.length === 0) {

            throw new Error(
                "Cannot derive a key from an empty string."
            );
        }


        const key =
            new Uint8Array(
                KeyDeriver.KEY_LENGTH_BYTES
            );


        /*
         * ----------------------------------------------------
         * INITIAL SEED
         * ----------------------------------------------------
         *
         * Start with deterministic non-zero values.
         *
         * This prevents untouched positions in very short
         * passwords from simply remaining zero.
         * ----------------------------------------------------
         */

        for (
            let i = 0;
            i < KeyDeriver.KEY_LENGTH_BYTES;
            i++
        ) {

            key[i] =
                (
                    0xA5 ^
                    ((i * 0x3D) & 0xFF)
                ) & 0xFF;
        }


        /*
         * ----------------------------------------------------
         * FIRST PASS
         *
         * Fold every UTF-8 input byte into one of the
         * sixteen output bytes.
         * ----------------------------------------------------
         */

        for (
            let i = 0;
            i < bytes.length;
            i++
        ) {

            const position =
                i %
                KeyDeriver.KEY_LENGTH_BYTES;


            const byte =
                bytes[i];


            /*
             * Rotate according to the absolute position.
             */

            const rotated =
                KeyDeriver.rotateByteLeft(
                    byte,
                    i % 8
                );


            /*
             * Position-dependent value.
             */

            const positionMix =
                (
                    (i * 31) +
                    (position * 17)
                ) & 0xFF;


            key[position] =
                (
                    key[position] ^
                    rotated ^
                    positionMix
                ) & 0xFF;
        }


        /*
         * ----------------------------------------------------
         * EXTENSION / DIFFUSION
         * ----------------------------------------------------
         *
         * This pass is especially important for strings
         * shorter than sixteen bytes.
         *
         * Every output position is influenced by:
         *
         *      an input byte
         *      the previous key byte
         *      another key position
         *      its own position
         * ----------------------------------------------------
         */

        for (
            let i = 0;
            i < KeyDeriver.KEY_LENGTH_BYTES;
            i++
        ) {

            const sourceByte =
                bytes[
                    i %
                    bytes.length
                ];


            const previous =
                key[
                    (
                        i +
                        KeyDeriver.KEY_LENGTH_BYTES -
                        1
                    ) %
                    KeyDeriver.KEY_LENGTH_BYTES
                ];


            const opposite =
                key[
                    (
                        i + 7
                    ) %
                    KeyDeriver.KEY_LENGTH_BYTES
                ];


            const rotatedSource =
                KeyDeriver.rotateByteLeft(
                    sourceByte,
                    (i + 3) % 8
                );


            key[i] =
                (
                    key[i] ^
                    rotatedSource ^
                    previous ^
                    KeyDeriver.rotateByteLeft(
                        opposite,
                        1
                    ) ^
                    ((i * 29) & 0xFF)
                ) & 0xFF;
        }


        /*
         * ----------------------------------------------------
         * ADDITIONAL MIXING ROUNDS
         * ----------------------------------------------------
         *
         * Run several cheap diffusion rounds so changes in
         * one input byte affect more than one output position.
         *
         * Again: this improves the experiment visually but
         * does NOT make this a cryptographically secure KDF.
         * ----------------------------------------------------
         */

        for (
            let round = 0;
            round < 4;
            round++
        ) {

            const previousKey =
                Uint8Array.from(
                    key
                );


            for (
                let i = 0;
                i < KeyDeriver.KEY_LENGTH_BYTES;
                i++
            ) {

                const left =
                    previousKey[
                        (
                            i +
                            KeyDeriver.KEY_LENGTH_BYTES -
                            1
                        ) %
                        KeyDeriver.KEY_LENGTH_BYTES
                    ];


                const right =
                    previousKey[
                        (
                            i + 1
                        ) %
                        KeyDeriver.KEY_LENGTH_BYTES
                    ];


                const distant =
                    previousKey[
                        (
                            i + 5
                        ) %
                        KeyDeriver.KEY_LENGTH_BYTES
                    ];


                key[i] =
                    (
                        previousKey[i] ^

                        KeyDeriver.rotateByteLeft(
                            left,
                            1
                        ) ^

                        KeyDeriver.rotateByteLeft(
                            right,
                            3
                        ) ^

                        KeyDeriver.rotateByteLeft(
                            distant,
                            5
                        ) ^

                        (
                            (
                                round + 1
                            ) *
                            (
                                i + 17
                            )
                        )
                    ) & 0xFF;
            }
        }


        return key;
    }


    /**
     * ========================================================
     * PBKDF2
     * ========================================================
     *
     * Uses the browser Web Crypto API:
     *
     *      Password
     *          ↓
     *      UTF-8
     *          ↓
     *      PBKDF2
     *          ↓
     *      HMAC-SHA-256
     *          ↓
     *      128-bit AES key
     *
     * A random salt is generated unless one is supplied.
     *
     * IMPORTANT:
     *
     * The salt must be stored alongside encrypted data if the
     * same key needs to be reconstructed later.
     *
     * ========================================================
     */

    static async derivePBKDF2(
        input,
        options = {}
    ) {

        if (
            typeof crypto === "undefined" ||
            !crypto.subtle
        ) {

            throw new Error(
                "Web Crypto API is not available in this browser."
            );
        }


        const passwordBytes =
            KeyDeriver.stringToBytes(
                input
            );


        /*
         * Use provided salt when decrypting.
         *
         * Otherwise generate a fresh random salt.
         */

        let salt;


        if (options.salt) {

            salt =
                Uint8Array.from(
                    options.salt
                );

        } else {

            salt =
                new Uint8Array(
                    KeyDeriver.PBKDF2_SALT_LENGTH
                );


            crypto.getRandomValues(
                salt
            );
        }


        const iterations =
            options.iterations ||
            KeyDeriver.PBKDF2_ITERATIONS;


        /*
         * Import password bytes as PBKDF2 key material.
         */

        const keyMaterial =
            await crypto.subtle.importKey(

                "raw",

                passwordBytes,

                {
                    name:
                        "PBKDF2"
                },

                false,

                [
                    "deriveBits"
                ]
            );


        /*
         * Derive exactly 128 bits.
         */

        const derivedBits =
            await crypto.subtle.deriveBits(

                {

                    name:
                        "PBKDF2",

                    salt:
                        salt,

                    iterations:
                        iterations,

                    hash:
                        "SHA-256"

                },

                keyMaterial,

                KeyDeriver.KEY_LENGTH_BITS
            );


        const key =
            new Uint8Array(
                derivedBits
            );


        return {

            method:
                "pbkdf2",

            key:
                key,

            salt:
                salt,

            iterations:
                iterations

        };
    }


    /**
     * ========================================================
     * UTF-8 STRING -> BYTES
     * ========================================================
     */

    static stringToBytes(input) {

        /*
         * Use the browser's native UTF-8 TextEncoder.
         *
         * Note that our project also has TextEncoder.js.
         * That class can provide higher-level message handling,
         * but this low-level conversion deliberately has no
         * dependency on it.
         */

        const encoder =
            new window.TextEncoder();


        return encoder.encode(
            input
        );
    }


    /**
     * ========================================================
     * ROTATE BYTE LEFT
     * ========================================================
     *
     * Example:
     *
     *      10110001
     *
     * rotate left by 2:
     *
     *      11000110
     *
     * ========================================================
     */

    static rotateByteLeft(
        value,
        amount
    ) {

        value &= 0xFF;

        amount %= 8;


        if (amount === 0) {
            return value;
        }


        return (
            (
                (value << amount) |
                (value >>> (8 - amount))
            )
            & 0xFF
        );
    }


    /**
     * ========================================================
     * ROTATE BYTE RIGHT
     * ========================================================
     */

    static rotateByteRight(
        value,
        amount
    ) {

        value &= 0xFF;

        amount %= 8;


        if (amount === 0) {
            return value;
        }


        return (
            (
                (value >>> amount) |
                (value << (8 - amount))
            )
            & 0xFF
        );
    }


    /**
     * ========================================================
     * KEY -> HEX
     * ========================================================
     *
     * Returns:
     *
     *      AB 31 94 ...
     *
     * AESUtils is used when available, otherwise this class
     * performs the conversion itself.
     *
     * ========================================================
     */

    static keyToHex(key) {

        KeyDeriver.validateKey(
            key
        );


        if (
            typeof AESUtils !== "undefined" &&
            typeof AESUtils.bytesToHex ===
                "function"
        ) {

            return AESUtils.bytesToHex(
                key
            );
        }


        return Array.from(key)
            .map(
                byte =>
                    byte
                        .toString(16)
                        .padStart(2, "0")
                        .toUpperCase()
            )
            .join(" ");
    }


    /**
     * ========================================================
     * KEY -> BINARY
     * ========================================================
     *
     * Gives us the actual 128 bits for visualisation.
     *
     * ========================================================
     */

    static keyToBinary(key) {

        KeyDeriver.validateKey(
            key
        );


        return Array.from(key)
            .map(
                byte =>
                    byte
                        .toString(2)
                        .padStart(8, "0")
            )
            .join(" ");
    }


    /**
     * ========================================================
     * KEY INFORMATION
     * ========================================================
     *
     * Convenient object for app.js and the key display.
     *
     * ========================================================
     */

    static getKeyInfo(key) {

        KeyDeriver.validateKey(
            key
        );


        return {

            bytes:
                Uint8Array.from(
                    key
                ),

            byteLength:
                key.length,

            bitLength:
                key.length * 8,

            hex:
                KeyDeriver.keyToHex(
                    key
                ),

            binary:
                KeyDeriver.keyToBinary(
                    key
                )

        };
    }


    /**
     * ========================================================
     * SALT -> HEX
     * ========================================================
     *
     * Useful when app.js needs to display or persist a
     * PBKDF2 salt.
     *
     * ========================================================
     */

    static saltToHex(salt) {

        if (!salt) {
            return "";
        }


        return Array.from(salt)
            .map(
                byte =>
                    byte
                        .toString(16)
                        .padStart(2, "0")
                        .toUpperCase()
            )
            .join("");
    }


    /**
     * ========================================================
     * HEX -> SALT
     * ========================================================
     *
     * Allows a previously generated PBKDF2 salt to be
     * reconstructed.
     *
     * ========================================================
     */

    static hexToSalt(hex) {

        if (typeof hex !== "string") {

            throw new Error(
                "Salt must be a hexadecimal string."
            );
        }


        const cleaned =
            hex.replace(
                /\s/g,
                ""
            );


        if (
            cleaned.length === 0 ||
            cleaned.length % 2 !== 0 ||
            !/^[0-9A-Fa-f]+$/.test(cleaned)
        ) {

            throw new Error(
                "Invalid hexadecimal salt."
            );
        }


        const salt =
            new Uint8Array(
                cleaned.length / 2
            );


        for (
            let i = 0;
            i < salt.length;
            i++
        ) {

            salt[i] =
                parseInt(
                    cleaned.substring(
                        i * 2,
                        (i * 2) + 2
                    ),
                    16
                );
        }


        return salt;
    }


    /**
     * ========================================================
     * VALIDATE AES KEY
     * ========================================================
     */

    static validateKey(key) {

        if (!key) {

            throw new Error(
                "AES key is missing."
            );
        }


        if (key.length !== 16) {

            throw new Error(
                "AES-128 requires exactly 16 key bytes."
            );
        }


        return true;
    }


    /**
     * ========================================================
     * DEMONSTRATE XOR DERIVATION
     * ========================================================
     *
     * Useful from the browser console while developing:
     *
     *      KeyDeriver.testXOR("hello");
     *
     * ========================================================
     */

    static testXOR(input) {

        const key =
            KeyDeriver.deriveXOR(
                input
            );


        const result = {

            input:
                input,

            inputBytes:
                Array.from(
                    KeyDeriver.stringToBytes(
                        input
                    )
                ),

            key:
                key,

            hex:
                KeyDeriver.keyToHex(
                    key
                ),

            binary:
                KeyDeriver.keyToBinary(
                    key
                ),

            bytes:
                key.length,

            bits:
                key.length * 8

        };


        console.log(
            "Experimental 128-bit key derivation:",
            result
        );


        return result;
    }

}