/**
 * ============================================================
 * CryptoTextEncoder
 * ============================================================
 *
 * Text / byte conversion utilities for the Encryption &
 * Steganography Lab.
 *
 * IMPORTANT:
 *
 * Browsers already provide:
 *
 *      window.TextEncoder
 *      window.TextDecoder
 *
 * Therefore this project class is called CryptoTextEncoder
 * even though the filename remains TextEncoder.js.
 *
 *
 * Responsibilities:
 *
 *      UTF-8 text -> bytes
 *      bytes -> UTF-8 text
 *
 *      bytes -> hexadecimal
 *      hexadecimal -> bytes
 *
 *      bytes -> Base64
 *      Base64 -> bytes
 *
 *      bytes -> binary
 *      binary -> bytes
 *
 *      PKCS#7 padding
 *      PKCS#7 unpadding
 *
 *      split data into 16-byte AES blocks
 *      join AES blocks
 *
 * ============================================================
 */

class CryptoTextEncoder {


    /**
     * AES block size.
     *
     * 16 bytes = 128 bits.
     */
    static AES_BLOCK_SIZE = 16;


    /**
     * ========================================================
     * TEXT -> UTF-8 BYTES
     * ========================================================
     *
     * Example:
     *
     *      "Hello"
     *
     * becomes:
     *
     *      48 65 6C 6C 6F
     *
     * Unicode characters may require multiple bytes.
     *
     * ========================================================
     */

    static encode(text) {

        if (typeof text !== "string") {

            throw new Error(
                "Text input must be a string."
            );
        }


        const encoder =
            new window.TextEncoder();


        return encoder.encode(
            text
        );
    }


    /**
     * Alias with a more explicit name.
     */
    static textToBytes(text) {

        return CryptoTextEncoder.encode(
            text
        );
    }


    /**
     * ========================================================
     * UTF-8 BYTES -> TEXT
     * ========================================================
     */

    static decode(
        bytes,
        fatal = true
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        const decoder =
            new window.TextDecoder(
                "utf-8",
                {
                    fatal: fatal
                }
            );


        try {

            return decoder.decode(
                bytes
            );

        } catch (error) {

            throw new Error(
                "Byte sequence does not contain valid UTF-8 text."
            );
        }
    }


    /**
     * Alias.
     */
    static bytesToText(bytes) {

        return CryptoTextEncoder.decode(
            bytes
        );
    }


    /**
     * ========================================================
     * TEXT BYTE LENGTH
     * ========================================================
     *
     * JavaScript string.length counts UTF-16 code units,
     * not UTF-8 bytes.
     *
     * For cryptography and steganography we need the actual
     * byte length.
     *
     * ========================================================
     */

    static getByteLength(text) {

        return CryptoTextEncoder
            .encode(text)
            .length;
    }


    /**
     * ========================================================
     * BYTES -> HEX
     * ========================================================
     *
     * Example:
     *
     *      [72, 101, 108]
     *
     * becomes:
     *
     *      "48 65 6C"
     *
     * ========================================================
     */

    static bytesToHex(
        bytes,
        separator = " "
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        return Array.from(bytes)
            .map(
                byte =>
                    byte
                        .toString(16)
                        .padStart(2, "0")
                        .toUpperCase()
            )
            .join(separator);
    }


    /**
     * ========================================================
     * HEX -> BYTES
     * ========================================================
     *
     * Accepts:
     *
     *      48656C6C6F
     *
     *      48 65 6C 6C 6F
     *
     *      48:65:6C:6C:6F
     *
     *      48-65-6C-6C-6F
     *
     * ========================================================
     */

    static hexToBytes(hex) {

        if (typeof hex !== "string") {

            throw new Error(
                "Hexadecimal input must be a string."
            );
        }


        const cleaned =
            hex.replace(
                /[\s:_-]/g,
                ""
            );


        if (cleaned.length === 0) {

            return new Uint8Array(0);
        }


        if (
            cleaned.length % 2 !== 0
        ) {

            throw new Error(
                "Hexadecimal input must contain an even number of digits."
            );
        }


        if (
            !/^[0-9A-Fa-f]+$/.test(
                cleaned
            )
        ) {

            throw new Error(
                "Hexadecimal input contains invalid characters."
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
     * BYTES -> BASE64
     * ========================================================
     *
     * Base64 is useful for displaying ciphertext because raw
     * encrypted bytes are not valid text.
     *
     * ========================================================
     */

    static bytesToBase64(bytes) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        /*
         * Build the binary string in chunks.
         *
         * Avoid:
         *
         *      String.fromCharCode(...hugeArray)
         *
         * because spreading a very large array can exceed
         * JavaScript's argument limit.
         */

        const chunkSize =
            0x8000;


        let binary = "";


        for (
            let offset = 0;
            offset < bytes.length;
            offset += chunkSize
        ) {

            const chunk =
                bytes.subarray
                    ? bytes.subarray(
                        offset,
                        Math.min(
                            offset + chunkSize,
                            bytes.length
                        )
                    )
                    : Uint8Array.from(
                        bytes.slice(
                            offset,
                            Math.min(
                                offset + chunkSize,
                                bytes.length
                            )
                        )
                    );


            binary +=
                String.fromCharCode(
                    ...chunk
                );
        }


        return window.btoa(
            binary
        );
    }


    /**
     * ========================================================
     * BASE64 -> BYTES
     * ========================================================
     */

    static base64ToBytes(base64) {

        if (
            typeof base64 !==
            "string"
        ) {

            throw new Error(
                "Base64 input must be a string."
            );
        }


        /*
         * Remove whitespace so copied multiline Base64
         * remains valid.
         */

        const cleaned =
            base64.replace(
                /\s/g,
                ""
            );


        if (
            cleaned.length === 0
        ) {

            return new Uint8Array(0);
        }


        let binary;


        try {

            binary =
                window.atob(
                    cleaned
                );

        } catch (error) {

            throw new Error(
                "Invalid Base64 ciphertext."
            );
        }


        const output =
            new Uint8Array(
                binary.length
            );


        for (
            let i = 0;
            i < binary.length;
            i++
        ) {

            output[i] =
                binary.charCodeAt(i);
        }


        return output;
    }


    /**
     * ========================================================
     * BYTES -> BINARY
     * ========================================================
     *
     * Example:
     *
     *      41
     *
     * becomes:
     *
     *      01000001
     *
     * ========================================================
     */

    static bytesToBinary(
        bytes,
        separator = " "
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        return Array.from(bytes)
            .map(
                byte =>
                    byte
                        .toString(2)
                        .padStart(8, "0")
            )
            .join(separator);
    }


    /**
     * ========================================================
     * BINARY -> BYTES
     * ========================================================
     */

    static binaryToBytes(binary) {

        if (
            typeof binary !==
            "string"
        ) {

            throw new Error(
                "Binary input must be a string."
            );
        }


        const cleaned =
            binary.replace(
                /\s/g,
                ""
            );


        if (
            cleaned.length === 0
        ) {

            return new Uint8Array(0);
        }


        if (
            !/^[01]+$/.test(
                cleaned
            )
        ) {

            throw new Error(
                "Binary input may contain only 0 and 1."
            );
        }


        if (
            cleaned.length % 8 !== 0
        ) {

            throw new Error(
                "Binary input must contain complete 8-bit bytes."
            );
        }


        const output =
            new Uint8Array(
                cleaned.length / 8
            );


        for (
            let i = 0;
            i < output.length;
            i++
        ) {

            output[i] =
                parseInt(
                    cleaned.substring(
                        i * 8,
                        (i * 8) + 8
                    ),
                    2
                );
        }


        return output;
    }


    /**
     * ========================================================
     * PKCS#7 PADDING
     * ========================================================
     *
     * AES operates on blocks of exactly:
     *
     *      16 bytes
     *
     * Messages will almost never naturally be a multiple of
     * sixteen bytes.
     *
     * PKCS#7 fills the remaining bytes with a value equal to
     * the number of padding bytes.
     *
     *
     * Example:
     *
     *      message length = 13
     *
     *      padding needed = 3
     *
     * result:
     *
     *      ... 03 03 03
     *
     *
     * IMPORTANT:
     *
     * If the message is ALREADY exactly a multiple of 16,
     * an entire padding block is added:
     *
     *      10 10 10 10 ...
     *
     * sixteen times.
     *
     * This makes unpadding unambiguous.
     *
     * ========================================================
     */

    static addPKCS7Padding(
        bytes,
        blockSize =
            CryptoTextEncoder.AES_BLOCK_SIZE
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        CryptoTextEncoder.validateBlockSize(
            blockSize
        );


        let paddingLength =
            blockSize -
            (
                bytes.length %
                blockSize
            );


        /*
         * This will naturally be blockSize when the input
         * already aligns exactly.
         */


        const output =
            new Uint8Array(
                bytes.length +
                paddingLength
            );


        output.set(
            bytes,
            0
        );


        output.fill(
            paddingLength,
            bytes.length
        );


        return output;
    }


    /**
     * ========================================================
     * REMOVE PKCS#7 PADDING
     * ========================================================
     */

    static removePKCS7Padding(
        bytes,
        blockSize =
            CryptoTextEncoder.AES_BLOCK_SIZE
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        CryptoTextEncoder.validateBlockSize(
            blockSize
        );


        if (
            bytes.length === 0 ||
            bytes.length %
                blockSize !== 0
        ) {

            throw new Error(
                "Invalid padded AES data."
            );
        }


        const paddingLength =
            bytes[
                bytes.length - 1
            ];


        if (
            paddingLength < 1 ||
            paddingLength >
                blockSize
        ) {

            throw new Error(
                "Invalid PKCS#7 padding."
            );
        }


        /*
         * Every padding byte must contain exactly the same
         * padding length.
         */

        for (
            let i =
                bytes.length -
                paddingLength;

            i <
                bytes.length;

            i++
        ) {

            if (
                bytes[i] !==
                paddingLength
            ) {

                throw new Error(
                    "Invalid PKCS#7 padding."
                );
            }
        }


        return bytes.slice(
            0,
            bytes.length -
                paddingLength
        );
    }


    /**
     * ========================================================
     * SPLIT INTO AES BLOCKS
     * ========================================================
     *
     * Input must already be padded.
     *
     * ========================================================
     */

    static splitIntoBlocks(
        bytes,
        blockSize =
            CryptoTextEncoder.AES_BLOCK_SIZE
    ) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        CryptoTextEncoder.validateBlockSize(
            blockSize
        );


        if (
            bytes.length %
                blockSize !== 0
        ) {

            throw new Error(
                "Byte array length must be a multiple of the AES block size."
            );
        }


        const blocks = [];


        for (
            let offset = 0;
            offset < bytes.length;
            offset += blockSize
        ) {

            blocks.push(
                bytes.slice(
                    offset,
                    offset +
                        blockSize
                )
            );
        }


        return blocks;
    }


    /**
     * ========================================================
     * JOIN BLOCKS
     * ========================================================
     */

    static joinBlocks(
        blocks,
        blockSize =
            CryptoTextEncoder.AES_BLOCK_SIZE
    ) {

        if (
            !Array.isArray(
                blocks
            )
        ) {

            throw new Error(
                "AES blocks must be supplied as an array."
            );
        }


        CryptoTextEncoder.validateBlockSize(
            blockSize
        );


        if (
            blocks.length === 0
        ) {

            return new Uint8Array(0);
        }


        for (
            const block of blocks
        ) {

            CryptoTextEncoder.validateBytes(
                block
            );


            if (
                block.length !==
                blockSize
            ) {

                throw new Error(
                    "Every AES block must contain exactly " +
                    blockSize +
                    " bytes."
                );
            }
        }


        const output =
            new Uint8Array(
                blocks.length *
                blockSize
            );


        let offset = 0;


        for (
            const block of blocks
        ) {

            output.set(
                block,
                offset
            );


            offset +=
                blockSize;
        }


        return output;
    }


    /**
     * ========================================================
     * TEXT -> PADDED AES BLOCKS
     * ========================================================
     *
     * Convenience method:
     *
     *      text
     *          ↓
     *      UTF-8
     *          ↓
     *      PKCS#7
     *          ↓
     *      16-byte blocks
     *
     * ========================================================
     */

    static textToAESBlocks(text) {

        const bytes =
            CryptoTextEncoder.encode(
                text
            );


        const padded =
            CryptoTextEncoder
                .addPKCS7Padding(
                    bytes
                );


        return CryptoTextEncoder
            .splitIntoBlocks(
                padded
            );
    }


    /**
     * ========================================================
     * AES BLOCKS -> TEXT
     * ========================================================
     *
     * Reverse operation:
     *
     *      blocks
     *          ↓
     *      joined bytes
     *          ↓
     *      remove PKCS#7
     *          ↓
     *      UTF-8
     *
     * ========================================================
     */

    static aesBlocksToText(
        blocks
    ) {

        const joined =
            CryptoTextEncoder
                .joinBlocks(
                    blocks
                );


        const unpadded =
            CryptoTextEncoder
                .removePKCS7Padding(
                    joined
                );


        return CryptoTextEncoder.decode(
            unpadded
        );
    }


    /**
     * ========================================================
     * PAD TEXT
     * ========================================================
     *
     * Returns one complete object useful for encryption.
     *
     * ========================================================
     */

    static prepareTextForAES(
        text
    ) {

        const original =
            CryptoTextEncoder.encode(
                text
            );


        const padded =
            CryptoTextEncoder
                .addPKCS7Padding(
                    original
                );


        const blocks =
            CryptoTextEncoder
                .splitIntoBlocks(
                    padded
                );


        return {

            text:
                text,

            bytes:
                original,

            paddedBytes:
                padded,

            blocks:
                blocks,

            originalLength:
                original.length,

            paddedLength:
                padded.length,

            blockCount:
                blocks.length

        };
    }


    /**
     * ========================================================
     * CONCATENATE BYTE ARRAYS
     * ========================================================
     */

    static concatBytes(
        ...arrays
    ) {

        let totalLength = 0;


        for (
            const array of arrays
        ) {

            if (!array) {
                continue;
            }


            CryptoTextEncoder
                .validateBytes(
                    array
                );


            totalLength +=
                array.length;
        }


        const output =
            new Uint8Array(
                totalLength
            );


        let offset = 0;


        for (
            const array of arrays
        ) {

            if (!array) {
                continue;
            }


            output.set(
                array,
                offset
            );


            offset +=
                array.length;
        }


        return output;
    }


    /**
     * ========================================================
     * COPY BYTES
     * ========================================================
     */

    static copyBytes(bytes) {

        CryptoTextEncoder.validateBytes(
            bytes
        );


        return Uint8Array.from(
            bytes
        );
    }


    /**
     * ========================================================
     * BYTE ARRAYS EQUAL
     * ========================================================
     */

    static arraysEqual(
        first,
        second
    ) {

        if (
            !first ||
            !second
        ) {

            return false;
        }


        if (
            first.length !==
            second.length
        ) {

            return false;
        }


        for (
            let i = 0;
            i < first.length;
            i++
        ) {

            if (
                first[i] !==
                second[i]
            ) {

                return false;
            }
        }


        return true;
    }


    /**
     * ========================================================
     * TEXT INFORMATION
     * ========================================================
     *
     * Useful for debugging and visualisation.
     *
     * ========================================================
     */

    static getTextInfo(text) {

        const bytes =
            CryptoTextEncoder.encode(
                text
            );


        return {

            text:
                text,

            characters:
                Array.from(
                    text
                ).length,

            bytes:
                bytes,

            byteLength:
                bytes.length,

            bits:
                bytes.length * 8,

            hex:
                CryptoTextEncoder
                    .bytesToHex(
                        bytes
                    ),

            binary:
                CryptoTextEncoder
                    .bytesToBinary(
                        bytes
                    ),

            base64:
                CryptoTextEncoder
                    .bytesToBase64(
                        bytes
                    )

        };
    }


    /**
     * ========================================================
     * VALIDATE BYTE ARRAY
     * ========================================================
     */

    static validateBytes(bytes) {

        if (
            bytes === null ||
            bytes === undefined
        ) {

            throw new Error(
                "Byte array is required."
            );
        }


        if (
            !(
                bytes instanceof
                    Uint8Array
            ) &&
            !(
                bytes instanceof
                    Uint8ClampedArray
            ) &&
            !Array.isArray(bytes)
        ) {

            throw new Error(
                "Expected a byte array."
            );
        }


        for (
            let i = 0;
            i < bytes.length;
            i++
        ) {

            const value =
                bytes[i];


            if (
                !Number.isInteger(
                    value
                ) ||
                value < 0 ||
                value > 255
            ) {

                throw new Error(
                    "Byte arrays may contain only values from 0 to 255."
                );
            }
        }


        return true;
    }


    /**
     * ========================================================
     * VALIDATE BLOCK SIZE
     * ========================================================
     */

    static validateBlockSize(
        blockSize
    ) {

        if (
            !Number.isInteger(
                blockSize
            ) ||
            blockSize < 1 ||
            blockSize > 255
        ) {

            throw new Error(
                "Invalid block size."
            );
        }


        return true;
    }


    /**
     * ========================================================
     * SELF TEST
     * ========================================================
     *
     * Browser console:
     *
     *      CryptoTextEncoder.runSelfTest();
     *
     * ========================================================
     */

    static runSelfTest() {

        const originalText =
            "Hello AES! 🔐";


        /*
         * UTF-8 round trip.
         */

        const encoded =
            CryptoTextEncoder.encode(
                originalText
            );


        const decoded =
            CryptoTextEncoder.decode(
                encoded
            );


        const utf8Passed =
            decoded ===
            originalText;


        /*
         * Hex round trip.
         */

        const hex =
            CryptoTextEncoder
                .bytesToHex(
                    encoded,
                    ""
                );


        const fromHex =
            CryptoTextEncoder
                .hexToBytes(
                    hex
                );


        const hexPassed =
            CryptoTextEncoder
                .arraysEqual(
                    encoded,
                    fromHex
                );


        /*
         * Base64 round trip.
         */

        const base64 =
            CryptoTextEncoder
                .bytesToBase64(
                    encoded
                );


        const fromBase64 =
            CryptoTextEncoder
                .base64ToBytes(
                    base64
                );


        const base64Passed =
            CryptoTextEncoder
                .arraysEqual(
                    encoded,
                    fromBase64
                );


        /*
         * Binary round trip.
         */

        const binary =
            CryptoTextEncoder
                .bytesToBinary(
                    encoded,
                    ""
                );


        const fromBinary =
            CryptoTextEncoder
                .binaryToBytes(
                    binary
                );


        const binaryPassed =
            CryptoTextEncoder
                .arraysEqual(
                    encoded,
                    fromBinary
                );


        /*
         * PKCS#7 round trip.
         */

        const padded =
            CryptoTextEncoder
                .addPKCS7Padding(
                    encoded
                );


        const unpadded =
            CryptoTextEncoder
                .removePKCS7Padding(
                    padded
                );


        const paddingPassed =
            CryptoTextEncoder
                .arraysEqual(
                    encoded,
                    unpadded
                );


        /*
         * AES block splitting.
         */

        const blocks =
            CryptoTextEncoder
                .splitIntoBlocks(
                    padded
                );


        const joined =
            CryptoTextEncoder
                .joinBlocks(
                    blocks
                );


        const blockPassed =
            CryptoTextEncoder
                .arraysEqual(
                    padded,
                    joined
                );


        const result = {

            passed:
                utf8Passed &&
                hexPassed &&
                base64Passed &&
                binaryPassed &&
                paddingPassed &&
                blockPassed,

            utf8Passed:
                utf8Passed,

            hexPassed:
                hexPassed,

            base64Passed:
                base64Passed,

            binaryPassed:
                binaryPassed,

            paddingPassed:
                paddingPassed,

            blockPassed:
                blockPassed,

            original:
                originalText,

            byteLength:
                encoded.length,

            paddedLength:
                padded.length,

            blocks:
                blocks.length,

            hex:
                hex,

            base64:
                base64

        };


        console.log(
            "CryptoTextEncoder self-test:",
            result
        );


        return result;
    }

}