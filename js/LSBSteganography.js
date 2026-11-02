/**
 * ============================================================
 * LSBSteganography
 * ============================================================
 *
 * Least-Significant-Bit image steganography.
 *
 * Stores arbitrary binary data inside the RGB channels of
 * browser ImageData.
 *
 * One bit is stored in each:
 *
 *      Red
 *      Green
 *      Blue
 *
 * Alpha is NEVER modified.
 *
 * Therefore each pixel stores:
 *
 *      3 hidden bits
 *
 *
 * PAYLOAD FORMAT
 * ------------------------------------------------------------
 *
 * The hidden byte stream is:
 *
 *      +----------------------+ 4 bytes
 *      | MAGIC SIGNATURE      |
 *      +----------------------+ 4 bytes
 *      | PAYLOAD LENGTH       |
 *      +----------------------+ N bytes
 *      | PAYLOAD              |
 *      +----------------------+
 *
 * Total header:
 *
 *      8 bytes
 *
 *
 * MAGIC:
 *
 *      "MPLS"
 *
 * This lets us distinguish one of our steganographic images
 * from an ordinary image.
 *
 *
 * LENGTH:
 *
 *      Unsigned 32-bit integer
 *      Big-endian
 *
 *
 * IMPORTANT:
 *
 * The resulting image must be saved losslessly, preferably
 * as PNG. JPEG compression can destroy the hidden LSB data.
 *
 * ============================================================
 */

class LSBSteganography {


    /**
     * ========================================================
     * CONSTANTS
     * ========================================================
     */

    static MAGIC =
        new Uint8Array([
            0x4D, // M
            0x50, // P
            0x4C, // L
            0x53  // S
        ]);


    static MAGIC_LENGTH = 4;

    static LENGTH_LENGTH = 4;

    static HEADER_LENGTH =
        LSBSteganography.MAGIC_LENGTH +
        LSBSteganography.LENGTH_LENGTH;


    static CHANNELS_PER_PIXEL = 3;

    static BITS_PER_BYTE = 8;


    /**
     * ========================================================
     * HIDE DATA
     * ========================================================
     *
     * @param {ImageData} imageData
     * @param {Uint8Array|Array} payload
     *
     * @returns {ImageData}
     *
     * The supplied ImageData is NOT modified.
     *
     * A new ImageData object is returned.
     *
     * ========================================================
     */

    static hideData(
        imageData,
        payload
    ) {

        LSBSteganography.validateImageData(
            imageData
        );


        if (!payload) {

            throw new Error(
                "No payload was supplied."
            );
        }


        const payloadBytes =
            Uint8Array.from(
                payload
            );


        /*
         * ----------------------------------------------------
         * CAPACITY CHECK
         * ----------------------------------------------------
         */

        const capacity =
            LSBSteganography.getPayloadCapacity(
                imageData
            );


        if (
            payloadBytes.length >
            capacity
        ) {

            throw new Error(
                "Payload is too large for this image. " +
                "Required: " +
                payloadBytes.length +
                " bytes. Capacity: " +
                capacity +
                " bytes."
            );
        }


        /*
         * ----------------------------------------------------
         * CREATE HEADER
         * ----------------------------------------------------
         */

        const header =
            LSBSteganography.createHeader(
                payloadBytes.length
            );


        /*
         * Complete hidden stream:
         *
         *      header + payload
         */

        const hiddenBytes =
            LSBSteganography.concatBytes(
                header,
                payloadBytes
            );


        /*
         * Work on a copy.
         *
         * Never modify the original uploaded image.
         */

        const output =
            LSBSteganography.cloneImageData(
                imageData
            );


        /*
         * ----------------------------------------------------
         * WRITE BITS
         * ----------------------------------------------------
         */

        LSBSteganography.writeBytes(
            output,
            hiddenBytes
        );


        return output;
    }


    /**
     * ========================================================
     * EXTRACT DATA
     * ========================================================
     *
     * Reads:
     *
     *      magic
     *      length
     *      payload
     *
     * from an ImageData object.
     *
     * ========================================================
     */

    static extractData(imageData) {

        LSBSteganography.validateImageData(
            imageData
        );


        /*
         * The image must at least be large enough to contain
         * our eight-byte header.
         */

        if (
            LSBSteganography.getRawCapacity(
                imageData
            ) <
            LSBSteganography.HEADER_LENGTH
        ) {

            throw new Error(
                "Image is too small to contain a steganography header."
            );
        }


        /*
         * ----------------------------------------------------
         * READ HEADER
         * ----------------------------------------------------
         */

        const header =
            LSBSteganography.readBytes(
                imageData,
                LSBSteganography.HEADER_LENGTH
            );


        /*
         * Verify magic identifier.
         */

        if (
            !LSBSteganography.hasValidMagic(
                header
            )
        ) {

            throw new Error(
                "No Midlife Programmer LSB payload was found in this image."
            );
        }


        /*
         * Decode payload length.
         */

        const payloadLength =
            LSBSteganography.decodeLength(
                header
            );


        /*
         * Make sure the claimed payload length is possible.
         *
         * This prevents corrupted/random image bits from
         * causing absurd allocations.
         */

        const capacity =
            LSBSteganography.getPayloadCapacity(
                imageData
            );


        if (
            payloadLength >
            capacity
        ) {

            throw new Error(
                "The hidden payload header is invalid or corrupted."
            );
        }


        /*
         * ----------------------------------------------------
         * READ COMPLETE STREAM
         * ----------------------------------------------------
         */

        const totalBytes =
            LSBSteganography.HEADER_LENGTH +
            payloadLength;


        const complete =
            LSBSteganography.readBytes(
                imageData,
                totalBytes
            );


        /*
         * Strip the eight-byte header.
         */

        return complete.slice(
            LSBSteganography.HEADER_LENGTH
        );
    }


    /**
     * ========================================================
     * CREATE HEADER
     * ========================================================
     */

    static createHeader(payloadLength) {

        if (
            !Number.isInteger(payloadLength) ||
            payloadLength < 0
        ) {

            throw new Error(
                "Invalid payload length."
            );
        }


        if (
            payloadLength >
            0xFFFFFFFF
        ) {

            throw new Error(
                "Payload exceeds the 32-bit length limit."
            );
        }


        const header =
            new Uint8Array(
                LSBSteganography.HEADER_LENGTH
            );


        /*
         * First four bytes:
         *
         *      M P L S
         */

        header.set(
            LSBSteganography.MAGIC,
            0
        );


        /*
         * Next four bytes:
         *
         *      unsigned 32-bit payload length
         *
         * Big-endian.
         */

        header[4] =
            (
                payloadLength >>> 24
            ) & 0xFF;


        header[5] =
            (
                payloadLength >>> 16
            ) & 0xFF;


        header[6] =
            (
                payloadLength >>> 8
            ) & 0xFF;


        header[7] =
            payloadLength & 0xFF;


        return header;
    }


    /**
     * ========================================================
     * DECODE LENGTH
     * ========================================================
     */

    static decodeLength(header) {

        if (
            !header ||
            header.length <
            LSBSteganography.HEADER_LENGTH
        ) {

            throw new Error(
                "Invalid steganography header."
            );
        }


        /*
         * JavaScript bitwise operations are signed 32-bit.
         *
         * >>> 0 converts the final result back to an unsigned
         * 32-bit integer.
         */

        return (
            (
                (header[4] << 24) |
                (header[5] << 16) |
                (header[6] << 8) |
                header[7]
            )
            >>> 0
        );
    }


    /**
     * ========================================================
     * VALIDATE MAGIC
     * ========================================================
     */

    static hasValidMagic(header) {

        if (
            !header ||
            header.length <
            LSBSteganography.MAGIC_LENGTH
        ) {

            return false;
        }


        for (
            let i = 0;
            i <
            LSBSteganography.MAGIC_LENGTH;
            i++
        ) {

            if (
                header[i] !==
                LSBSteganography.MAGIC[i]
            ) {

                return false;
            }
        }


        return true;
    }


    /**
     * ========================================================
     * WRITE BYTE STREAM
     * ========================================================
     *
     * Each byte:
     *
     *      b7 b6 b5 b4 b3 b2 b1 b0
     *
     * is written one bit at a time into RGB LSBs.
     *
     * Example channel:
     *
     *      original:
     *
     *          11010110
     *
     *      hidden bit = 1
     *
     *      result:
     *
     *          11010111
     *
     * Only the final bit changes.
     *
     * ========================================================
     */

    static writeBytes(
        imageData,
        bytes
    ) {

        const pixels =
            imageData.data;


        let byteIndex = 0;

        let bitIndex = 7;


        /*
         * ImageData:
         *
         *      R G B A R G B A ...
         *
         * We skip every alpha channel.
         */

        for (
            let pixelIndex = 0;
            pixelIndex < pixels.length;
            pixelIndex++
        ) {

            /*
             * Every fourth channel is alpha:
             *
             *      index % 4 === 3
             */

            if (
                pixelIndex % 4 === 3
            ) {

                continue;
            }


            /*
             * Finished writing all bytes.
             */

            if (
                byteIndex >=
                bytes.length
            ) {

                break;
            }


            /*
             * Extract current payload bit.
             */

            const bit =
                (
                    bytes[byteIndex] >>
                    bitIndex
                ) & 1;


            /*
             * Clear channel LSB:
             *
             *      value & 11111110
             *
             * Then insert hidden bit.
             */

            pixels[pixelIndex] =
                (
                    pixels[pixelIndex] &
                    0xFE
                ) |
                bit;


            /*
             * Move to next bit.
             */

            bitIndex--;


            /*
             * Finished current byte.
             */

            if (bitIndex < 0) {

                bitIndex = 7;

                byteIndex++;
            }
        }


        if (
            byteIndex <
            bytes.length
        ) {

            throw new Error(
                "Image capacity was exhausted while writing hidden data."
            );
        }
    }


    /**
     * ========================================================
     * READ BYTE STREAM
     * ========================================================
     *
     * Reads the specified number of bytes from RGB LSBs.
     *
     * ========================================================
     */

    static readBytes(
        imageData,
        byteCount
    ) {

        LSBSteganography.validateImageData(
            imageData
        );


        if (
            !Number.isInteger(byteCount) ||
            byteCount < 0
        ) {

            throw new Error(
                "Invalid byte count."
            );
        }


        const rawCapacity =
            LSBSteganography.getRawCapacity(
                imageData
            );


        if (
            byteCount >
            rawCapacity
        ) {

            throw new Error(
                "Requested data exceeds the image capacity."
            );
        }


        const output =
            new Uint8Array(
                byteCount
            );


        const pixels =
            imageData.data;


        let byteIndex = 0;

        let bitIndex = 7;


        for (
            let pixelIndex = 0;
            pixelIndex < pixels.length;
            pixelIndex++
        ) {

            /*
             * Ignore alpha.
             */

            if (
                pixelIndex % 4 === 3
            ) {

                continue;
            }


            if (
                byteIndex >=
                byteCount
            ) {

                break;
            }


            /*
             * Extract channel's least-significant bit.
             */

            const bit =
                pixels[pixelIndex] & 1;


            /*
             * Insert into output byte.
             */

            output[byteIndex] |=
                bit << bitIndex;


            bitIndex--;


            if (bitIndex < 0) {

                bitIndex = 7;

                byteIndex++;
            }
        }


        if (
            byteIndex <
            byteCount
        ) {

            throw new Error(
                "Image ended before all hidden data could be read."
            );
        }


        return output;
    }


    /**
     * ========================================================
     * CHECK FOR HIDDEN DATA
     * ========================================================
     *
     * Allows app.js to inspect an uploaded image without
     * throwing an exception.
     *
     * ========================================================
     */

    static containsPayload(imageData) {

        try {

            if (
                LSBSteganography.getRawCapacity(
                    imageData
                ) <
                LSBSteganography.HEADER_LENGTH
            ) {

                return false;
            }


            const magic =
                LSBSteganography.readBytes(
                    imageData,
                    LSBSteganography.MAGIC_LENGTH
                );


            return (
                LSBSteganography.hasValidMagic(
                    magic
                )
            );

        } catch (error) {

            return false;
        }
    }


    /**
     * ========================================================
     * GET PAYLOAD INFORMATION
     * ========================================================
     *
     * Reads only the header.
     *
     * Does not extract the complete payload.
     *
     * ========================================================
     */

    static getPayloadInfo(imageData) {

        LSBSteganography.validateImageData(
            imageData
        );


        if (
            !LSBSteganography.containsPayload(
                imageData
            )
        ) {

            return {

                found:
                    false,

                length:
                    0

            };
        }


        const header =
            LSBSteganography.readBytes(
                imageData,
                LSBSteganography.HEADER_LENGTH
            );


        const length =
            LSBSteganography.decodeLength(
                header
            );


        return {

            found:
                true,

            length:
                length,

            headerBytes:
                LSBSteganography.HEADER_LENGTH,

            totalBytes:
                length +
                LSBSteganography.HEADER_LENGTH

        };
    }


    /**
     * ========================================================
     * RAW CAPACITY
     * ========================================================
     *
     * 3 bits per pixel.
     *
     * Returns total whole bytes available INCLUDING header.
     *
     * ========================================================
     */

    static getRawCapacity(imageData) {

        LSBSteganography.validateImageData(
            imageData
        );


        const pixels =
            imageData.width *
            imageData.height;


        const bits =
            pixels *
            LSBSteganography.CHANNELS_PER_PIXEL;


        return Math.floor(
            bits /
            LSBSteganography.BITS_PER_BYTE
        );
    }


    /**
     * ========================================================
     * PAYLOAD CAPACITY
     * ========================================================
     *
     * Removes our eight-byte metadata header.
     *
     * ========================================================
     */

    static getPayloadCapacity(imageData) {

        return Math.max(

            0,

            LSBSteganography.getRawCapacity(
                imageData
            ) -
            LSBSteganography.HEADER_LENGTH

        );
    }


    /**
     * ========================================================
     * CAPACITY INFORMATION
     * ========================================================
     */

    static getCapacityInfo(imageData) {

        LSBSteganography.validateImageData(
            imageData
        );


        const pixels =
            imageData.width *
            imageData.height;


        const bits =
            pixels *
            LSBSteganography.CHANNELS_PER_PIXEL;


        const rawBytes =
            Math.floor(
                bits / 8
            );


        const payloadBytes =
            Math.max(
                0,
                rawBytes -
                LSBSteganography.HEADER_LENGTH
            );


        return {

            width:
                imageData.width,

            height:
                imageData.height,

            pixels:
                pixels,

            bits:
                bits,

            rawBytes:
                rawBytes,

            headerBytes:
                LSBSteganography.HEADER_LENGTH,

            payloadBytes:
                payloadBytes

        };
    }


    /**
     * ========================================================
     * USAGE INFORMATION
     * ========================================================
     *
     * Useful for the capacity meter in index.html.
     *
     * ========================================================
     */

    static getUsageInfo(
        imageData,
        payloadLength
    ) {

        const capacity =
            LSBSteganography.getPayloadCapacity(
                imageData
            );


        const used =
            Math.max(
                0,
                payloadLength
            );


        const percentage =
            capacity === 0
                ? 0
                : (
                    used /
                    capacity
                ) * 100;


        return {

            usedBytes:
                used,

            capacityBytes:
                capacity,

            remainingBytes:
                Math.max(
                    0,
                    capacity - used
                ),

            percentage:
                Math.min(
                    100,
                    percentage
                ),

            fits:
                used <= capacity

        };
    }


    /**
     * ========================================================
     * TEXT HELPER
     * ========================================================
     *
     * This helper is useful during testing.
     *
     * Normally TextEncoder.js will own text conversion.
     *
     * ========================================================
     */

    static hideText(
        imageData,
        text
    ) {

        if (
            typeof text !== "string"
        ) {

            throw new Error(
                "Hidden message must be a string."
            );
        }


        const encoder =
            new window.TextEncoder();


        const bytes =
            encoder.encode(
                text
            );


        return LSBSteganography.hideData(
            imageData,
            bytes
        );
    }


    /**
     * ========================================================
     * TEXT EXTRACTION HELPER
     * ========================================================
     */

    static extractText(imageData) {

        const bytes =
            LSBSteganography.extractData(
                imageData
            );


        const decoder =
            new window.TextDecoder(
                "utf-8",
                {
                    fatal: true
                }
            );


        try {

            return decoder.decode(
                bytes
            );

        } catch (error) {

            throw new Error(
                "Hidden data was found, but it is not valid UTF-8 text."
            );
        }
    }


    /**
     * ========================================================
     * CLONE IMAGE DATA
     * ========================================================
     */

    static cloneImageData(imageData) {

        LSBSteganography.validateImageData(
            imageData
        );


        return new ImageData(

            new Uint8ClampedArray(
                imageData.data
            ),

            imageData.width,

            imageData.height
        );
    }


    /**
     * ========================================================
     * CONCATENATE BYTE ARRAYS
     * ========================================================
     */

    static concatBytes(...arrays) {

        let length = 0;


        for (const array of arrays) {

            if (array) {
                length += array.length;
            }
        }


        const output =
            new Uint8Array(
                length
            );


        let offset = 0;


        for (const array of arrays) {

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
     * COMPARE IMAGES
     * ========================================================
     *
     * Calculates how many RGB channels were altered by the
     * steganography operation.
     *
     * Since only the LSB is changed, each altered channel
     * should differ by exactly 1.
     *
     * ========================================================
     */

    static compareImages(
        original,
        modified
    ) {

        LSBSteganography.validateImageData(
            original
        );

        LSBSteganography.validateImageData(
            modified
        );


        if (
            original.width !==
                modified.width ||
            original.height !==
                modified.height
        ) {

            throw new Error(
                "Images must have identical dimensions."
            );
        }


        let changedChannels = 0;

        let changedPixels = 0;

        let maximumDifference = 0;


        for (
            let i = 0;
            i < original.data.length;
            i += 4
        ) {

            let pixelChanged = false;


            for (
                let channel = 0;
                channel < 3;
                channel++
            ) {

                const difference =
                    Math.abs(
                        original.data[
                            i + channel
                        ] -
                        modified.data[
                            i + channel
                        ]
                    );


                if (difference > 0) {

                    changedChannels++;

                    pixelChanged = true;


                    maximumDifference =
                        Math.max(
                            maximumDifference,
                            difference
                        );
                }
            }


            if (pixelChanged) {
                changedPixels++;
            }
        }


        const totalPixels =
            original.width *
            original.height;


        return {

            totalPixels:
                totalPixels,

            changedPixels:
                changedPixels,

            changedChannels:
                changedChannels,

            changedPixelPercentage:
                totalPixels === 0
                    ? 0
                    : (
                        changedPixels /
                        totalPixels
                    ) * 100,

            maximumChannelDifference:
                maximumDifference

        };
    }


    /**
     * ========================================================
     * VALIDATION
     * ========================================================
     */

    static validateImageData(imageData) {

        if (
            !imageData ||
            !(imageData instanceof ImageData)
        ) {

            throw new Error(
                "Valid ImageData is required."
            );
        }


        if (
            imageData.width <= 0 ||
            imageData.height <= 0
        ) {

            throw new Error(
                "Image dimensions must be greater than zero."
            );
        }


        if (
            imageData.data.length !==
            imageData.width *
            imageData.height *
            4
        ) {

            throw new Error(
                "ImageData contains an invalid RGBA buffer."
            );
        }


        return true;
    }

}