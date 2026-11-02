/**
 * ============================================================
 * ImageProcessor
 * ============================================================
 *
 * Handles image loading and pixel-level access for the
 * Encryption & Steganography Lab.
 *
 * Responsibilities:
 *
 *      Load PNG / JPEG files
 *      Convert uploaded files into Image objects
 *      Draw images onto Canvas
 *      Read RGBA ImageData
 *      Copy ImageData safely
 *      Calculate LSB storage capacity
 *      Render modified ImageData
 *      Export steganographic images as PNG
 *
 * LSBSteganography.js will perform the actual hiding and
 * extraction of data. This class only manages images/pixels.
 *
 * ============================================================
 */

class ImageProcessor {


    /**
     * --------------------------------------------------------
     * CONSTRUCTOR
     * --------------------------------------------------------
     */

    constructor() {

        this.image = null;

        this.file = null;

        this.width = 0;
        this.height = 0;

        this.originalImageData = null;
        this.currentImageData = null;
    }


    /**
     * ========================================================
     * LOAD FILE
     * ========================================================
     *
     * Loads an image selected using:
     *
     *      <input type="file">
     *
     * Returns a Promise so app.js can use:
     *
     *      await imageProcessor.loadFile(file);
     *
     * ========================================================
     */

    loadFile(file) {

        return new Promise(
            (resolve, reject) => {

                if (!file) {

                    reject(
                        new Error(
                            "No image file was selected."
                        )
                    );

                    return;
                }


                if (!file.type.startsWith("image/")) {

                    reject(
                        new Error(
                            "The selected file is not an image."
                        )
                    );

                    return;
                }


                this.file = file;


                const reader =
                    new FileReader();


                reader.onload = event => {

                    const image =
                        new Image();


                    image.onload = () => {

                        this.image = image;

                        this.width =
                            image.naturalWidth;

                        this.height =
                            image.naturalHeight;


                        resolve({

                            image: image,

                            width:
                                this.width,

                            height:
                                this.height,

                            file:
                                file

                        });
                    };


                    image.onerror = () => {

                        reject(
                            new Error(
                                "The image could not be loaded."
                            )
                        );
                    };


                    image.src =
                        event.target.result;
                };


                reader.onerror = () => {

                    reject(
                        new Error(
                            "The image file could not be read."
                        )
                    );
                };


                reader.readAsDataURL(file);
            }
        );
    }


    /**
     * ========================================================
     * DRAW ORIGINAL IMAGE
     * ========================================================
     *
     * Draws the loaded image onto a canvas and stores the
     * resulting ImageData.
     *
     * The canvas uses the ORIGINAL image dimensions.
     *
     * CSS controls how large it appears on screen.
     *
     * We must not resize the actual pixel data because doing
     * so would damage steganographic LSB information.
     *
     * ========================================================
     */

    drawToCanvas(canvas) {

        this.validateCanvas(canvas);

        if (!this.image) {

            throw new Error(
                "No image has been loaded."
            );
        }


        canvas.width =
            this.width;

        canvas.height =
            this.height;


        const context =
            canvas.getContext(
                "2d",
                {
                    willReadFrequently: true
                }
            );


        context.clearRect(
            0,
            0,
            canvas.width,
            canvas.height
        );


        context.drawImage(
            this.image,
            0,
            0,
            this.width,
            this.height
        );


        this.originalImageData =
            context.getImageData(
                0,
                0,
                this.width,
                this.height
            );


        this.currentImageData =
            this.cloneImageData(
                this.originalImageData
            );


        return this.originalImageData;
    }


    /**
     * ========================================================
     * GET IMAGE DATA FROM CANVAS
     * ========================================================
     */

    getImageData(canvas) {

        this.validateCanvas(canvas);


        if (
            canvas.width === 0 ||
            canvas.height === 0
        ) {

            throw new Error(
                "Canvas contains no image data."
            );
        }


        const context =
            canvas.getContext(
                "2d",
                {
                    willReadFrequently: true
                }
            );


        return context.getImageData(
            0,
            0,
            canvas.width,
            canvas.height
        );
    }


    /**
     * ========================================================
     * SET CURRENT IMAGE DATA
     * ========================================================
     *
     * LSBSteganography.js can produce modified ImageData
     * and pass it back here.
     *
     * ========================================================
     */

    setCurrentImageData(imageData) {

        this.validateImageData(
            imageData
        );


        this.currentImageData =
            this.cloneImageData(
                imageData
            );


        return this.currentImageData;
    }


    /**
     * ========================================================
     * GET ORIGINAL IMAGE DATA
     * ========================================================
     *
     * Returns a COPY so another class cannot accidentally
     * modify our original image.
     *
     * ========================================================
     */

    getOriginalImageData() {

        if (!this.originalImageData) {
            return null;
        }


        return this.cloneImageData(
            this.originalImageData
        );
    }


    /**
     * ========================================================
     * GET CURRENT IMAGE DATA
     * ========================================================
     */

    getCurrentImageData() {

        if (!this.currentImageData) {
            return null;
        }


        return this.cloneImageData(
            this.currentImageData
        );
    }


    /**
     * ========================================================
     * RENDER IMAGE DATA
     * ========================================================
     *
     * Draw arbitrary ImageData onto a canvas.
     *
     * Used for:
     *
     *      Original preview
     *      Steganographic preview
     *      Comparison canvas
     *
     * ========================================================
     */

    renderImageData(
        canvas,
        imageData
    ) {

        this.validateCanvas(canvas);

        this.validateImageData(
            imageData
        );


        canvas.width =
            imageData.width;

        canvas.height =
            imageData.height;


        const context =
            canvas.getContext(
                "2d"
            );


        context.clearRect(
            0,
            0,
            canvas.width,
            canvas.height
        );


        context.putImageData(
            imageData,
            0,
            0
        );
    }


    /**
     * ========================================================
     * CLONE IMAGE DATA
     * ========================================================
     *
     * ImageData contains a mutable Uint8ClampedArray.
     *
     * Simply assigning:
     *
     *      copy = original
     *
     * would cause both variables to reference the same pixel
     * data.
     *
     * We therefore make a completely independent copy.
     *
     * ========================================================
     */

    cloneImageData(imageData) {

        this.validateImageData(
            imageData
        );


        const copiedPixels =
            new Uint8ClampedArray(
                imageData.data
            );


        return new ImageData(
            copiedPixels,
            imageData.width,
            imageData.height
        );
    }


    /**
     * ========================================================
     * RESET IMAGE
     * ========================================================
     *
     * Discards all steganographic modifications and restores
     * the original uploaded image.
     *
     * ========================================================
     */

    reset() {

        if (!this.originalImageData) {
            return null;
        }


        this.currentImageData =
            this.cloneImageData(
                this.originalImageData
            );


        return this.getCurrentImageData();
    }


    /**
     * ========================================================
     * LSB CAPACITY
     * ========================================================
     *
     * Our initial steganography format will use:
     *
     *      1 bit in Red
     *      1 bit in Green
     *      1 bit in Blue
     *
     * Alpha is left untouched.
     *
     * Therefore:
     *
     *      bits = width × height × 3
     *
     * Example:
     *
     *      1000 × 1000 image
     *
     *      1,000,000 pixels
     *      × 3 bits
     *
     *      = 3,000,000 bits
     *      = 375,000 bytes
     *
     * ========================================================
     */

    getCapacityBits() {

        if (
            this.width === 0 ||
            this.height === 0
        ) {

            return 0;
        }


        return (
            this.width *
            this.height *
            3
        );
    }


    /**
     * Raw byte capacity before metadata.
     */
    getCapacityBytes() {

        return Math.floor(
            this.getCapacityBits() / 8
        );
    }


    /**
     * ========================================================
     * PAYLOAD CAPACITY
     * ========================================================
     *
     * LSBSteganography.js will need some bytes for metadata.
     *
     * We reserve:
     *
     *      4 bytes - magic identifier
     *      4 bytes - payload length
     *
     * Total:
     *
     *      8 bytes
     *
     * This allows the extractor to determine whether hidden
     * data exists and exactly how many bytes to read.
     *
     * ========================================================
     */

    getPayloadCapacityBytes(
        metadataBytes = 8
    ) {

        return Math.max(
            0,
            this.getCapacityBytes() -
            metadataBytes
        );
    }


    /**
     * ========================================================
     * CAPACITY INFORMATION
     * ========================================================
     *
     * Convenient object for app.js.
     *
     * ========================================================
     */

    getCapacityInfo() {

        const pixels =
            this.width *
            this.height;


        const bits =
            this.getCapacityBits();


        const bytes =
            this.getCapacityBytes();


        const payloadBytes =
            this.getPayloadCapacityBytes();


        return {

            width:
                this.width,

            height:
                this.height,

            pixels:
                pixels,

            channels:
                3,

            bits:
                bits,

            bytes:
                bytes,

            payloadBytes:
                payloadBytes,

            kilobytes:
                bytes / 1024,

            payloadKilobytes:
                payloadBytes / 1024

        };
    }


    /**
     * ========================================================
     * DIMENSION STRING
     * ========================================================
     *
     * Used directly by:
     *
     *      #imageDimensions
     *
     * ========================================================
     */

    getDimensionString() {

        if (
            this.width === 0 ||
            this.height === 0
        ) {

            return "—";
        }


        return (
            this.width +
            " × " +
            this.height +
            " px"
        );
    }


    /**
     * ========================================================
     * CAPACITY STRING
     * ========================================================
     */

    getCapacityString() {

        const bytes =
            this.getPayloadCapacityBytes();


        if (bytes === 0) {
            return "—";
        }


        return this.formatBytes(
            bytes
        );
    }


    /**
     * ========================================================
     * FORMAT BYTES
     * ========================================================
     */

    formatBytes(bytes) {

        if (
            !Number.isFinite(bytes) ||
            bytes < 0
        ) {

            return "0 B";
        }


        if (bytes < 1024) {

            return (
                bytes +
                " B"
            );
        }


        if (
            bytes <
            1024 * 1024
        ) {

            return (
                (
                    bytes / 1024
                ).toFixed(1) +
                " KB"
            );
        }


        return (
            (
                bytes /
                (1024 * 1024)
            ).toFixed(2) +
            " MB"
        );
    }


    /**
     * ========================================================
     * PIXEL INFORMATION
     * ========================================================
     *
     * Useful later if we want the UI to show exactly how
     * individual RGB values changed during steganography.
     *
     * ========================================================
     */

    getPixel(
        imageData,
        x,
        y
    ) {

        this.validateImageData(
            imageData
        );


        if (
            x < 0 ||
            x >= imageData.width ||
            y < 0 ||
            y >= imageData.height
        ) {

            throw new Error(
                "Pixel coordinates are outside the image."
            );
        }


        const index =
            (
                y *
                imageData.width +
                x
            ) * 4;


        return {

            x: x,

            y: y,

            r:
                imageData.data[index],

            g:
                imageData.data[
                    index + 1
                ],

            b:
                imageData.data[
                    index + 2
                ],

            a:
                imageData.data[
                    index + 3
                ]

        };
    }


    /**
     * ========================================================
     * SET PIXEL
     * ========================================================
     *
     * Mainly useful for debugging and visualisation.
     *
     * LSBSteganography should generally manipulate the
     * ImageData array directly for performance.
     *
     * ========================================================
     */

    setPixel(
        imageData,
        x,
        y,
        r,
        g,
        b,
        a = 255
    ) {

        this.validateImageData(
            imageData
        );


        if (
            x < 0 ||
            x >= imageData.width ||
            y < 0 ||
            y >= imageData.height
        ) {

            throw new Error(
                "Pixel coordinates are outside the image."
            );
        }


        const index =
            (
                y *
                imageData.width +
                x
            ) * 4;


        imageData.data[index] =
            this.clampByte(r);

        imageData.data[
            index + 1
        ] =
            this.clampByte(g);

        imageData.data[
            index + 2
        ] =
            this.clampByte(b);

        imageData.data[
            index + 3
        ] =
            this.clampByte(a);
    }


    /**
     * ========================================================
     * EXPORT CANVAS TO PNG
     * ========================================================
     *
     * Returns a Promise containing a Blob.
     *
     * PNG is important here.
     *
     * JPEG must NOT be used for the steganographic output
     * because JPEG compression can alter RGB values and
     * destroy the hidden least-significant bits.
     *
     * ========================================================
     */

    canvasToPNGBlob(canvas) {

        this.validateCanvas(canvas);


        return new Promise(
            (resolve, reject) => {

                canvas.toBlob(
                    blob => {

                        if (!blob) {

                            reject(
                                new Error(
                                    "PNG image could not be generated."
                                )
                            );

                            return;
                        }


                        resolve(blob);
                    },

                    "image/png"
                );
            }
        );
    }


    /**
     * ========================================================
     * DOWNLOAD CANVAS AS PNG
     * ========================================================
     */

    async downloadPNG(
        canvas,
        filename =
            "steganographic-image.png"
    ) {

        const blob =
            await this.canvasToPNGBlob(
                canvas
            );


        const url =
            URL.createObjectURL(
                blob
            );


        const link =
            document.createElement(
                "a"
            );


        link.href = url;

        link.download =
            filename;


        document.body.appendChild(
            link
        );


        link.click();


        document.body.removeChild(
            link
        );


        /*
         * Give the browser a moment to begin processing the
         * download before releasing the temporary object URL.
         */

        setTimeout(
            () => {

                URL.revokeObjectURL(
                    url
                );

            },
            1000
        );
    }


    /**
     * ========================================================
     * EXPORT IMAGE DATA DIRECTLY
     * ========================================================
     *
     * Allows:
     *
     *      ImageData
     *          ↓
     *      temporary canvas
     *          ↓
     *      PNG Blob
     *
     * ========================================================
     */

    imageDataToPNGBlob(imageData) {

        this.validateImageData(
            imageData
        );


        const canvas =
            document.createElement(
                "canvas"
            );


        canvas.width =
            imageData.width;

        canvas.height =
            imageData.height;


        const context =
            canvas.getContext(
                "2d"
            );


        context.putImageData(
            imageData,
            0,
            0
        );


        return this.canvasToPNGBlob(
            canvas
        );
    }


    /**
     * ========================================================
     * IMAGE COMPARISON
     * ========================================================
     *
     * Counts how many RGB channels differ between two images.
     *
     * This will be useful for displaying how little LSB
     * steganography actually changes the image.
     *
     * ========================================================
     */

    compareImageData(
        first,
        second
    ) {

        this.validateImageData(first);
        this.validateImageData(second);


        if (
            first.width !== second.width ||
            first.height !== second.height
        ) {

            throw new Error(
                "Images must have identical dimensions."
            );
        }


        let changedChannels = 0;

        let changedPixels = 0;

        let totalDifference = 0;


        for (
            let i = 0;
            i < first.data.length;
            i += 4
        ) {

            let pixelChanged = false;


            /*
             * Compare RGB only.
             *
             * Alpha is deliberately ignored.
             */

            for (
                let channel = 0;
                channel < 3;
                channel++
            ) {

                const difference =
                    Math.abs(
                        first.data[
                            i + channel
                        ] -
                        second.data[
                            i + channel
                        ]
                    );


                if (difference !== 0) {

                    changedChannels++;

                    pixelChanged = true;

                    totalDifference +=
                        difference;
                }
            }


            if (pixelChanged) {
                changedPixels++;
            }
        }


        const totalPixels =
            first.width *
            first.height;


        const totalRGBChannels =
            totalPixels * 3;


        return {

            totalPixels:
                totalPixels,

            changedPixels:
                changedPixels,

            changedChannels:
                changedChannels,

            totalRGBChannels:
                totalRGBChannels,

            changedPixelPercentage:
                totalPixels === 0
                    ? 0
                    : (
                        changedPixels /
                        totalPixels
                    ) * 100,

            changedChannelPercentage:
                totalRGBChannels === 0
                    ? 0
                    : (
                        changedChannels /
                        totalRGBChannels
                    ) * 100,

            totalDifference:
                totalDifference

        };
    }


    /**
     * ========================================================
     * CLAMP BYTE
     * ========================================================
     */

    clampByte(value) {

        value =
            Number(value);


        if (!Number.isFinite(value)) {
            return 0;
        }


        return Math.max(
            0,
            Math.min(
                255,
                Math.round(value)
            )
        );
    }


    /**
     * ========================================================
     * VALIDATION
     * ========================================================
     */

    validateCanvas(canvas) {

        if (
            !canvas ||
            !(canvas instanceof HTMLCanvasElement)
        ) {

            throw new Error(
                "A valid HTML canvas is required."
            );
        }
    }


    validateImageData(imageData) {

        if (
            !imageData ||
            !(imageData instanceof ImageData)
        ) {

            throw new Error(
                "Valid ImageData is required."
            );
        }
    }

}