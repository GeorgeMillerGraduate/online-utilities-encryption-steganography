/**
 * ============================================================
 * SteganographyRenderer
 * ============================================================
 *
 * UI / rendering layer for the image steganography section.
 *
 * Responsibilities:
 *
 *      Render original image
 *      Render steganographic image
 *      Render comparison image
 *      Update image dimensions
 *      Update capacity information
 *      Update capacity meter
 *      Show steganography status
 *      Hide/show canvas placeholders
 *      Display image modification statistics
 *
 * This class DOES NOT hide or extract data.
 *
 * LSBSteganography.js handles the algorithm.
 * ImageProcessor.js handles image manipulation.
 *
 * ============================================================
 */

class SteganographyRenderer {


    /**
     * --------------------------------------------------------
     * CONSTRUCTOR
     * --------------------------------------------------------
     *
     * Finds the HTML elements created in index.html.
     */

    constructor() {

        /*
         * Main uploaded-image preview.
         */

        this.originalCanvas =
            document.getElementById(
                "originalCanvas"
            );

        this.originalPlaceholder =
            document.getElementById(
                "originalPlaceholder"
            );


        /*
         * Comparison section.
         */

        this.comparisonOriginalCanvas =
            document.getElementById(
                "comparisonOriginalCanvas"
            );

        this.stegoCanvas =
            document.getElementById(
                "stegoCanvas"
            );

        this.stegoPlaceholder =
            document.getElementById(
                "stegoPlaceholder"
            );


        /*
         * Image information.
         */

        this.imageDimensions =
            document.getElementById(
                "imageDimensions"
            );

        this.imageCapacity =
            document.getElementById(
                "imageCapacity"
            );


        /*
         * Capacity meter.
         */

        this.capacityText =
            document.getElementById(
                "capacityText"
            );

        this.capacityBar =
            document.getElementById(
                "capacityBar"
            );


        /*
         * Output status.
         */

        this.stegoStatus =
            document.getElementById(
                "stegoStatus"
            );


        /*
         * Download button.
         */

        this.downloadButton =
            document.getElementById(
                "downloadImageButton"
            );


        /*
         * Current rendered images.
         */

        this.originalImageData = null;

        this.stegoImageData = null;


        /*
         * Capacity.
         */

        this.capacityBytes = 0;

        this.usedBytes = 0;


        this.initialise();
    }


    /**
     * ========================================================
     * INITIALISE
     * ========================================================
     */

    initialise() {

        this.updateDimensions(
            0,
            0
        );

        this.updateCapacity(
            0
        );

        this.updateCapacityMeter(
            0,
            0
        );

        this.setStatus(
            "Waiting for image"
        );

        this.setDownloadEnabled(
            false
        );
    }


    /**
     * ========================================================
     * RENDER ORIGINAL IMAGE
     * ========================================================
     *
     * Draws the original ImageData into:
     *
     *      #originalCanvas
     *
     * and:
     *
     *      #comparisonOriginalCanvas
     *
     * ========================================================
     */

    renderOriginal(imageData) {

        this.validateImageData(
            imageData
        );


        this.originalImageData =
            this.cloneImageData(
                imageData
            );


        /*
         * Main image preview.
         */

        this.renderToCanvas(
            this.originalCanvas,
            imageData
        );


        /*
         * Comparison preview.
         */

        this.renderToCanvas(
            this.comparisonOriginalCanvas,
            imageData
        );


        /*
         * Hide original-image placeholder.
         */

        this.hideElement(
            this.originalPlaceholder
        );


        /*
         * The comparison canvas uses a generic placeholder
         * without an ID in the original HTML.
         *
         * Locate it from the canvas container.
         */

        if (
            this.comparisonOriginalCanvas
        ) {

            const container =
                this.comparisonOriginalCanvas
                    .parentElement;


            if (container) {

                const placeholder =
                    container.querySelector(
                        ".canvas-placeholder"
                    );


                this.hideElement(
                    placeholder
                );
            }
        }


        /*
         * Update dimensions.
         */

        this.updateDimensions(
            imageData.width,
            imageData.height
        );


        /*
         * Determine LSB payload capacity.
         */

        let capacity = 0;


        if (
            typeof LSBSteganography !==
            "undefined"
        ) {

            capacity =
                LSBSteganography
                    .getPayloadCapacity(
                        imageData
                    );

        } else {

            /*
             * Fallback:
             *
             * 3 RGB bits per pixel,
             * minus eight-byte header.
             */

            capacity =
                Math.max(
                    0,

                    Math.floor(
                        (
                            imageData.width *
                            imageData.height *
                            3
                        ) / 8
                    ) - 8
                );
        }


        this.updateCapacity(
            capacity
        );


        this.updateCapacityMeter(
            0,
            capacity
        );


        this.clearStego();


        this.setStatus(
            "Image loaded"
        );
    }


    /**
     * ========================================================
     * RENDER STEGANOGRAPHIC IMAGE
     * ========================================================
     */

    renderStego(imageData) {

        this.validateImageData(
            imageData
        );


        this.stegoImageData =
            this.cloneImageData(
                imageData
            );


        this.renderToCanvas(
            this.stegoCanvas,
            imageData
        );


        this.hideElement(
            this.stegoPlaceholder
        );


        this.setDownloadEnabled(
            true
        );


        /*
         * If we have the original image, compare the two.
         */

        if (this.originalImageData) {

            const comparison =
                this.compareImages(
                    this.originalImageData,
                    imageData
                );


            this.setStatus(
                this.createComparisonStatus(
                    comparison
                )
            );

        } else {

            this.setStatus(
                "Steganographic image generated"
            );
        }
    }


    /**
     * ========================================================
     * RENDER TO CANVAS
     * ========================================================
     */

    renderToCanvas(
        canvas,
        imageData
    ) {

        if (!canvas) {
            return;
        }


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


        /*
         * putImageData writes exact pixel values.
         *
         * This is important for LSB steganography because
         * interpolation/rescaling would destroy hidden bits.
         */

        context.putImageData(
            imageData,
            0,
            0
        );
    }


    /**
     * ========================================================
     * CLEAR STEGO OUTPUT
     * ========================================================
     */

    clearStego() {

        this.stegoImageData = null;


        if (this.stegoCanvas) {

            const context =
                this.stegoCanvas.getContext(
                    "2d"
                );


            context.clearRect(
                0,
                0,
                this.stegoCanvas.width,
                this.stegoCanvas.height
            );


            /*
             * A small blank canvas prevents an old image
             * remaining visually present.
             */

            this.stegoCanvas.width = 1;
            this.stegoCanvas.height = 1;
        }


        this.showElement(
            this.stegoPlaceholder
        );


        this.setDownloadEnabled(
            false
        );
    }


    /**
     * ========================================================
     * UPDATE DIMENSIONS
     * ========================================================
     */

    updateDimensions(
        width,
        height
    ) {

        if (!this.imageDimensions) {
            return;
        }


        if (
            !width ||
            !height
        ) {

            this.imageDimensions.textContent =
                "—";

            return;
        }


        this.imageDimensions.textContent =
            width +
            " × " +
            height +
            " px";
    }


    /**
     * ========================================================
     * UPDATE CAPACITY
     * ========================================================
     */

    updateCapacity(bytes) {

        this.capacityBytes =
            Math.max(
                0,
                Number(bytes) || 0
            );


        if (!this.imageCapacity) {
            return;
        }


        if (
            this.capacityBytes === 0
        ) {

            this.imageCapacity.textContent =
                "—";

            return;
        }


        this.imageCapacity.textContent =
            this.formatBytes(
                this.capacityBytes
            );
    }


    /**
     * ========================================================
     * UPDATE CAPACITY METER
     * ========================================================
     *
     * Used as the user types a secret message.
     *
     * app.js can call:
     *
     *      renderer.updateCapacityMeter(
     *          encryptedBytes.length,
     *          capacity
     *      );
     *
     * ========================================================
     */

    updateCapacityMeter(
        usedBytes,
        capacityBytes =
            this.capacityBytes
    ) {

        usedBytes =
            Math.max(
                0,
                Number(usedBytes) || 0
            );


        capacityBytes =
            Math.max(
                0,
                Number(capacityBytes) || 0
            );


        this.usedBytes =
            usedBytes;

        this.capacityBytes =
            capacityBytes;


        /*
         * Text:
         *
         *      124 / 48.2 KB
         */

        if (this.capacityText) {

            this.capacityText.textContent =
                this.formatBytes(
                    usedBytes
                ) +
                " / " +
                this.formatBytes(
                    capacityBytes
                );
        }


        /*
         * Percentage.
         */

        let percentage = 0;


        if (capacityBytes > 0) {

            percentage =
                (
                    usedBytes /
                    capacityBytes
                ) * 100;
        }


        const displayPercentage =
            Math.min(
                100,
                Math.max(
                    0,
                    percentage
                )
            );


        if (this.capacityBar) {

            this.capacityBar.style.width =
                displayPercentage + "%";


            /*
             * Expose status for CSS if we later want different
             * colours for full/overflowing capacity.
             */

            if (
                usedBytes >
                capacityBytes &&
                capacityBytes > 0
            ) {

                this.capacityBar.dataset.status =
                    "overflow";

            } else if (
                percentage >= 85
            ) {

                this.capacityBar.dataset.status =
                    "warning";

            } else {

                this.capacityBar.dataset.status =
                    "normal";
            }
        }


        return {

            usedBytes:
                usedBytes,

            capacityBytes:
                capacityBytes,

            percentage:
                percentage,

            fits:
                usedBytes <=
                capacityBytes

        };
    }


    /**
     * ========================================================
     * UPDATE CAPACITY FROM PAYLOAD
     * ========================================================
     *
     * Convenience method.
     *
     * ========================================================
     */

    updatePayloadUsage(payload) {

        if (!payload) {

            return this.updateCapacityMeter(
                0,
                this.capacityBytes
            );
        }


        return this.updateCapacityMeter(
            payload.length,
            this.capacityBytes
        );
    }


    /**
     * ========================================================
     * STATUS
     * ========================================================
     */

    setStatus(message) {

        if (!this.stegoStatus) {
            return;
        }


        this.stegoStatus.textContent =
            message;
    }


    /**
     * ========================================================
     * SUCCESS STATUS
     * ========================================================
     */

    showSuccess(message) {

        this.setStatus(
            message
        );


        if (this.stegoStatus) {

            this.stegoStatus.dataset.status =
                "success";
        }
    }


    /**
     * ========================================================
     * ERROR STATUS
     * ========================================================
     */

    showError(message) {

        this.setStatus(
            message
        );


        if (this.stegoStatus) {

            this.stegoStatus.dataset.status =
                "error";
        }
    }


    /**
     * ========================================================
     * NORMAL STATUS
     * ========================================================
     */

    showNormalStatus(message) {

        this.setStatus(
            message
        );


        if (this.stegoStatus) {

            this.stegoStatus.dataset.status =
                "normal";
        }
    }


    /**
     * ========================================================
     * DOWNLOAD BUTTON
     * ========================================================
     */

    setDownloadEnabled(enabled) {

        if (!this.downloadButton) {
            return;
        }


        this.downloadButton.disabled =
            !enabled;
    }


    /**
     * ========================================================
     * IMAGE COMPARISON
     * ========================================================
     *
     * Calculates how much the steganography operation changed
     * the original image.
     *
     * Only RGB is inspected.
     *
     * ========================================================
     */

    compareImages(
        original,
        modified
    ) {

        this.validateImageData(
            original
        );

        this.validateImageData(
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


        /*
         * Use LSBSteganography's comparison method when
         * available.
         */

        if (
            typeof LSBSteganography !==
                "undefined" &&
            typeof LSBSteganography
                .compareImages ===
                "function"
        ) {

            return (
                LSBSteganography
                    .compareImages(
                        original,
                        modified
                    )
            );
        }


        /*
         * Fallback implementation.
         */

        let changedPixels = 0;

        let changedChannels = 0;

        let maximumDifference = 0;


        const totalPixels =
            original.width *
            original.height;


        for (
            let i = 0;
            i < original.data.length;
            i += 4
        ) {

            let pixelChanged = false;


            /*
             * R, G and B only.
             */

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
     * CREATE COMPARISON STATUS
     * ========================================================
     */

    createComparisonStatus(
        comparison
    ) {

        if (!comparison) {

            return (
                "Steganographic image generated"
            );
        }


        const percentage =
            Number(
                comparison
                    .changedPixelPercentage
            ).toFixed(2);


        return (
            "Hidden data embedded — " +
            this.formatNumber(
                comparison.changedPixels
            ) +
            " pixels modified (" +
            percentage +
            "%)"
        );
    }


    /**
     * ========================================================
     * GET DIFFERENCE INFORMATION
     * ========================================================
     *
     * Useful if app.js later wants a more detailed statistics
     * panel.
     *
     * ========================================================
     */

    getDifferenceInfo() {

        if (
            !this.originalImageData ||
            !this.stegoImageData
        ) {

            return null;
        }


        return this.compareImages(
            this.originalImageData,
            this.stegoImageData
        );
    }


    /**
     * ========================================================
     * GET STEGO CANVAS
     * ========================================================
     *
     * app.js can pass this directly to:
     *
     *      ImageProcessor.downloadPNG(...)
     *
     * ========================================================
     */

    getStegoCanvas() {

        return this.stegoCanvas;
    }


    /**
     * ========================================================
     * GET ORIGINAL CANVAS
     * ========================================================
     */

    getOriginalCanvas() {

        return this.originalCanvas;
    }


    /**
     * ========================================================
     * GET STEGO IMAGE DATA
     * ========================================================
     */

    getStegoImageData() {

        if (!this.stegoImageData) {
            return null;
        }


        return this.cloneImageData(
            this.stegoImageData
        );
    }


    /**
     * ========================================================
     * GET ORIGINAL IMAGE DATA
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
     * RESET
     * ========================================================
     */

    reset() {

        this.originalImageData = null;

        this.stegoImageData = null;

        this.capacityBytes = 0;

        this.usedBytes = 0;


        /*
         * Clear canvases.
         */

        this.clearCanvas(
            this.originalCanvas
        );

        this.clearCanvas(
            this.comparisonOriginalCanvas
        );

        this.clearCanvas(
            this.stegoCanvas
        );


        /*
         * Restore placeholders.
         */

        this.showElement(
            this.originalPlaceholder
        );

        this.showElement(
            this.stegoPlaceholder
        );


        if (
            this.comparisonOriginalCanvas
        ) {

            const container =
                this.comparisonOriginalCanvas
                    .parentElement;


            if (container) {

                this.showElement(
                    container.querySelector(
                        ".canvas-placeholder"
                    )
                );
            }
        }


        this.updateDimensions(
            0,
            0
        );


        this.updateCapacity(
            0
        );


        this.updateCapacityMeter(
            0,
            0
        );


        this.showNormalStatus(
            "Waiting for image"
        );


        this.setDownloadEnabled(
            false
        );
    }


    /**
     * ========================================================
     * CLEAR CANVAS
     * ========================================================
     */

    clearCanvas(canvas) {

        if (!canvas) {
            return;
        }


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


        canvas.width = 1;

        canvas.height = 1;
    }


    /**
     * ========================================================
     * SHOW / HIDE ELEMENT
     * ========================================================
     */

    hideElement(element) {

        if (!element) {
            return;
        }


        element.style.display =
            "none";
    }


    showElement(element) {

        if (!element) {
            return;
        }


        element.style.display =
            "";
    }


    /**
     * ========================================================
     * FORMAT BYTES
     * ========================================================
     */

    formatBytes(bytes) {

        bytes =
            Number(bytes);


        if (
            !Number.isFinite(bytes) ||
            bytes <= 0
        ) {

            return "0 B";
        }


        if (bytes < 1024) {

            return (
                Math.round(bytes) +
                " B"
            );
        }


        if (
            bytes <
            1024 * 1024
        ) {

            return (
                (
                    bytes /
                    1024
                ).toFixed(1) +
                " KB"
            );
        }


        if (
            bytes <
            1024 * 1024 * 1024
        ) {

            return (
                (
                    bytes /
                    (
                        1024 *
                        1024
                    )
                ).toFixed(2) +
                " MB"
            );
        }


        return (
            (
                bytes /
                (
                    1024 *
                    1024 *
                    1024
                )
            ).toFixed(2) +
            " GB"
        );
    }


    /**
     * ========================================================
     * FORMAT NUMBER
     * ========================================================
     */

    formatNumber(value) {

        value =
            Number(value) || 0;


        return value.toLocaleString();
    }


    /**
     * ========================================================
     * CLONE IMAGE DATA
     * ========================================================
     */

    cloneImageData(imageData) {

        this.validateImageData(
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
     * VALIDATION
     * ========================================================
     */

    validateImageData(imageData) {

        if (
            !imageData ||
            !(imageData instanceof ImageData)
        ) {

            throw new Error(
                "Valid ImageData is required for rendering."
            );
        }


        return true;
    }

}