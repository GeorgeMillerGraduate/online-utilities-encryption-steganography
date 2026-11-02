/**
 * ============================================================
 * AES128
 * ============================================================
 *
 * Educational implementation of the AES-128 block cipher.
 *
 * AES-128:
 *
 *      Block size : 128 bits / 16 bytes
 *      Key size   : 128 bits / 16 bytes
 *      Rounds     : 10
 *
 * Encryption:
 *
 *      Initial AddRoundKey
 *
 *      Rounds 1-9:
 *          SubBytes
 *          ShiftRows
 *          MixColumns
 *          AddRoundKey
 *
 *      Round 10:
 *          SubBytes
 *          ShiftRows
 *          AddRoundKey
 *
 * This class encrypts/decrypts individual 16-byte blocks.
 *
 * Message encoding and padding will be handled elsewhere.
 *
 * AESUtils.js must be loaded before this file.
 *
 * ============================================================
 */

class AES128 {

    /**
     * --------------------------------------------------------
     * CONSTRUCTOR
     * --------------------------------------------------------
     *
     * @param {Uint8Array|Array} key
     *        Exactly 16 bytes.
     */
    constructor(key) {

        if (!key) {
            throw new Error(
                "AES-128 requires a 128-bit key."
            );
        }

        if (key.length !== 16) {
            throw new Error(
                "AES-128 key must contain exactly 16 bytes."
            );
        }

        this.key =
            Uint8Array.from(key);

        /*
         * AES-128 produces:
         *
         *      Round key 0
         *      Round key 1
         *      ...
         *      Round key 10
         *
         * Eleven 16-byte keys in total.
         */
        this.roundKeys =
            this.expandKey(this.key);

        /*
         * Used by the visual AES round inspector.
         *
         * Each entry contains a copy of the state at
         * a particular stage of encryption.
         */
        this.roundStates = [];
    }


    /**
     * ========================================================
     * PUBLIC ENCRYPTION
     * ========================================================
     */

    /**
     * Encrypt exactly one 16-byte block.
     *
     * @param {Uint8Array|Array} block
     * @returns {Uint8Array}
     */
    encryptBlock(block) {

        this.validateBlock(block);

        this.roundStates = [];

        let state =
            this.bytesToState(
                Uint8Array.from(block)
            );


        /*
         * ----------------------------------------------------
         * INPUT STATE
         * ----------------------------------------------------
         */

        this.recordState(
            0,
            "Input",
            state
        );


        /*
         * ----------------------------------------------------
         * INITIAL ROUND
         *
         * AES begins with AddRoundKey before the numbered
         * transformation rounds.
         * ----------------------------------------------------
         */

        this.addRoundKey(
            state,
            this.roundKeys[0]
        );

        this.recordState(
            0,
            "AddRoundKey",
            state
        );


        /*
         * ----------------------------------------------------
         * ROUNDS 1 - 9
         * ----------------------------------------------------
         */

        for (
            let round = 1;
            round <= 9;
            round++
        ) {

            this.subBytes(state);

            this.recordState(
                round,
                "SubBytes",
                state
            );


            this.shiftRows(state);

            this.recordState(
                round,
                "ShiftRows",
                state
            );


            this.mixColumns(state);

            this.recordState(
                round,
                "MixColumns",
                state
            );


            this.addRoundKey(
                state,
                this.roundKeys[round]
            );

            this.recordState(
                round,
                "AddRoundKey",
                state
            );
        }


        /*
         * ----------------------------------------------------
         * ROUND 10
         *
         * The final AES round does NOT perform MixColumns.
         * ----------------------------------------------------
         */

        this.subBytes(state);

        this.recordState(
            10,
            "SubBytes",
            state
        );


        this.shiftRows(state);

        this.recordState(
            10,
            "ShiftRows",
            state
        );


        this.addRoundKey(
            state,
            this.roundKeys[10]
        );

        this.recordState(
            10,
            "AddRoundKey",
            state
        );


        return this.stateToBytes(state);
    }


    /**
     * ========================================================
     * PUBLIC DECRYPTION
     * ========================================================
     */

    /**
     * Decrypt exactly one 16-byte AES block.
     *
     * @param {Uint8Array|Array} block
     * @returns {Uint8Array}
     */
    decryptBlock(block) {

        this.validateBlock(block);

        let state =
            this.bytesToState(
                Uint8Array.from(block)
            );


        /*
         * Start using the final round key.
         */

        this.addRoundKey(
            state,
            this.roundKeys[10]
        );


        /*
         * ----------------------------------------------------
         * REVERSE ROUNDS 9 - 1
         * ----------------------------------------------------
         */

        for (
            let round = 9;
            round >= 1;
            round--
        ) {

            this.inverseShiftRows(state);

            this.inverseSubBytes(state);

            this.addRoundKey(
                state,
                this.roundKeys[round]
            );

            this.inverseMixColumns(state);
        }


        /*
         * ----------------------------------------------------
         * FINAL REVERSE ROUND
         * ----------------------------------------------------
         */

        this.inverseShiftRows(state);

        this.inverseSubBytes(state);

        this.addRoundKey(
            state,
            this.roundKeys[0]
        );


        return this.stateToBytes(state);
    }


    /**
     * ========================================================
     * SUB BYTES
     * ========================================================
     */

    subBytes(state) {

        for (let row = 0; row < 4; row++) {

            for (
                let column = 0;
                column < 4;
                column++
            ) {

                state[row][column] =
                    AESUtils.SBOX[
                        state[row][column]
                    ];
            }
        }
    }


    /**
     * Inverse SubBytes operation.
     */
    inverseSubBytes(state) {

        for (let row = 0; row < 4; row++) {

            for (
                let column = 0;
                column < 4;
                column++
            ) {

                state[row][column] =
                    AESUtils.INVERSE_SBOX[
                        state[row][column]
                    ];
            }
        }
    }


    /**
     * ========================================================
     * SHIFT ROWS
     * ========================================================
     *
     * Row 0 -> unchanged
     * Row 1 -> shift left 1
     * Row 2 -> shift left 2
     * Row 3 -> shift left 3
     */

    shiftRows(state) {

        for (let row = 1; row < 4; row++) {

            state[row] =
                this.rotateLeft(
                    state[row],
                    row
                );
        }
    }


    /**
     * Reverse ShiftRows.
     */
    inverseShiftRows(state) {

        for (let row = 1; row < 4; row++) {

            state[row] =
                this.rotateRight(
                    state[row],
                    row
                );
        }
    }


    /**
     * ========================================================
     * MIX COLUMNS
     * ========================================================
     *
     * Matrix multiplication in GF(2^8):
     *
     *      02 03 01 01
     *      01 02 03 01
     *      01 01 02 03
     *      03 01 01 02
     *
     * ========================================================
     */

    mixColumns(state) {

        for (
            let column = 0;
            column < 4;
            column++
        ) {

            const a0 = state[0][column];
            const a1 = state[1][column];
            const a2 = state[2][column];
            const a3 = state[3][column];


            state[0][column] =
                (
                    AESUtils.multiply(a0, 0x02) ^
                    AESUtils.multiply(a1, 0x03) ^
                    a2 ^
                    a3
                ) & 0xFF;


            state[1][column] =
                (
                    a0 ^
                    AESUtils.multiply(a1, 0x02) ^
                    AESUtils.multiply(a2, 0x03) ^
                    a3
                ) & 0xFF;


            state[2][column] =
                (
                    a0 ^
                    a1 ^
                    AESUtils.multiply(a2, 0x02) ^
                    AESUtils.multiply(a3, 0x03)
                ) & 0xFF;


            state[3][column] =
                (
                    AESUtils.multiply(a0, 0x03) ^
                    a1 ^
                    a2 ^
                    AESUtils.multiply(a3, 0x02)
                ) & 0xFF;
        }
    }


    /**
     * ========================================================
     * INVERSE MIX COLUMNS
     * ========================================================
     *
     * Inverse matrix:
     *
     *      0E 0B 0D 09
     *      09 0E 0B 0D
     *      0D 09 0E 0B
     *      0B 0D 09 0E
     *
     * ========================================================
     */

    inverseMixColumns(state) {

        for (
            let column = 0;
            column < 4;
            column++
        ) {

            const a0 = state[0][column];
            const a1 = state[1][column];
            const a2 = state[2][column];
            const a3 = state[3][column];


            state[0][column] =
                (
                    AESUtils.multiply(a0, 0x0E) ^
                    AESUtils.multiply(a1, 0x0B) ^
                    AESUtils.multiply(a2, 0x0D) ^
                    AESUtils.multiply(a3, 0x09)
                ) & 0xFF;


            state[1][column] =
                (
                    AESUtils.multiply(a0, 0x09) ^
                    AESUtils.multiply(a1, 0x0E) ^
                    AESUtils.multiply(a2, 0x0B) ^
                    AESUtils.multiply(a3, 0x0D)
                ) & 0xFF;


            state[2][column] =
                (
                    AESUtils.multiply(a0, 0x0D) ^
                    AESUtils.multiply(a1, 0x09) ^
                    AESUtils.multiply(a2, 0x0E) ^
                    AESUtils.multiply(a3, 0x0B)
                ) & 0xFF;


            state[3][column] =
                (
                    AESUtils.multiply(a0, 0x0B) ^
                    AESUtils.multiply(a1, 0x0D) ^
                    AESUtils.multiply(a2, 0x09) ^
                    AESUtils.multiply(a3, 0x0E)
                ) & 0xFF;
        }
    }


    /**
     * ========================================================
     * ADD ROUND KEY
     * ========================================================
     *
     * XOR the state with the current 128-bit round key.
     */

    addRoundKey(state, roundKey) {

        for (
            let column = 0;
            column < 4;
            column++
        ) {

            for (
                let row = 0;
                row < 4;
                row++
            ) {

                const keyIndex =
                    (column * 4) + row;

                state[row][column] =
                    (
                        state[row][column] ^
                        roundKey[keyIndex]
                    ) & 0xFF;
            }
        }
    }


    /**
     * ========================================================
     * KEY EXPANSION
     * ========================================================
     *
     * AES-128 expands the original 16-byte key into
     * 44 four-byte words:
     *
     *      44 words × 4 bytes = 176 bytes
     *
     * These form eleven 16-byte round keys.
     */

    expandKey(key) {

        const expanded =
            new Uint8Array(176);


        /*
         * First 16 bytes are simply the original key.
         */

        expanded.set(
            key,
            0
        );


        let bytesGenerated = 16;

        let rconIteration = 1;

        let temp =
            new Uint8Array(4);


        while (bytesGenerated < 176) {

            /*
             * Copy previous four bytes.
             */

            for (let i = 0; i < 4; i++) {

                temp[i] =
                    expanded[
                        bytesGenerated - 4 + i
                    ];
            }


            /*
             * Every 16 bytes perform the AES key schedule
             * core operation.
             */

            if (
                bytesGenerated % 16 === 0
            ) {

                temp =
                    this.keyScheduleCore(
                        temp,
                        rconIteration
                    );

                rconIteration++;
            }


            /*
             * XOR with the word 16 bytes earlier.
             */

            for (let i = 0; i < 4; i++) {

                expanded[bytesGenerated] =
                    (
                        expanded[
                            bytesGenerated - 16
                        ] ^
                        temp[i]
                    ) & 0xFF;

                bytesGenerated++;
            }
        }


        /*
         * Convert the 176 expanded bytes into
         * eleven separate 16-byte keys.
         */

        const roundKeys = [];

        for (
            let round = 0;
            round <= 10;
            round++
        ) {

            const start =
                round * 16;

            roundKeys.push(
                expanded.slice(
                    start,
                    start + 16
                )
            );
        }


        return roundKeys;
    }


    /**
     * AES key schedule core:
     *
     *      RotWord
     *      SubWord
     *      XOR Rcon
     */
    keyScheduleCore(word, iteration) {

        const result =
            Uint8Array.from(word);


        /*
         * RotWord
         *
         * [a b c d]
         *
         * becomes
         *
         * [b c d a]
         */

        const first =
            result[0];

        result[0] = result[1];
        result[1] = result[2];
        result[2] = result[3];
        result[3] = first;


        /*
         * SubWord
         */

        for (let i = 0; i < 4; i++) {

            result[i] =
                AESUtils.SBOX[
                    result[i]
                ];
        }


        /*
         * Rcon affects the first byte.
         */

        result[0] ^=
            AESUtils.RCON[iteration];


        return result;
    }


    /**
     * ========================================================
     * STATE CONVERSION
     * ========================================================
     *
     * AES represents the 16-byte block as:
     *
     *      | b0  b4  b8  b12 |
     *      | b1  b5  b9  b13 |
     *      | b2  b6  b10 b14 |
     *      | b3  b7  b11 b15 |
     *
     * Notice that AES fills the matrix COLUMN FIRST.
     *
     * ========================================================
     */

    bytesToState(bytes) {

        const state = [
            new Uint8Array(4),
            new Uint8Array(4),
            new Uint8Array(4),
            new Uint8Array(4)
        ];


        for (
            let column = 0;
            column < 4;
            column++
        ) {

            for (
                let row = 0;
                row < 4;
                row++
            ) {

                state[row][column] =
                    bytes[
                        (column * 4) + row
                    ];
            }
        }


        return state;
    }


    /**
     * Convert the AES matrix back into
     * a normal 16-byte array.
     */
    stateToBytes(state) {

        const output =
            new Uint8Array(16);


        for (
            let column = 0;
            column < 4;
            column++
        ) {

            for (
                let row = 0;
                row < 4;
                row++
            ) {

                output[
                    (column * 4) + row
                ] =
                    state[row][column];
            }
        }


        return output;
    }


    /**
     * ========================================================
     * ROUND INSPECTOR
     * ========================================================
     */

    recordState(round, operation, state) {

        this.roundStates.push({

            round: round,

            operation: operation,

            state:
                this.copyState(state)

        });
    }


    /**
     * Return all recorded states from the most recent
     * encryption operation.
     */
    getRoundStates() {

        return this.roundStates;
    }


    /**
     * Return recorded states belonging to one AES round.
     */
    getStatesForRound(round) {

        return this.roundStates.filter(
            entry =>
                entry.round === round
        );
    }


    /**
     * Return a particular state snapshot.
     */
    getState(round, operation) {

        const result =
            this.roundStates.find(
                entry =>
                    entry.round === round &&
                    entry.operation === operation
            );


        if (!result) {
            return null;
        }


        return this.copyState(
            result.state
        );
    }


    /**
     * ========================================================
     * HELPERS
     * ========================================================
     */

    validateBlock(block) {

        if (!block) {

            throw new Error(
                "AES block cannot be null."
            );
        }


        if (block.length !== 16) {

            throw new Error(
                "AES block must contain exactly 16 bytes."
            );
        }
    }


    copyState(state) {

        return state.map(
            row =>
                Uint8Array.from(row)
        );
    }


    rotateLeft(array, amount) {

        const result =
            new Uint8Array(4);


        for (let i = 0; i < 4; i++) {

            result[i] =
                array[
                    (i + amount) % 4
                ];
        }


        return result;
    }


    rotateRight(array, amount) {

        const result =
            new Uint8Array(4);


        for (let i = 0; i < 4; i++) {

            result[
                (i + amount) % 4
            ] =
                array[i];
        }


        return result;
    }


    /**
     * Convert a state matrix into hexadecimal strings.
     *
     * Useful for SteganographyRenderer/app.js.
     */
    stateToHexMatrix(state) {

        return state.map(
            row =>
                Array.from(row).map(
                    byte =>
                        byte
                            .toString(16)
                            .padStart(2, "0")
                            .toUpperCase()
                )
        );
    }


    /**
     * Return one round key.
     */
    getRoundKey(round) {

        if (
            round < 0 ||
            round > 10
        ) {

            throw new Error(
                "AES round must be between 0 and 10."
            );
        }


        return Uint8Array.from(
            this.roundKeys[round]
        );
    }

}