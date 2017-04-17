/** @file cipher.js
 *  @brief File containing the functions accessing seifnode cipher functions
 *
 *  @author Aashish Sheshadri
 *  @author Rohit Harchandani
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2016, 2017 PayPal
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

/*jslint node: true */
// jshint esversion: 6

/**
 * @brief Main function executed when the module is required to create the
 *        cipher access object.
 *
 * @return object object containing the cipher access functions.
 */
function getCipher() {
    'use strict';

    let seifnode = require('seifnode');
    let loggerGenerator = require("../log");

    let logger = loggerGenerator.child({componentName: "CIPHER"});


    /**
     * @brief Constructor for BlockCipher object responsible for cipher
     *        operations.
     *
     * @param options parameters to setup the BlockCipher object
     *
     * @return object BlockCipher object with functions for cipher operations.
     */
    function createBlockCipher(options) {
        logger.trace({options}, 'Creating new BlockCipher object.');

        let key = options.key;
        let isInitiator = options.isInitiator;

        /**
         * @brief Implementation of the AES-XOR mode.
         *
         * @param options options to setup the cipher mode.
         *
         * @return object object containing the cipher mode functions.
         */
        function createXorMode() {

            // Setup properties of the mode based on the given options.
            let name = 'AES-XOR';
            let encrng, decrng;

            /**
             * @brief Utility function to split the given key so as to get two
             *        different seeds for the random number generator used for
             *        link encryption.
             *
             * @param key key bytes to be split
             * @param isInitiator boolean indicating type of party
             *
             * @return object object containing the cipher access functions.
             */
            function splitKey() {
                logger.trace(
                    {isInitiator},
                    'Splitting the secret to get different seeds for AES'
                );

                let seeds = {};

                /* If the party is an initiator the first 16 bytes are used to
                 * seed the RNG for encrypting the data over the link, and the
                 * next 16 bytes are used to seed the RNG for decrypting the
                 * data received over the link. If its neither, then the first
                 * 16 bytes are used to seed both the RNGs.
                 */
                if (isInitiator === true) {

                    seeds.enc = key.slice(0, 16);
                    seeds.dec = key.slice(16);
                } else if (isInitiator === false) {

                    seeds.dec = key.slice(0, 16);
                    seeds.enc = key.slice(16);
                } else {

                    seeds.enc = key.slice(0, 16);
                    seeds.dec = key.slice(0, 16);
                }

                return seeds;
            }


            /**
             * @brief Initializes the cipher mode based on
             *        given link properties.
             *
             * @param options options to setup the cipher mode for current
             *        session.
             *
             * @return None
             */
            function start() {

                logger.trace("Starting AES-XOR mode");

                // Splits the key to generate seeds for the AES RNGs
                let seeds = splitKey();

                // Create the addon objects responsible for the
                // cipher operations.
                encrng = new seifnode.AESXOR256(seeds.enc);
                decrng = new seifnode.AESXOR256(seeds.dec);

            }


            /**
             * @brief Encrypts the given input to return the output using the
             *        AES-XOR mode.
             *
             * @param input buffer to be encrypted
             * @param output buffer containing the encrypted data
             *
             * @return None
             */
            function encrypt(input) {
                logger.trace({secret: key}, "Encrypting using AES-XOR mode");
                return encrng.encrypt(key, input);
            }


            /**
             * @brief Decrypts the given input to return the output using the
             *        AES-XOR mode.
             *
             * @param input buffer to be decrypted
             * @param output buffer containing the decrypted data
             *
             * @return None
             */
            function decrypt(input) {
                logger.trace({secret: key}, "Decrypting using AES-XOR mode");
                return decrng.decrypt(key, input);
            }


            return Object.freeze({
                name,
                start,
                encrypt,
                decrypt
            });

        }

        // Setup properties of BlockCipher object.
        let mode = createXorMode();
        let op = mode.encrypt;
        let isDecrypt = options.decrypt;
        if (isDecrypt === true) {
            op = mode.decrypt;
        }

        function start() {
            mode.start();
        }

        /**
         * @brief Updates the next block according to the cipher mode.
         *
         * @param input the buffer to read from.
         *
         * @return None
         */
        function update(input) {
            logger.trace(
                {key, isInitiator, isDecrypt},
                'Updating cipher'
            );

            return op.call(mode, input);
        }

        // Return the object with above functions.
        return Object.freeze({
            start,
            update
        });

    }


    /**
     * @brief Creates a cipher object that can be used to encrypt data using
     *        the given algorithm and key. The algorithm may be provided as a
     *        string value for a previously registered algorithm or it may be
     *        given as a cipher algorithm API object.
     *
     * @param algorithm the algorithm to use, either a string or an algorithm
     *        API object.
     * @param key the key to use, as a hex buffer.
     *
     * @return object the cipher.
     */
    function createCipher(options) {
        logger.trace({key: options.key}, 'Creating cipher');

        // Create block cipher for encryption.
        return createBlockCipher({
            key: options.key,
            isInitiator: options.isInitiator,
            decrypt: false
        });
    }


    /**
     * @brief Creates a decipher object that can be used to decrypt data using
     *        the given algorithm and key. The algorithm may be provided as a
     *        string value for a previously registered algorithm or it may be
     *        given as a cipher algorithm API object.
     *
     * @param algorithm the algorithm to use, either a string or an algorithm
     *        API object.
     * @param key the key to use, as hex buffer.
     *
     * @return the cipher.
     */
    function createDecipher(options) {
        logger.trace({key: options.key}, 'Creating decipher');

        // Create block cipher for encryption.
        return createBlockCipher({
            key: options.key,
            isInitiator: options.isInitiator,
            decrypt: true
        });
    }


    return Object.freeze({
        createCipher,
        createDecipher
    });

}


module.exports = getCipher();
