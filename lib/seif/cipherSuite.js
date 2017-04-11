/** @file cipherSuite.js
 *  @brief File containing the cipher suite interface functions
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

function initialize() {
    'use strict';

    let cipher = require("./cipher");
    let loggerGenerator = require("../log");

    let logger = loggerGenerator.child({componentName: "AES_CIPHER_SUITES"});

    /**
     * @brief Main function returned when the module is required to create the
     *        cipher suites object. The object contains an object with supported
     *        encryption mechanisms.
     *
     * @return object object containing the various cipher suites.
     */
    function getCipherSuites() {

        logger.trace('Setting up cipher suites');

        /**
         * @brief Encrypts a message string into a cipher buffer
         *        using AES in custom AES-XOR mode.
         *
         * @param cipherState initalized cipher state
         * @param messageBuffer message buffer to be encrypted
         *
         * @return buffer cipher buffer
         */
        function encrypt(cipherState, messageBuffer) {

            // Initialize the aes xor cipher if it isnt already.
            let aesCipher = cipherState.cipher;
            if (aesCipher === undefined) {
                aesCipher = cipher.createCipher({
                    key: cipherState.key
                });
            }

            aesCipher.start();

            // Perform encryption and return the cipher output.
            let cipherBuffer = aesCipher.update(messageBuffer);
            if (cipherBuffer === undefined) {
                return;
            }

            return cipherBuffer;
        }


        /**
         * @brief Decrypts a cipher buffer into the original message buffer
         *        using AES in custom AES-XOR mode.
         *
         * @param cipherState initalized cipher state
         * @param cipherBuffer cipher buffer to be decrypted
         *
         * @return decrypted message buffer
         */
        function decrypt(cipherState, cipherBuffer) {

            // Initialize the aes xor cipher if it isnt already.
            let aesCipher = cipherState.cipher;
            if (aesCipher === undefined) {
                aesCipher = cipher.createDecipher({
                    key: cipherState.key
                });
            }

            aesCipher.start();
            // Perform decryption and return the message output.
            let messageBuffer = aesCipher.update(cipherBuffer);
            if (messageBuffer === undefined) {
                return;
            }

            return messageBuffer;
        }


        /**
         * @brief Encrypts the seif record into an encrypted record
         *        using the encrypt() helper function.
         *
         * @param record the seif record to encrypt
         * @param s the ConnectionState to use
         *
         * @return buffer cipher buffer
         */
        function encryptFunction(record, s) {
            logger.trace('Encrypt operation');

            // Encrypting using the helper function.
            return encrypt(s.cipherState, record);
        }


        /**
         * @brief Decrypts a cipher record into the original decrypted seif
         *        record using the decrypt() helper function.
         *
         * @param buffer the seif record buffer to decrypt
         * @param s the ConnectionState to use
         *
         * @return buffer decrypted message buffer
         */
        function decryptFunction(record, s) {
            logger.trace('Decrypting operation');

            // Decrypting using the helper function.
            return decrypt(s.cipherState, record);
        }


        /**
         * @brief Function responsible for initializing the connection state
         *        with the cipher encrypt/decrypt functions and keys.
         *
         * @param state connection state with read and write states
         * @param isInitiator indicating whether party is an initiator or not
         * @param sp security parameters associated with the connection
         *
         * @return None
         */
        function initConnectionState(state, isInitiator, sp) {
            logger.trace('Init connection state');

            // Cipher setup
            state.read.cipherState = {

                cipher: cipher.createDecipher({
                    key: sp.keys.secretKey,
                    isInitiator
                }),
                key: sp.keys.secretKey
            };

            state.write.cipherState = {

                cipher: cipher.createCipher({
                    key: sp.keys.secretKey,
                    isInitiator
                }),
                key: sp.keys.secretKey
            };

            state.read.cipherFunction = decryptFunction;
            state.write.cipherFunction = encryptFunction;
        }


        // Object corresponding to the SEIF_ECC_WITH_AES_256 encryption scheme
        return Object.freeze({
            name: 'SEIF_ECC_WITH_AES_256',
            initSecurityParameters: function (sp) {
                sp.secretKeyLength = 32;
                sp.blockLength = 16;
            },
            initConnectionState,
            encrypt,
            decrypt
        });
    }

    return getCipherSuites;
}

module.exports = initialize();
