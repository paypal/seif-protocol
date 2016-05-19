/** @file seifCache.js
 *  @brief File containing the implementation of a secure cache which encrypts
 *         the data stored in the cache using the given key.
 *
 *  @author Aashish Sheshadri
 *  @author Rohit Harchandani
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2016 PayPal
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

function initialize() {
    'use strict';

    // Enable logging.
    let loggerGenerator = require("./log");
    let logger = loggerGenerator.child({componentName: "SEIF_CACHE"});

    /**
     * @brief Main function returned when the module is required to create the
     *        the object enabling connection to the random number service.
     *
     * @param cache is an object that supports read, write and clear operations.
     * @param dataKey is the encryption key used to ecrypt data before writing
     *        to the cache or used to decrypt cache data.
     * @param cipherSuite is a object that enables encryption and decryption of
     *        data when provided with a cipher key.
     *
     * @return an object with properties:
     *         read: reads entryped data from the underlying cache and invokes
     *               the callback with decrypted message.
     *         write: wites key value pair to the underlying cache after
     *                encrypting the value in the presence of a valid
     *                cipher suite.
     *         clear: clears entry from the underlying cache.
     *
     */
    function createSeifCache(cache, dataKey, cipherSuite) {

        // A cache object supporting key,value read and write.
        cache = cache || {};

        /* Encryption is enabled by default. It is disabled in the absence of
         * a valid encryption key or cipher suite.
         */
        let encryptionEnabled = true;
        if (dataKey === undefined || cipherSuite === undefined) {
            encryptionEnabled = false;
        }

        /**
         * @brief Performs a `key' look-up to retrieve associated data from
         *        the underlying cache.
         *
         * @param key is used to look-up the underlying cache for an associated
         *        value.
         * @param callback is a function invoked with the retrived message. In
         *        the case where decryption/look-up fails, the message is
         *        undefined and the error is passed along.
         *
         * @return none
         */
        function read(key, callback) {

            // Default callback in the case where it is undefined.
            callback = callback || function (response, error) {
                if (error !== undefined) {
                    logger.error(error);
                    return;
                }
                logger.trace({response});
            };

            // Checking if the underlying cache has read support.
            if (
                cache.read === undefined
                || typeof cache.read !== "function"
            ) {

                // Invoking callback, since no look up can be performed.
                callback();
                return;
            }

            /* Invoking read on the underlying cache for `key'. Response will
             * be handled by a callback.
             */
            cache.read(key, function (response, error) {
                // Handling response.

                /* If error or response in undefined, call invoker callback
                 * with error.
                 */
                if (error !== undefined || response === undefined) {
                    callback(undefined, error);
                    return;
                }

                // Check if decryption is required.
                if (encryptionEnabled === true) {

                    // Setup cipher state to decrypt cipher.
                    let cipherState = {
                        key: dataKey
                    };

                    // Attempt to decryt message.
                    let message;
                    try {
                        message = cipherSuite.decrypt(cipherState, response);
                        logger.trace(
                            {
                                key,
                                value: message
                            },
                            "Looking up seif cache."
                        );
                    } catch (ex) {
                        // Decryption failed.

                        logger.error(ex);

                        /* Call invoker callback with undefined value and the
                         * exception.
                         */
                        callback(undefined, ex);

                        return;
                    }

                    /* Call the invoker callback with the recovered value
                     * associated with the `key'.
                     */
                    callback(message, undefined);

                } else {

                    /* Call the invoker callback with the looked up value
                     * associated with the `key'.
                     */
                    callback(response, undefined);
                }
            });
        }

        /**
         * @brief Writes a key-value pair to underlying cache.
         *
         * @param key is a unique value used to associate data for look-up.
         * @param value is the data associated with an unique `key'
         * @param callback is a function invoked after an attempted write to the
         *        underlying cache.
         *
         * @return none
         */
        function write(key, value, callback) {

            // Default callback in the case where it is undefined.
            callback = callback || function (response, error) {
                if (error !== undefined) {
                    logger.error(error);
                    return;
                }
                logger.trace({response});
            };

            // Checking if the underlying cache has write support.
            if (
                cache.write === undefined
                || typeof cache.write !== "function"
            ) {

                // Invoking callback, since no write can be performed.
                callback();
                return;
            }

            logger.trace({key, value}, "Writing to seif cache.");

            // Checking if a key is provided.
            if (key === undefined) {

                /* Cannot write to cache without a key. Invoke callback with
                 * an error.
                 */
                callback(undefined, new Error("No cache key provided."));
                return;
            }

            // Check if encryption is required before write.
            if (encryptionEnabled === true) {

                // Set up cipher state to encrypt with dataKey.
                let cipherState = {
                    key: dataKey
                };

                // Attempt to encrypt.
                try {

                    // Encrypt value using the cipher suite.
                    let cipher = cipherSuite.encrypt(cipherState, value);

                    /* Write encrypted value with associated key to the
                     * underlying cache.
                     */
                    cache.write(key, cipher, callback);
                } catch (ex) {

                    /* Encryption failed. Invoke callback with an undefined
                     * response and the exception.
                     */
                    logger.error(ex);
                    callback(undefined, ex);
                }
            } else {

                /* Write key-value pair to the underlying cache without
                 * encryption.
                 */
                cache.write(key, value, callback);
            }
        }

        /**
         * @brief Clears a key-value pair from the underlying cache.
         *
         * @param key is the unique value associated with data to be cleared
         *        from the cache.
         * @param callback is a function invoked after an attempted deletion of
         *        the key-value pair from the underlying cache.
         *
         * @return none
         */
        function clear(key, callback) {

            // Default callback in the case where it is undefined.
            callback = callback || function (response, error) {
                if (error !== undefined) {
                    logger.error(error);
                    return;
                }
                logger.trace({response});
            };

            // Checking if the underlying cache has support to clear values.
            if (
                cache.clear === undefined
                || typeof cache.clear !== "function"
            ) {

                // Invoking callback, since no deletion can be performed.
                callback();
                return;
            }

            // Checking if a key is provided.
            if (key === undefined) {

                /* Cannot delete value without its key. Invoke callback with
                 * an error.
                 */
                callback(undefined, new Error("No cache key provided."));
                return;
            }

            // Delete key-value pair from the underlying cache without
            cache.clear(key, callback);
        }

        // Return an object with read, write and clear capabilities.
        return Object.freeze({
            read,
            write,
            clear
        });

    }

    return createSeifCache;
}

module.exports = initialize();