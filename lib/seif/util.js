/** @file util.js
 *  @brief File containing the utility functions used in the protocol
 *         implementation.
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
 *        utility object.
 *
 * @return object object containing the utility functions.
 */
function initialize() {

    'use strict';
    let loggerGenerator = require("../log");
    let logger = loggerGenerator.child({componentName: "SEIF_UTIL"});

    /**
     * @brief This function is responsible for creating a string data queue.
     *
     * @return object object containing the string queue functions:
     *                clear,
     *                compact,
     *                size,
     *                getData,
     *                insertData,
     *                removeData,
     *                toString
     */
    function createBuffer() {
        logger.trace("Creating data queue.");

        let bufferData = Buffer.alloc(0); // contains the string data
        let readPointer = 0; // indicates how much of the data has been read


        /**
         * @brief Clears the string data and resets the read pointer.
         *
         * @return none
         */
        function clear() {
            bufferData = Buffer.alloc(0);
            readPointer = 0;
        }


        /**
         * @brief Clears the read string data and resets the read pointer.
         *
         * @return none
         */
        function compact() {
            if (readPointer > 0) {
                bufferData = bufferData.slice(readPointer);
                readPointer = 0;
            }
        }


        /**
         * @brief Gets the size of queue which is equivalent to the unread
         *        string data.
         *
         * @return number length of the unread string data
         */
        function size() {
            return bufferData.length - readPointer;
        }


        /**
         * @brief Gets the unread data from the queue upto the given length. If
         *        no length is provided all the unread string data is returned.
         *
         * @param length length of string data required from the queue
         *
         * @return string unread string data from the queue.
         */
        function getData(length) {
            if (typeof length === "number") {
                return bufferData.slice(readPointer, readPointer + length);
            }

            return bufferData;
        }


        /**
         * @brief Inserts data into the queue.
         *
         * @param data string data to be inserted into the queue
         *
         * @return none
         */
        function insertData(data) {
            bufferData = Buffer.concat(
                [bufferData, data],
                bufferData.length + data.length
            );
        }


        /**
         * @brief Gets the unread data from the queue upto the given length. If
         *        no length is provided all the unread string data is returned.
         *        The returned data is removed from the queue as well.
         *
         * @param length length of string data required from the queue
         *
         * @return string unread string data from the queue.
         */
        function removeData(length) {
            let result;

            if (typeof length === "number") {
                length = Math.min(size(), length);
                result = bufferData.slice(readPointer, readPointer + length);
                readPointer += length;
            } else {
                if (readPointer === 0) {
                    result = bufferData;
                } else {
                    result = bufferData.slice(readPointer);
                }
                clear();
            }

            return result;
        }


        /**
         * @brief Returns string representation of the string queue.
         *
         * @return string representation of the string queue
         */
        function toString() {
            return JSON.stringify({
                bufferData,
                readPointer
            });
        }

        return Object.freeze({
            clear,
            compact,
            size,
            getData,
            insertData,
            removeData,
            toString
        });
    }


    /**
     * @brief Takes a string and returns the number represented by the first
     *        two bytes of the hex string.
     *
     * @return object object containing the numeric result and the length of the
     *                string used to get the number
     */
    function getNumberFromBytes(b) {
        return Number.parseInt(b.toString('hex'), 16);
    }


    /**
     * @brief Takes a number as argument and returns the string representation
     *        of the number in hex format.
     *
     * @return object object containing the string result and the length of the
     *                string result
     */
    function getBytesFromNumber(length) {

        let result = length.toString(16);

        if (result.length % 2 !== 0) {
            result = '0' + result;
        }

        let returnBuffer = Buffer.from(result, 'hex');

        if (returnBuffer.length < 2) {
            returnBuffer = Buffer.concat([Buffer.alloc(1), returnBuffer], 2);
        }

        return returnBuffer;
    }

    return Object.freeze({
        getNumberFromBytes,
        getBytesFromNumber,
        createBuffer
    });

}

module.exports = initialize();
