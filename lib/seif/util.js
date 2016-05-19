/** @file util.js
 *  @brief File containing the utility functions used in the protocol
 *         implementation.
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
    function createStringBuffer() {
        logger.trace("Creating new string data queue.");

        let bufferData = ""; // contains the string data
        let readPointer = 0; // indicates how much of the data has been read


        /**
         * @brief Clears the string data and resets the read pointer.
         *
         * @return none
         */
        function clear() {
            bufferData = "";
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
            bufferData += data;
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
        let power = 1;
        let totalExtract = 0;

        while (b.length > 0) {
            let currentExtract = Math.pow(2, power + 1);
            totalExtract += currentExtract;
            let numBytes = b.slice(0, currentExtract);

            let num = parseInt(numBytes, 16);
            if (num !== 0) {
                return {
                    result: num,
                    length: totalExtract
                };
            }
            power = power + 1;
            b = b.slice(currentExtract);
        }

        return undefined;
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
        let log2Length = Math.log2(result.length);
        let power = Math.floor(log2Length);
        let resultLen = (log2Length % 1 || log2Length <= 1)
            ? power + 1
            : power;

        let numZeroes = Math.pow(2, resultLen) - result.length;
        let j = 1;
        while (j < resultLen - 1) {
            numZeroes += Math.pow(2, j + 1);
            j = j + 1;
        }

        let i = 0;
        while (i < numZeroes) {
            result = "0" + result;
            i = i + 1;
        }

        return {
            result,
            length: result.length
        };
    }

    return Object.freeze({
        getNumberFromBytes,
        getBytesFromNumber,
        createStringBuffer
    });

}

module.exports = initialize();