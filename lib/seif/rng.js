/** @file rng.js
 *  @brief File containing the implementation of the isaac RNG service
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

function startRNGService() {

    'use strict';

    const seifnode = require("seifnode"); // Enable Seifnode for SHA3-256
    const net = require("net"); // Enable network services.

    const hasher = seifnode.SEIFSHA3(); // Enable SHA3-256 hashing - Seifnode.

    const listenPort = 9993; // Port to listen on for incoming connections.

    let generatorMap = new Map(); // Map to store/access random generators.

    let numConnections = 0; // Number of active connections.

    // On process abrupt exit, call exit with error code 1.
    process.on('SIGINT', function () {
        process.exit(1);
    });

    // On process exit, destroy all generators initiated so as to update state.
    process.on("exit", function () {
        generatorMap.forEach(function (generatorObject) {
            generatorObject.generator.destroy();
        });
    });

    /**
     * @brief Initializes a random generator and informs listeners when ready.
     *
     * @param generatorObject is a JSON with generator credentials, listeners.
     *
     */
    function startRNG(generatorObject) {

        // Get seifnode random generator.
        let generator = generatorObject.generator;

        /* Check if generator is seeded, i.e, state file is present
         * and decryption is successful. If not, seed a new generator.
         */
        generator.isInitialized(
            generatorObject.pwd,
            generatorObject.fileName,
            function (result) {

                /* If not seeded, call initialize to gather entropy
                 * and seed the random generator.
                 */
                if (result.code !== 0) {

                    generatorObject.socketArray.forEach(function (item) {
                        item.socket.end();
                        item.socket.destroy();
                    });
                    generatorMap.delete(generatorObject.id);

                    return;
                }

                // Loaded state successfully, set generator as initialized.
                generatorObject.isInitialized = true;

                /* Inform listeners that the generator is ready to process
                 * requests.
                 */
                generatorObject.socketArray.forEach(function (item) {
                    item.socket.write(JSON.stringify(item.response) + "\r\n");
                });

                // Delete all informed listeners.
                delete generatorObject.socketArray;
            }
        );
    }

    /**
     * @brief Processes a request recived and responds as appropriate.
     *
     * @param request is a JSON recieved from the random service.
     * @param response is a JSON to be sent after being populated.
     * @param socket is a reference to the connection socket.
     *
     * @return boolean true if response should be written on the socket.
     *
     */
    function processData(request, response, socket) {

        // Get operation from request.
        let op = request.op;

        // Define variables to handle request.
        let generatorObject, generator, id;

        // Check if request is for random bytes.
        if (op === "getBytes") {

            // Get request byte count.
            let numBytes = request.numBytes;

            // Get generator id assigned by this service.
            id = request.id;

            // Get the associated generator.
            generatorObject = generatorMap.get(id);

            // Unknown id.
            if (generatorObject === undefined) {
                response.error = true;
                return true;
            }

            // Get the random generator from the generator object.
            generator = generatorObject.generator;

            /* Check if the request if for an array of random bytes. Call the
             * random generator accordingly.
             */
            if (Array.isArray(numBytes) === true) {

                /* Response will contain an array with random bytes,
                 * each of length as determined by request array numBytes.
                 */
                response.random = [];
                numBytes.forEach(function (num) {
                    response.random.push(
                        generator.getBytes(num).toString("hex")
                    );
                });
            } else {

                // Response is a random string of length numBytes.
                response.random = generator.getBytes(numBytes).toString("hex");
            }

            // Save the RNG state if requested to do so.
            if (request.saveState === true) {
                generator.saveState(
                    function (error) {
                        if (error !== undefined) {
                            console.info(error);
                        }
                    }
                );
            }

            // Write the response.
            return true;
        }

        // Check if request is to initialize a random generator.
        if (op === "initialize") {

            // Parse filename from request.
            let fileName = request.fileName;

            // Parse credentials of the random generator.
            let key = {
                pwd: request.pwd,
                fileName
            };

            /* SHA3-256 hash of the key JSON will be used as the key for
             * generator look up.
             */
            let idBuffer = hasher.hash(JSON.stringify(key));

            // Key for lookup/storing the generator.
            id = idBuffer.toString("hex");

            // Lookup for generator object, if initialized previously.
            generatorObject = generatorMap.get(id);

            // Assign id as the lookup key.
            response.id = id;

            // If a valid generator was not found, spawn and initialize one.
            if (generatorObject === undefined) {

                // Decryption key for random generator state.
                let pwd = new Buffer(request.pwd, "hex");

                // Instantiate a random generator from seifnode.
                generator = new seifnode.RNG();

                /* Populate generator object with seifnode random generator
                 * credentials, initialization state and listeners waiting for
                 * initialization.
                 */
                generatorObject = {
                    id,
                    pwd,
                    fileName,
                    generator,
                    isInitialized: false,
                    socketArray: [{response, socket}]
                };

                // Store generator.
                generatorMap.set(id, generatorObject);

                // Initialize and start the generator.
                startRNG(generatorObject);

                /* Response will be written after initialization. Response
                 * object is stored in the generator object along with the
                 * corresponding connection.
                 */
                return false;
            }

            /* If generator is not yet initialized, add connection to its set
             * of listeners.
             */
            if (generatorObject.isInitialized === false) {
                generatorObject.socketArray.push({response, socket});

                /* Response will be written after initialization. Response
                 * object is stored in the generator object along with the
                 * corresponding connection.
                 */
                return false;
            }

            /* Generator is initialized and ready to process requests. Write
             * to the requestor the look up id for correspondence in the future.
             */
            return true;
        }

        // Unknown request; ignored.
        return false;
    }

    // Create server to handle connections from clients requesting random.
    let service = net.createServer(function (socket) {

        // Increment numConnections to account for this connection.
        numConnections = numConnections + 1;

        // Set utf8 as the default encoding of the socket.
        socket.setEncoding("utf8");

        // Buffer data from the socket.
        let chunk = "";

        /* On recieving data from the random service, buffer data and parse
         * when possible.
         */
        socket.on('data', function (data) {

            /**
             * @brief Process a JSON recieved on the connection.
             *
             * @param request is a JSON recieved from the requestor.
             *
             */
            function processRequest(request) {
                let response = {}; // Response object.
                response.header = request.header; // Add request header.

                // Attempt to respond to the request.
                try {

                    // invoke processData to handle response.
                    let result = processData(request, response, socket);
                    if (result === false) {
                        return;
                    }
                } catch (ex) {
                    console.log(ex);
                    response = {};
                }

                // Write response JSON and add "\r\n" as a delimiter.
                socket.write(JSON.stringify(response) + "\r\n");
            }

            chunk += data; // Buffer data on the socket.

            // Search for "\r\n" to identify parsable chunk of data.
            let nIndex = chunk.indexOf("\r\n");

            // While a valid index exists parse such chunks of data.
            while (nIndex > -1) {

                // Extract parsable chunk.
                let currentData = chunk.substring(0, nIndex);

                // Parse chunk.
                currentData = JSON.parse(currentData);

                // Process chunk.
                processRequest(currentData);

                // Advance over chunk separator.
                chunk = chunk.substring(nIndex + 2);

                // Search for "\r\n" to identify parsable chunk of data.
                nIndex = chunk.indexOf("\r\n");
            }
        });

        // On connection close event, decrement number of connections by one.
        socket.on("close", function () {
            numConnections = numConnections - 1;

            // If service has no active connections, quit service.
            if (numConnections === 0) {
                process.exit(0);
            }
        });
    });

    /* On error in an attempt to listen on listenPort while it is already in
     * use, quit service, since a random service is already active of the port
     * is in use by some other service.
     */
    service.on('error', function (error) {
        if (error.code === 'EADDRINUSE') {
            process.exit(1);
        }
    });

    // Attempt to listen on listenPort for connections to random service.
    service.listen(listenPort, function () {

        // On listening event inform parent process on success.
        let okResponse = {
            status: "OK"
        };

        process.send(okResponse);

    });
}

// Attempt to start random service.
startRNGService();
