/** @file isaacrng.js
 *  @brief File containing the functions accessing the isaac rng service
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

    const cp = require('child_process'); // Enable forking/spawning processes.
    const loggerGenerator = require("../log"); // Enable logging.
    const net = require("net"); // Enable network services.
    const createDeque = require("../seifDeque"); // Deque to save requests.
    const logger = loggerGenerator.child( // Logger to log data.
        {
            componentName: "ISAAC_RNG"
        }
    );
    const rngServicePort = 9993; // Port to connect to reach random service.

    /**
     * @brief Main function returned when the module is required to create the
     *        the object enabling connection to the random number service.
     *
     * @param pwd is a buffer with the hash to encrypt random generator state.
     * @param fileName is a string with the file name to hold random
     *        generator state.
     * @param rngCallback is a function to be invoked after a connection with
     *        the random number service is established.
     *        'function rngCallback(rngObject)', where, rngObject contains:
     *         getBytes - function takes number of bytes as an int and
     *                    a callback function which is invoked with
     *                    random bytes from the generator.
     *         destroy - function severs the connection with the random
     *                   number service.
     *
     */
    function createRNG(pwd, fileName, rngCallback) {
        let generatorId; // Id assigned by a random number service.

        // Object with a reference to the connection with random number service.
        let socketHandler = {
            socket: undefined
        };

        // Mapping between requests and callbacks to handle responses.
        let funcMap = new Map();

        let requestQueue = createDeque(); // Queue recieved requests for random.

        // Request Ids.
        let id = 0;

        /* Boolean indicating if a working connection exists with
         * the random service.
         */
        let connectedToRandomService = false;

        /* Boolean indicating if a random service is
         * in the process of/has been established.
         */
        let isStartingService = false;

        // Holds child process object corresponding to random service.
        let rngService;

        /**
         * @brief Process a JSON recieved from the random service.
         *
         * @param data is a JSON recieved from the random service.
         *
         */
        function processData(data) {

            // Dequeue from the request Queue since we recieved a reponse.
            requestQueue.removeFront();

            /* Find the callback associated with the header field
             * of the response.
             */
            let mapKey = JSON.stringify(data.header);
            let callback = funcMap.get(mapKey);
            // Delete entry from the map since we will no longer need it.
            funcMap.delete(mapKey);

            // Invoke the callback.
            if (callback !== undefined) {
                callback(data);
            }
        }

        /**
         * @brief Requests the rng service to initialize a random generator
         *        associated with some credentials.
         *
         */
        function initializeRNG() {

            // Id to map relevant callback on response as part of the header.
            id = id + 1;

            /* Request JSON to initialize the random generator with state stored
             * in fileName encrypted with pwd. The header field enables mapping
             * a response to this request. The op field informs the random
             * service to initialize this generator if not already so.
             */
            let initRequest = {
                header: {
                    id
                },
                op: "initialize",
                pwd: pwd.toString("hex"),
                fileName
            };

            // Key to map function associated with the request.
            let mapKey = JSON.stringify(initRequest.header);

            // Set key and define function to handle response.
            funcMap.set(mapKey, function (response) {

                /* Response should contain an id assigned by the random service.
                 * This id will be sent as part of any further communication
                 * with the random service.
                 */
                generatorId = response.id;
                if (response.id !== undefined) {

                    logger.trace("Initialized RNG service.");

                    /* Set state to be successfully connected to the random
                     * service with initialization.
                     */
                    connectedToRandomService = true;

                    /* Check if rngCallback has been invoked, if so we
                     * do not need to define functions to interact with a
                     * generator hosted by the random service again.
                     */
                    if (rngCallback !== undefined) {

                        /**
                         * @brief Makes a request to the random service to get
                         *        bytes from the associated generator.
                         *
                         * @param numBytes is an array or a natural number
                         *        indicating number of random bytes desired for
                         *        each number in the array.
                         * @param saveState flag indicating if RNG state needs
                         *        to be saved
                         * @param callback is a function which is invoked on
                         *        recieving random bytes from the associated
                         *        generator.
                         *        'function callback(byteArray)', where,
                         *            byteArray: is an array of random numbers,
                         *                       or just a random number.
                         *
                         */
                        let getBytes = function (numBytes, saveState, callback) {

                            // Id to map relevant callback on response.
                            id = id + 1;

                            /* Request JSON has fields: header used to enable
                             * internal mapping when a reponse is recieved,
                             * op indicates that the desired operation is to get
                             * random bytes, id has the generator id assigned by
                             * the random service, numBytes is an array or a
                             * natural number indicating number of bytes for a
                             * number or for each in the array.
                             */
                            let request = {
                                header: {
                                    id
                                },
                                op: "getBytes",
                                id: generatorId,
                                numBytes,
                                saveState
                            };

                            // Key to map function associated with the request.
                            let requestString = JSON.stringify(request);
                            let funcMapKey = JSON.stringify(request.header);

                            // Set key and define function to handle response.
                            funcMap.set(funcMapKey, function (response) {
                                callback(response.random);
                            });

                            /* Enqueue the request for random bytes, to be
                             * sent again if the random service fails/is reset.
                             */
                            requestQueue.insertBack(requestString);

                            /* Check if connection with random service is still
                             * valid, if so write the request on the socket
                             * established with the random service.
                             */
                            if (connectedToRandomService === true) {
                                socketHandler.socket.write(
                                    requestString + "\r\n"
                                );
                            }
                        };

                        /**
                         * @brief Disconnects from the random service.
                         *
                         */
                        let destroy = function () {
                            logger.info("Asked to be destroyed?");
                            /* Sever the socket established with the random
                             * service
                             */
                            socketHandler.socket.end();
                            socketHandler.socket.destroy();
                        };

                        /* Object which rngCallback is invoked with to enable
                         *  interaction with the associated random generator.
                         */
                        let rngObject = Object.freeze({
                            getBytes,
                            destroy
                        });

                        logger.trace("Init complete.");

                        // call rngCallback and make it undefined.
                        rngCallback(rngObject);
                        rngCallback = undefined;
                        return;
                    }

                    /* resend requests that did not get a response on an
                     * earlier connection with the random service.
                     */
                    requestQueue.forEach(function (requestString) {
                        socketHandler.socket.write(requestString + "\r\n");
                    });

                    logger.trace("Reinit complete.");
                }
            });

            /* Write the request on the socket established with
             * the random service.
             */
            socketHandler.socket.write(JSON.stringify(initRequest) + "\r\n");
        }

        /**
         * @brief Establishes a connection with an existing random service or
         *        starts one before attempting to connect again.
         *
         */
        function connectToRandomService() {

            /**
             * @brief Starts the random service.
             *
             */
            function startRandomService() {

                // Check if in the process of starting a service already.
                if (isStartingService === true) {
                    return;
                }

                /* Set boolean to indicate starting the service is in progress,
                 * or has already been established.
                 */
                isStartingService = true;

                // Fork the rng service from the module install directory.
                let execString = __dirname + "/rng.js";
                rngService = cp.fork(execString);

                /* On recieving a "OK" message from the random service,
                 * signifying an up and ready state to accept connections.
                 * Attempt to connect.
                 */
                rngService.on("message", function (message) {
                    if (message !== undefined && message.status === "OK") {
                        logger.trace("Got OK from random service.");

                        // Connect to random service.
                        connectToRandomService();
                    }
                });

                /* On rngService exit, attempt to reconnect or re-establish
                 * the random service if desired.
                 */
                rngService.on('exit', function (code) {
                    // Reset isStartingService.
                    isStartingService = false;

                    logger.error({code}, "Service exitted.");

                    /* If the exit wasn't a desired effect attempt to reconnect
                     * or re-establish the random service.
                     */
                    if (code !== 0) {
                        connectToRandomService();
                    }
                });
            }

            // Create a socket and store the reference to it in socketHandler.
            socketHandler.socket = new net.Socket();

            // Set encoding type for the socket.
            socketHandler.socket.setEncoding("utf8");

            // Connect to the random service listening at rngServicePort.
            socketHandler.socket.connect(rngServicePort);

            /* On successfully connecting with the random service, request
             * initialization of a random generator.
             */
            socketHandler.socket.on("connect", function () {
                logger.trace("Connected to the RNG service");
                initializeRNG();
            });

            /* On connection close event with the random service, an attempt
             * will be made if the close was not desired. If not
             * connectedToRandomService is reset.
             */
            socketHandler.socket.on("close", function () {
                connectedToRandomService = false;
            });

            /* On connection error event with the random service, an attempt
             * will be made to reconnect/re-establish service if the connection
             * was terminated by the random service.
             */
            socketHandler.socket.on("error", function (error) {

                logger.error(error);

                /* Check if the random service wasn't reachable, if so establish
                 * the random service.
                 */
                if (error.code === "ECONNREFUSED") {

                    // Establish the random service.
                    startRandomService();
                    return;
                }

                // Attempt to reconnect with the random service.
                connectToRandomService();
            });

            /* On connection end event with the random service, an attempt
             * will be made to reconnect/re-establish service if the connection
             * was terminated by the random service.
             */
            socketHandler.socket.on("end", function () {
                connectToRandomService();
            });

            /**
             * @brief Returns a function which buffers data on the socket
             *        and parses when possible.
             *
             * @return A function which buffers data from the socket and parses
             *         when possible.
             *
             */
            function dataHandler() {
                // Buffer for socket data.
                let chunk = "";
                return function (data) {

                    // Buffer data.
                    chunk += data;

                    // Search for "\r\n" to identify parsable chunk of data.
                    let nIndex = chunk.indexOf("\r\n");

                    // While a valid index exists parse such chunks of data.
                    while (nIndex > -1) {

                        // Extract parsable chunk.
                        let currentData = chunk.substring(0, nIndex);

                        // Parse chunk.
                        currentData = JSON.parse(currentData);

                        // Process chunk.
                        processData(currentData);

                        // Advance over chunk separator.
                        chunk = chunk.substring(nIndex + 2);

                        // Search for "\r\n" to identify parsable chunk of data.
                        nIndex = chunk.indexOf("\r\n");
                    }
                };
            }

            /* On recieving data from the random service, buffer data and parse
             * when possible.
             */
            socketHandler.socket.on("data", dataHandler());
        }

        /* If rngCallback is valid, attempt to connect to random service or
         * start one before connecting.
         */
        if (rngCallback !== undefined && typeof rngCallback === 'function') {
            connectToRandomService(rngCallback);
        }

    }

    return createRNG;
}

module.exports = initialize();
