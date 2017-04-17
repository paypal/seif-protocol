/** @file seifParty.js
 *  @brief File containing the implementation of the seif party which the
 *         application has access to and can use to connect to other parites
 *         using the seif protocol.
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

    let net = require('net');
    let EventEmitter = require('events');

    let loggerGenerator = require("./log");

    let seif = require('./seif/seif');
    let getCipherSuite = require("./seif/cipherSuite");
    let createSeifCache = require("./seifCache");
    let idGenerator = require("./seif/idGenerator");

    let createDeque = require("./seifDeque");

    let logger = loggerGenerator.child({componentName: "SEIF_PARTY"});

    let getEntityManagementUtil = require("./entityManagementUtil");

    let getConfig = require('./config');

    /**
     * @brief Main function returned when the module is required. This is a
     *        generator function for generating seif parties.
     *
     * @return function party generator function
     */
    function seifPartyGenerator() {

        let config = getConfig();

        /**
         * @brief Generates the party object based on the given input
         *
         * @param input object containing initialization parameters:
         *              entity
         *              password
         *              logger
         *              hostCache
         *
         * @param callback callback to be called once the party has been created
         *                 and initialized.
         *                 function callback(partyObjectGenerator, error)
         *                 where,
         *                 partyObjectGenerator: function which creates the
         *                                       party object representing the
         *                                       current party with ability to
         *                                       perform the following:
         *                                       connect,
         *                                       send,
         *                                       sendStatus,
         *                                       end,
         *                                       listen,
         *                                       seifEventEmitter,
         *                                       destroy,
         *                                       properties
         *                 error: Error object generated while creating party
         *
         *
         * @return none
         */
        function seifParty(input, callback) {

            if (typeof input !== "object") {
                return callback(undefined, new Error("Bad Input."));
            }

            loggerGenerator.update(input.logger);

            let entity = input.entity;
            let password = input.password;
            let hostCache = createSeifCache(input.hostCache);
            let seifRNG;

            let cipherSuite = getCipherSuite();

            // Instantiate the authentication utility using the given config.
            let entityManagementUtil =
                    getEntityManagementUtil({folder: config.folder});


            /**
             * @brief Function to be invoked once the entity auth is complete.
             *        This function creates the seif party and invokes the
             *        given callback.
             *
             * @param entityIdentity object containing party info:
             *                     keys - public(enc)/private(dec) key pair
             *                     seifECC - ecc encryption/decryption object
             *                     seifRNG - isaac rng object
             * @param authError error due to identity authentication
             *
             * @return ECC encrypted cipher buffer
             */
            function useIdentity(entityIdentity, authError) {

                // Error logging in.
                if (authError !== undefined) {
                    logger.error({authError}, "Authentication error.");

                    return callback(undefined, new Error(authError.message));
                }

                // Successful authentication.
                logger.trace({entityIdentity}, "Authentication Complete.");

                let keys = entityIdentity.keys;
                let seifECC = entityIdentity.seifECC;
                if (seifRNG === undefined) {
                    seifRNG = entityIdentity.seifRNG;
                }

                /**
                 * @brief Uses the ECCISAAC object generated at login to
                 *        encrypt the message with the given key.
                 *
                 * @param key public key to encrypt the message with
                 * @param message message to be encrypted
                 *
                 * @return ECC encrypted cipher buffer
                 */
                function eccEncrypt(key, message) {
                    return seifECC.encrypt(key, message);
                }


                /**
                 * @brief Uses the ECCISAAC object generated at login to
                 *        decrypt the cipher with the given key.
                 *
                 * @param key public key to decrypt the cipher with.
                 * @param cipher cipher to be decrypted.
                 *
                 * @return decrypted message buffer
                 */
                function eccDecrypt(key, cipher) {
                    return seifECC.decrypt(key, cipher);
                }

                /**
                 * @brief Creates the party using the given initialized RNG.
                 *
                 * @return object generated party object which has the following
                 *                attributes:
                 *                connect,
                 *                send,
                 *                sendStatus,
                 *                sendUnreliableMessage,
                 *                end,
                 *                listen,
                 *                seifEventEmitter,
                 *                destroy,
                 *                properties
                 */
                function createParty() {

                    let petName; // pet name of the host being connected to
                    // connection object when the party is an initiator
                    let seifInitiatorConnection;
                    // queue of messages being processed as an initiator
                    let messageQueue;
                    // queue of messages not been processed by the initiator
                    let workItemQueue;
                    // flag indicating the initiator party is connected
                    let partyIsConnected = false;
                    // flag indicating the party has a connection in progress
                    let connectionInProgress = false;
                    /* object to trigger events in the application
                     * creating the parties
                     */
                    let eventEmitter = new EventEmitter();
                    // function to generate message ids
                    let generateMessageId = idGenerator();


                    /**
                     * @brief The protocol invokes this function when seif
                     *        connection has received a permanent redirect
                     *        and we need to update the host cache
                     *        containing the pet name to party details
                     *        mappings.
                     *
                     * @param connection seif connection object
                     *
                     * @return none
                     */
                    function updateHostCache(
                        hostData,
                        updateCallback
                    ) {
                        /* Default cache key is the petname of the connected
                         * party.
                         */
                        let key = petName;
                        if (hostData.key !== undefined) {
                            key = hostData.key;
                        }

                        if (key !== undefined) {
                            hostCache.write(
                                key,
                                hostData.value,
                                updateCallback
                            );
                        }
                    }


                    /**
                     * @brief Returns a reference to the event emitter.
                     *        This is used by the caller to get access to the
                     *        "message" events.
                     *
                     * @return object event emitter object
                     */
                    function seifEventEmitter() {
                        return eventEmitter;
                    }


                    /**
                     * @brief Creates connection to the given host and executes
                     *        the callback once the connection has been
                     *        established.
                     *
                     * @param hostData properties of the listening party:
                     *                 connectAddress - ip-address + port
                     *                 connectPublicKey - public-key
                     * @param options Other options for the connection:
                     * @param connectCallback function to be called once
                     *                        connection has been established.
                     *                        function callback(error)
                     *                        where, error - connection error
                     *
                     * @return none
                     */
                    function createConnection(
                        hostData,
                        options,
                        connectCallback
                    ) {
                        logger.trace({hostData}, "Creating seif connection.");

                        let seifConnection; // connection object
                        let socket; // underlying tcp socket

                        // address of remote party being connected to
                        let connectAddress = hostData.connectAddress;
                        // public key of party being connected to
                        let connectPublicKey = hostData.connectPublicKey;
                        // flag indicating if the initiator is redirecting
                        let isRedirecting = false;
                        // flag indicating if the initiator socket is connected
                        let isConnected = false;

                        // Create the message queue for messages being sent.
                        messageQueue = createDeque();

                        /**
                         * @brief This function is responsible for sending
                         *        a message over the established connection.
                         *
                         * @param messageItem object representing message to be
                         *                    sent:
                         *                    messageId - message id
                         *                    options - message options
                         *
                         * @return none
                         */
                        function sendMessage(messageItem) {

                            // message to be sent over the connection
                            let message = messageItem.options.message;

                            // Create message wrapper with the message and id.
                            let messageWrapper = {
                                message,
                                messageId: messageItem.messageId
                            };

                            // Send the message over the connection.
                            seifConnection.prepare(
                                messageWrapper
                            );

                            // Process the next message item if available.
                            workItemQueue.done();
                        }


                        /**
                         * @brief Processes the request object from the
                         *        initiator's message queue.
                         *
                         * @param requestItem Object from the message queue
                         *                    containing the actual message and
                         *                    callback to be invoked if
                         *                    applicable
                         *
                         * @return none
                         */
                        function processWorkItem(requestItem) {
                            // message related options
                            let messageOptions = requestItem.options;

                            // confirmation callback for normal messages
                            let messageCallback = requestItem.callback;

                            // Check if message to be sent is given.
                            if (messageOptions.message === undefined) {
                                eventEmitter.emit(
                                    "seifError",
                                    new Error("No message given to send.")
                                );
                                return;
                            }

                            let messageItem = {
                                options: messageOptions
                            };

                            /* If the message does not need a confirmation, then
                             * we do not need to enqueue the message.
                             */
                            if (messageItem.unreliable !== true) {
                                /* Generate a new message id and enqueue the
                                 * message item.
                                 */
                                messageItem.messageId = generateMessageId();
                                messageItem.messageCallback = messageCallback;
                                messageQueue.insertBack(messageItem);
                            }

                            /* If the party is currently redirecting, then do
                             * not attempt to send the message just yet.
                             */
                            if (isRedirecting !== true) {
                                sendMessage(messageItem);
                            }

                        }

                        /* Create the work item queue with the function to be
                         * invoked when the party is free to process an item.
                         */
                        workItemQueue = createDeque(processWorkItem);

                        /* If the connection options includes a messageQueue,
                         * as in the case of redirecting to a new party, then
                         * push the messages into the workItemQueue.
                         */
                        if (options.messageQueue !== undefined) {
                            while (options.messageQueue.size() !== 0) {
                                workItemQueue.insertBack(
                                    options.messageQueue.removeFront()
                                );
                            }
                        }

                        // Set connection to in progress.
                        connectionInProgress = true;


                        /**
                         * @brief This function is invoked when the seif
                         *        connection needs to be ended. This involves
                         *        ending the tcp connection and destroying the
                         *        socket and also resetting the seif connection
                         *        parameters.
                         *
                         * @param error error object if disconnect is due to an
                         *              error
                         *
                         * @return none
                         */
                        function disconnect(error) {
                            logger.trace('[seif] disconnected');

                            if (
                                isConnected === false
                            ) {
                                return;
                            }

                            // Tcp connection has been ended.
                            isConnected = false;

                            // Destroy the underlying tcp connection socket.
                            socket.end();
                            socket.destroy();

                            // Close and reset the seif connection object.
                            seifConnection.close(error);
                        }


                        /**
                         * @brief Creates a tcp socket and uses it to connect to
                         *        the given host and port.
                         *
                         * @param address address of the party to which a
                         *                connection has to be created. It
                         *                contains:
                         *                host - ip address of the party
                         *                port - listening port of the party
                         *
                         * @return
                         */
                        function tcpConnect(address) {

                            /**
                             * @brief Creates a tcp socket and its event
                             *        handlers.
                             *
                             * @return object created socket object
                             */
                            function createSocket() {

                                logger.trace("Creating socket at initiator.");

                                // Create a TCP socket.
                                let tcpSocket = new net.Socket();

                                // Binary buffers on TCP.
                                if (tcpSocket._readableState === true) {
                                    delete tcpSocket._readableState.decoder;
                                    delete tcpSocket._readableState.encoding;
                                }

                                /* Defining the "connect" event handler. Once
                                 * the tcp connection is established, the seif
                                 * handshake process is carried out.
                                 */
                                tcpSocket.on('connect', function () {
                                    logger.trace(
                                        {
                                            socket: tcpSocket.remoteAddress,
                                            myself: tcpSocket.localPort
                                        },
                                        '[socket] connected'
                                    );

                                    seifConnection.updateRemoteAddress({
                                        host: tcpSocket.remoteAddress,
                                        port: tcpSocket.remotePort
                                    });

                                    // Socket is now connected.
                                    isConnected = true;
                                    // Initiate the seif connection handshake.
                                    seifConnection.handshake();
                                });

                                /* Defining the "data" event handler. Once the
                                 * tcp connection receives any data, it is then
                                 * processed by the seif layer.
                                 */
                                tcpSocket.on('data', function (data) {
                                    logger.trace(
                                        "[socket] reading:" +
                                        data.length
                                    );
                                    seifConnection.process(data);
                                });

                                /* Defining the "end" event handler. Once the
                                 * socket is disconnected, the seif connection
                                 * is terminated too.
                                 */
                                tcpSocket.on('end', function () {
                                    logger.trace('[socket] ended');
                                });

                                // Defining the "close" event handler.
                                tcpSocket.on('close', function (hasError) {
                                    logger.trace('[socket] close event');
                                    isConnected = false;
                                    if (hasError !== true) {
                                        disconnect(
                                            new Error(
                                                "Connection closed by the " +
                                                "other party."
                                            )
                                        );
                                    }
                                });

                                /* Defining the "error" event handler. Invoke
                                 * the seif error handler and disconnect if
                                 * necessary.
                                 */
                                tcpSocket.on('error', function (tcpError) {
                                    logger.error(tcpError);
                                    if (
                                        seifConnection.error(tcpError) ===
                                        false
                                    ) {
                                        disconnect(tcpError);
                                    }
                                });

                                return tcpSocket;
                            }

                            logger.trace(
                                {address},
                                "Connecting via tcp to given address."
                            );

                            // Create the tcp socket for this connection.
                            socket = createSocket();

                            // Use given address to create tcp connection.
                            let port = address.port, host = address.host;

                            /* Create tcp connection using the new socket.
                             * On successful connection, the handshake process
                             * is executed as defined in the socket event
                             * handler.
                             */
                            socket.connect(port, host);
                        }

                        /**
                         * @brief The protocol invokes this function when a seif
                         *        handshake is complete and a connection is
                         *        established. The connection object can now be
                         *        used to send messages. This function invokes
                         *        the callback to the app indicating a
                         *        successful connection.
                         *
                         * @return none
                         */
                        function connected() {
                            logger.trace('[seif] connected');

                            /* Set the initiator party connection to the current
                             * connection object.
                             */
                            seifInitiatorConnection = seifConnection;

                            /* Invoke callback without any errors, indicating
                             * successful seif connection.
                             */
                            connectCallback();

                            // Begin processing messages.
                            workItemQueue.done();
                        }


                        /**
                         * @brief The protocol invokes this function when seif
                         *        data is ready to be sent over the connection.
                         *
                         * @return none
                         */
                        function seifDataReady() {
                            logger.trace(
                                {numRecords: seifConnection.seifRecords.length},
                                "Sending records over socket"
                            );

                            /* Write each of the records ready to be sent using
                             * the tcp socket corresponding to this connection.
                             */
                            seifConnection.seifRecords.forEach(
                                function (record) {
                                    socket.write(record);
                                }
                            );

                            // Delete all the sent seif records.
                            seifConnection.seifRecords.length = 0;
                        }


                        /**
                         * @brief The protocol invokes this function when
                         *        a message has been received on the connection
                         *        and it has been decrypted.
                         *
                         * @return
                         */
                        function dataReady(dataReceived) {
                            // Get the message id from the received data.

                            let messageId = dataReceived.messageId;

                            if (messageId !== undefined) {
                                logger.trace(
                                    {messageId},
                                    "Received message with id."
                                );

                                // Send a success confirmation for this message.
                                seifConnection
                                    .prepareApplicationDataConfirmation(
                                        {
                                            messageId,
                                            confirm: true
                                        }
                                    );
                            }

                            // Emit "message" event for the party to handle.
                            eventEmitter.emit(
                                "message",
                                dataReceived.message
                            );

                        }


                        /**
                         * @brief The protocol invokes this function when seif
                         *        connection is being closed.
                         *
                         * @param error error due to which the connection closed
                         *
                         * @return none
                         */
                        function closed(error) {
                            logger.trace(
                                {error, isRedirecting},
                                '[seif] closed'
                            );

                            // Reset the flags when connection is closed.
                            partyIsConnected = false;
                            connectionInProgress = false;
                            petName = undefined;
                            seifConnection = undefined;
                            seifInitiatorConnection = undefined;

                            /* In case connection is closed due to a redirect,
                             * then nothing more needs to be done.
                             */
                            if (
                                isRedirecting === true &&
                                error !== undefined &&
                                error.message === "Redirecting"
                            ) {
                                return;
                            }

                            /* Give an error for all messages which have not
                             * been confirmed yet.
                             */
                            if (error === undefined) {
                                error = new Error("Connection closed. " +
                                        "Message unconfirmed.");
                            }

                            /* Throw an error for all messages in the message
                             * queue and the work item queue.
                             */
                            let messageItem;
                            while (messageQueue.size() !== 0) {
                                messageItem = messageQueue.removeFront();
                                if (
                                    typeof messageItem.callback ===
                                    "function"
                                ) {
                                    messageItem.callback(
                                        new Error(error.message)
                                    );
                                }
                            }

                            if (workItemQueue.size() > 0) {
                                while (workItemQueue.size() !== 0) {
                                    messageItem = workItemQueue.removeFront();
                                    if (
                                        typeof messageItem.callback ===
                                        "function"
                                    ) {
                                        messageItem.callback(
                                            new Error(error.message)
                                        );
                                    }
                                }
                            }

                            // Emit the "close" event handler with the error.
                            eventEmitter.emit("close", error);
                        }


                        /**
                         * @brief The protocol invokes this function when seif
                         *        connection has encountered an error. If the
                         *        error occurs while establishing the
                         *        connection, then the callback given to
                         *        connect() is invoked.
                         *
                         * @param error seif error encountered
                         *
                         * @return none
                         */
                        function seifError(error) {
                            logger.error(error, '[seif] error');

                            logger.trace({
                                connectionInProgress,
                                isSeifConnected:
                                        seifConnection.isSeifConnected()
                            });

                            /* If the error needs to be informed modify the
                             * error message.
                             */
                            let errorMessage = "Error while connecting";
                            if (error.inform === true) {
                                errorMessage = "Error while connecting: " +
                                        error.message;
                            }

                            /* If the connection has not yet been established,
                             * reset the party connection parameters and invoke
                             * the given callback.
                             */
                            if (
                                isConnected !== true ||
                                (
                                    isConnected === true &&
                                    seifConnection.isSeifConnected() !== true
                                )
                            ) {
                                // Reset the connection.
                                disconnect(new Error(errorMessage));

                                connectCallback(
                                    new Error(errorMessage)
                                );
                                return true;
                            }

                            // Emit the "seifError" event with the error object.
                            eventEmitter.emit(
                                "seifError",
                                new Error(errorMessage)
                            );

                            return false;
                        }


                        /**
                         * @brief The protocol invokes this function when seif
                         *        connection has received indication of an party
                         *        redirect. This involves, creating a new
                         *        connection to the new party and sending it the
                         *        appropriate message obtained from the message
                         *        store.
                         *
                         * @param connection seif connection object
                         * @param redirectData data received indicating a
                         *                     redirect:
                         *                     publicKey - new party's publickey
                         *                     address - host+port of new party
                         *
                         * @return none
                         */
                        function receivedRedirect(redirectData) {
                            logger.trace(
                                {redirectData},
                                "Received a redirect for a message"
                            );

                            /* Updating connect options with the address and
                             * public key given in the redirect data.
                             */
                            let redirectOptions = {
                                connectAddress: redirectData.address,
                                connectPublicKey: redirectData.publicKey ||
                                        connectPublicKey
                            };

                            // Set connection to redirecting state.
                            isRedirecting = true;

                            let connectOptions = {
                                messageQueue: messageQueue,
                                connectionInfo: redirectData.redirectContext
                            };


                            // Disconnect the party from the current host.
                            disconnect(new Error("Redirecting"));

                            // Connect to the new host using connect options.
                            createConnection(
                                redirectOptions,
                                connectOptions,
                                function (error) {

                                    /* The connection had now been redirected to
                                     * the new host or the redirection has
                                     * failed.
                                     */
                                    isRedirecting = false;

                                    // Redirect has succeeded.
                                    if (error === undefined) {
                                        workItemQueue.done();
                                        return;
                                    }

                                    // Error while connecting to the new host.
                                    disconnect(new Error(
                                        "Redirect failure." +
                                        " Unable to connect to new host."
                                    ));
                                }
                            );

                        }


                        /**
                         * @brief The protocol invokes this function when seif
                         *        connection has received a message delivery
                         *        confirmation. At this point the message is
                         *        removed from the message list.
                         *
                         * @param confirmation object containing:
                         *                     result - success/failure?
                         *                     messageId - id of message being
                         *                                 confirmed
                         *
                         * @return none
                         */
                        function receivedMessageConfirmation(confirmation) {

                            let messageId = confirmation.messageId;
                            if (confirmation.result === true) {
                                // Confirm the message at front of the queue.
                                let messageItem = messageQueue.removeFront();
                                if (messageItem.messageId !== messageId) {
                                    messageQueue.insertFront(messageItem);
                                    seifConnection.error(
                                        new Error("Message out of order")
                                    );
                                    return;
                                }

                                // Invoke the confirmation callback for message.
                                if (typeof messageItem.callback ===
                                        "function") {
                                    messageItem.callback();
                                }
                            } else {
                                /* If the message was unconfirmed, then set the
                                 * connection to redirecting state.
                                 */
                                isRedirecting = true;
                            }

                        }

                        // Creates the seif connection object.
                        seifConnection = seif.createConnection({
                            listener: false,

                            seifRNG,

                            cipherSuite,

                            connectPublicKey,

                            privateKey: keys.dec,

                            publicKey: keys.enc,

                            eccEncrypt,

                            eccDecrypt,

                            connected,

                            seifDataReady,

                            dataReady,

                            closed,

                            seifError,

                            updateHostCache,

                            disconnect,

                            receivedRedirect,

                            receivedMessageConfirmation,

                            connectionInfo: options.connectionInfo
                        });


                        logger.trace(
                            {address: connectAddress},
                            "Connecting via seif"
                        );

                        // Connection object has been created.
                        connectionInProgress = false;

                        // Create a tcp connection with the host.
                        tcpConnect(connectAddress);

                    }


                    /**
                     * @brief Connects to the host using seif protocol and saved
                     *        the connection to the party's connection cache.
                     *        Callback is invoked with an error in case the
                     *        connection fails.
                     *
                     * @param properties Frozen Object (the function freezes it
                     *                   if it isnt already frozen) containing
                     *                   the remote host's details and other
                     *                   connection options:
                     *                   connectAddress: ip-address + port
                     *                   petName: short name to lookup
                     *                   connectPublicKey: public-key
                     *                   connectionInfo: unencrypted options
                     *                      sent in the hello initiating a new
                     *                      connection.
                     *
                     * @param connectCallback callback to be invoked after a
                     *                        connection has been established.
                     *                        function callback(error), where
                     *                        error: connection error
                     *
                     * @return none
                     */
                    function connect(properties, connectCallback) {

                        let connectOptions;
                        let options = Object.freeze(properties);

                        logger.trace({options}, "Processing the connection");

                        let host,
                            port = 9992;

                        // Error if party already has an active connection.
                        if (partyIsConnected === true) {
                            return connectCallback(
                                new Error(
                                    "Please call end() before calling " +
                                    "connect() again"
                                )
                            );
                        }

                        // Starting the connection process.
                        partyIsConnected = true;
                        connectionInProgress = true;

                        // Check if RNG has been initialized.
                        if (seifRNG === undefined) {
                            // RNG needs to be initialized to proceed further.
                            logger.error("RNG has not been initialized.");

                            partyIsConnected = false;
                            connectionInProgress = false;
                            return connectCallback(
                                new Error("RNG has not been initialized.")
                            );
                        }

                        /* Check if host's ip-address/port are provided in given
                         * input.
                         */
                        if (options.connectAddress !== undefined) {
                            logger.trace(
                                {address: options.connectAddress},
                                "Address given to connect()"
                            );

                            host = options.connectAddress.host;
                            port = options.connectAddress.port || port;

                            // Check if host,public-key is provided in "input".
                            if (
                                host !== undefined &&
                                options.connectPublicKey !== undefined
                            ) {

                                /* If so, create the host data object using
                                 * below properties.
                                 */
                                connectOptions = {
                                    connectAddress: {
                                        host,
                                        port
                                    },
                                    connectPublicKey: options.connectPublicKey
                                };

                                logger.trace(
                                    {hostData: connectOptions},
                                    "Using input to create connection"
                                );

                                /* Create the connection using given host data
                                 * and connection options.
                                 */
                                createConnection(
                                    connectOptions,
                                    options,
                                    connectCallback
                                );

                                return;
                            }
                        }

                        /* Check if petName is provided instead of the
                         * host ip-address/port.
                         */
                        if (
                            host === undefined && options.petName !== undefined
                        ) {

                            logger.trace(
                                {petName: options.petName},
                                "Petname provided. Looking up cache."
                            );

                            /* Lookup host-cache with the given pet name to
                             * get host details.
                             */
                            hostCache.read(
                                options.petName,
                                function (reply, error) {

                                    // Error looking up host-cache.
                                    if (
                                        (
                                            error !== undefined &&
                                            error !== null
                                        ) ||
                                        (
                                            reply === null ||
                                            reply === undefined
                                        )
                                    ) {

                                        partyIsConnected = false;
                                        connectionInProgress = false;
                                        logger.error(error);
                                        return connectCallback(error);
                                    }

                                    /* Parse the response obtained from the
                                     * host cache
                                     */
                                    try {
                                        connectOptions = JSON.parse(reply);
                                    } catch (err) {
                                        return connectCallback(err);
                                    }

                                    /* Check for required host address and
                                     * public key in the obtained host data.
                                     */
                                    if (
                                        connectOptions.connectAddress ===
                                            undefined ||
                                        connectOptions.connectPublicKey ===
                                            undefined
                                    ) {

                                        partyIsConnected = false;
                                        connectionInProgress = false;
                                        logger.error("Insufficient host data" +
                                                " obtained from the cache.");
                                        return connectCallback(
                                            new Error(
                                                "Insufficient host data" +
                                                " obtained from the cache."
                                            )
                                        );
                                    }

                                    /* Set the petname in the party representing
                                     * the party's current active connection.
                                     */
                                    petName = options.petName;


                                    logger.trace("Using cache data to connect");

                                    /* Create connection using host data and
                                     * given options.
                                     */
                                    createConnection(
                                        connectOptions,
                                        options,
                                        connectCallback
                                    );
                                }
                            );

                            return;
                        }

                        // Error since required details are not provided.
                        if (
                            host === undefined &&
                            options.petName === undefined
                        ) {
                            partyIsConnected = false;
                            connectionInProgress = false;
                            logger.error("Bad request. No host/petname given.");
                            return connectCallback(
                                new Error("Bad request. No host/petname given.")
                            );
                        }

                    }


                    /**
                     * @brief Sends message to the connected host using the seif
                     *        protocol.
                     *
                     * @param options Frozen object containing message details:
                     *                message - message to be sent to a party
                     * @param confirmationCallback callback to be invoked after
                     *                             a message is confirmed, or
                     *                             an error occurs while sending
                     *                             the message:
                     *                             'function callback(error)'
                     *
                     * @return none
                     */
                    function send(options, confirmationCallback) {
                        // Check if connection exists or not.
                        if (seifInitiatorConnection === undefined) {
                            if (connectionInProgress === true) {
                                eventEmitter.emit(
                                    "seifError",
                                    new Error(
                                        "Unable to send message. " +
                                        "Connection has not yet been " +
                                        "established."
                                    )
                                );

                            } else {
                                eventEmitter.emit(
                                    "seifError",
                                    new Error(
                                        "Unable to send message. " +
                                        "Please call connect() first."
                                    )
                                );
                            }
                            return;
                        }

                        // Enqueue the message details in the work item queue.
                        let messageItem = {
                            options: Object.freeze(options),
                            callback: confirmationCallback
                        };
                        workItemQueue.insertBack(messageItem);

                        // Process the queue if connection is established.
                        if (seifInitiatorConnection.isSeifConnected() ===
                                true) {
                            workItemQueue.done();
                        }
                    }

                    /**
                     * @brief Sends a message to the connected host
                     *        using the seif protocol without the need for a
                     *        message confirmation. These type of messages
                     *        are not guaranteed to be sent by the protocol,
                     *        if the connection is broken or the initiator/
                     *        listener go down for some reason. This can be
                     *        used for log/status messages etc.
                     *
                     * @param options Frozen Object containing message details:
                     *                message - message to be sent to a party
                     *
                     * @return none
                     */
                    function sendStatus(options) {
                        // Check if connection exists or not.
                        if (seifInitiatorConnection === undefined) {
                            if (connectionInProgress === true) {
                                eventEmitter.emit(
                                    "seifError",
                                    new Error(
                                        "Unable to send message. " +
                                        "Connection has not yet been " +
                                        "established."
                                    )
                                );

                            } else {
                                eventEmitter.emit(
                                    "seifError",
                                    new Error(
                                        "Unable to send message. " +
                                        "Please call connect() first."
                                    )
                                );
                            }
                            return;
                        }

                        // Enqueue the message details in the work item queue.
                        let messageItem = {
                            options: Object.freeze(options),
                            unreliable: true
                        };
                        workItemQueue.insertBack(messageItem);

                        // Process the queue if connection is established.
                        if (
                            seifInitiatorConnection.isSeifConnected() ===
                            true
                        ) {
                            workItemQueue.done();
                        }
                    }


                    function end(endCallback) {

                        if (connectionInProgress === true) {
                            logger.error("Connection in progress.");

                            if (typeof endCallback === "function") {
                                return endCallback(
                                    new Error("Connection in progress.")
                                );
                            }

                            return;
                        }

                        partyIsConnected = false;

                        if (seifInitiatorConnection !== undefined) {
                            seifInitiatorConnection.disconnect();
                        }

                        petName = undefined;

                        if (typeof endCallback === "function") {
                            return endCallback();
                        }
                    }


                    /**
                     * @brief This function is to be invoked when the party
                     *        wants to act as a listener to accept incoming
                     *        connections. The party can provide a port on
                     *        which tcp connections can be accepted and various
                     *        other options along with a connection listener,
                     *        which is invoked everytime a seif connection is
                     *        established.
                     *
                     * @param port port on which the party listens for
                     *             incoming connections
                     * @param connectionListener Application level callback to
                     *                           be invoked everytime a request
                     *                           has been received on the
                     *                           established seif connection
                     *
                     * @return none
                     */
                    function listen(port, connectionListener) {

                        logger.trace(
                            {port},
                            "Creating tcp server on given port"
                        );

                        /**
                         * @brief This function is responsible for generating
                         *        the connection listener for tcp connections.
                         *
                         * @return function Generated tcp connection listener
                         */
                        function setupSeifConnectionListener() {

                            /**
                             * @brief Connection listener to be executed
                             *        everytime a tcp connection has been
                             *        established.
                             *
                             * @param socket tcp socket on which a connection
                             *               has been established
                             *
                             * @return None
                             */
                            function seifConnectionListener(socket) {

                                // Queue to cache messages until confirmation
                                let connectionMessageQueue = createDeque();

                                let newConnection;
                                let seifListernerConnection;

                                // Buffers on TCP.
                                if (socket._readableState) {
                                    delete socket._readableState.decoder;
                                    delete socket._readableState.encoding;
                                }

                                logger.trace(
                                    'Received connection. CONNECTED: ' +
                                    socket.remoteAddress + ':' +
                                    socket.remotePort
                                );


                                /**
                                 * @brief End the tcp connection and reset the
                                 *        seif connection parameters.
                                 *
                                 * @param error error due to which the
                                 *              connection is being ended
                                 *
                                 * @return none
                                 */
                                function disconnect(error) {
                                    logger.trace('[seif] disconnected');

                                    // Destroy the tcp socket.
                                    socket.end();
                                    socket.destroy();

                                    // Close the seif connection.
                                    seifListernerConnection.close(error);
                                }


                                /**
                                 * @brief Creates a representation of the
                                 *        connection object to be used by the
                                 *        application layer.
                                 *
                                 * @param cInfo connection info part of the
                                 *        initiating hello.
                                 * @param callback function to be invoked when
                                 *                 the application connection
                                 *                 is ready
                                 *
                                 * @return none
                                 */
                                function createMessageSender(cInfo, callback) {
                                    /* Emits message events to be handled by
                                     * the application.
                                     */
                                    let messageListener
                                            = new EventEmitter();
                                    // flag indicating connection status
                                    let isAlive = true;
                                    /* flag indicating if connection is
                                     * redirecting
                                     */
                                    let isRedirecting = false;
                                    // initiator public key
                                    let currentSession = seifListernerConnection
                                        .getCurrentSession();
                                    let initiatorPublicKey = currentSession
                                        .sp
                                        .initiatorPublicKey;

                                    // initiator details
                                    let connector = {
                                        publicKey: initiatorPublicKey
                                    };
                                    // seif connection properties: connection id
                                    let connectionProperties = {};

                                    connectionProperties.connectionInfo = cInfo;

                                    /**
                                     * @brief Returns the initiator properties.
                                     *
                                     * @return object initiator details object
                                     */
                                    function initiator() {
                                        return connector;
                                    }


                                    /**
                                     * @brief Returns the message event
                                     *        listener.
                                     *
                                     * @return object event emitter object
                                     */
                                    function seifMessageListener() {
                                        return messageListener;
                                    }


                                    /**
                                     * @brief Returns the connection status.
                                     *
                                     * @return boolean indicating if connection
                                     *                 is open
                                     */
                                    function isStillAlive() {

                                        if (socket.writable) {
                                            return isAlive;
                                        }
                                        return false;
                                    }


                                    /**
                                     * @brief This function can be invoked by
                                     *        the party to send normal message
                                     *        over a connection.
                                     *
                                     * @param message Frozen message to be sent
                                     * @param confirmationCallback function to
                                     *                             be invoked
                                     *                             on message
                                     *                             confirmation
                                     *
                                     * @return none
                                     */
                                    function listenerSend(
                                        messageOptions,
                                        confirmationCallback
                                    ) {
                                        // Generate a new message id.
                                        let messageId = generateMessageId();

                                        /* Create message wrapper object and
                                         * enqueue it in this connection's
                                         * message queue.
                                         */
                                        let messageWrapper = {
                                            message: Object.freeze(
                                                messageOptions
                                            ).message,
                                            messageId,
                                            callback: confirmationCallback
                                        };
                                        connectionMessageQueue.insertBack(
                                            messageWrapper
                                        );

                                        /* Package the message in a seif record
                                         * and send it over this connection.
                                         */
                                        seifListernerConnection.prepare(
                                            messageWrapper
                                        );
                                    }

                                    /**
                                     * @brief This function can be invoked by
                                     *        the party to send status message
                                     *        over a connection.
                                     *
                                     * @param message Frozen message to be sent
                                     * @param confirmationCallback function to
                                     *                             be invoked
                                     *                             on message
                                     *                             confirmation
                                     *
                                     * @return none
                                     */
                                    function listenerSendStatus(
                                        messageOptions
                                    ) {

                                        /* Create message wrapper object and
                                         * enqueue it in this connection's
                                         * message queue.
                                         */
                                        let messageWrapper = {
                                            message: Object.freeze(
                                                messageOptions
                                            ).message
                                        };

                                        /* Package the message in a seif record
                                         * and send it over this connection.
                                         */
                                        seifListernerConnection.prepare(
                                            messageWrapper
                                        );
                                    }


                                    /**
                                     * @brief Ends the underlying seif
                                     *        connection.
                                     *
                                     * @return none
                                     */
                                    function endConnection() {
                                        logger.trace(
                                            "Preparing to send response."
                                        );

                                        isAlive = false;

                                        disconnect();
                                    }

                                    /**
                                     * @brief Redirect the connection to another
                                     *        party. This function is
                                     *        responsible for sending a
                                     *        message to the initiator
                                     *        with the address/info
                                     *        of the new party it should be
                                     *        connecting to with optional
                                     *        redirect context.
                                     *
                                     * @param redirectOptions object containing:
                                     *                        connectOptions
                                     *                        permanent
                                     *                        redirectContext
                                     * @param callback function to be
                                     *                 invoked when there is an
                                     *                 error or the message with
                                     *                 redirect info has been
                                     *                 sent to the initiator.
                                     *
                                     * @return none
                                     */
                                    function processRedirect(
                                        redirectOptions,
                                        callback
                                    ) {


                                        /* Prepare message to be sent to the
                                         * the initiator notifying redirect.
                                         */
                                        let redirectPublicKey =
                                                redirectOptions
                                            .connectOptions
                                            .connectPublicKey;


                                        let record = {
                                            address: redirectOptions
                                                .connectOptions
                                                .connectAddress,
                                            publicKey:
                                                    redirectPublicKey,
                                            permanent: redirectOptions
                                                .permanent,
                                            redirectContext: redirectOptions
                                                .redirectContext
                                        };

                                        /* Package the message into a seif
                                         * record and invoke given callback
                                         * after sending it.
                                         */
                                        seifListernerConnection
                                            .prepareRedirectRequest(
                                                record
                                            );

                                        if (
                                            typeof callback ===
                                            "function"
                                        ) {
                                            return callback();
                                        }
                                        return;

                                    }


                                    /**
                                     * @brief Redirect the connection to another
                                     *        party.
                                     *
                                     * @param options object containing:
                                     *                address
                                     *                petName
                                     *                permanent
                                     *                publicKey
                                     *                redirectContext
                                     * @param callback function to be invoked
                                     *                 once the initiator has
                                     *                 been informed about the
                                     *                 redirect
                                     *
                                     * @return none
                                     */
                                    function redirect(options, callback) {
                                        // Set state to redirecting.
                                        isRedirecting = true;

                                        logger.info("Redirecting.");

                                        // Check for valid redirect options.
                                        if (options === undefined) {
                                            return;
                                        }

                                        let address = options.address;

                                        /**
                                         * @brief Function to be invoked once
                                         *        the host cache has been looked
                                         *        up with the petname
                                         *
                                         * @param reply cache value for given
                                         *              petname
                                         * @param err error looking up the cache
                                         *
                                         * @return none
                                         */
                                        function hostCacheCallback(
                                            reply,
                                            err
                                        ) {
                                            // Error looking up host-cache.
                                            if (
                                                err !== undefined ||
                                                reply === undefined
                                            ) {
                                                if (
                                                    typeof callback ===
                                                    "function"
                                                ) {
                                                    return callback(err);
                                                }
                                                messageListener.emit(
                                                    "seifError",
                                                    new Error(err)
                                                );
                                                return;
                                            }

                                            // Get host info from cache value.
                                            let thisHostInfo;
                                            try {
                                                thisHostInfo = JSON.parse(
                                                    reply
                                                );
                                            } catch (error) {
                                                if (
                                                    typeof callback ===
                                                    "function"
                                                ) {
                                                    return callback(error);
                                                }
                                                messageListener.emit(
                                                    "seifError",
                                                    new Error(err)
                                                );
                                                return;
                                            }

                                            /* Process the redirect using the
                                             * given details.
                                             */
                                            let redirectOptions = {
                                                connectOptions:
                                                        thisHostInfo,
                                                permanent: options.permanent,
                                                redirectContext:
                                                        options.redirectContext
                                            };

                                            processRedirect(
                                                redirectOptions,
                                                callback
                                            );
                                        }

                                        /* Lookup host cache if petname of the
                                         * party is provided instead of the
                                         * actual address.
                                         */
                                        if (
                                            address === undefined &&
                                            options.petName !== undefined
                                        ) {
                                            hostCache.read(
                                                options.petName,
                                                hostCacheCallback
                                            );

                                            return;
                                        }

                                        /* Process the redirect using the
                                         * given details.
                                         */
                                        let redirectOptions = {
                                            connectOptions: {
                                                connectAddress: address,
                                                connectPublicKey: options
                                                    .publicKey
                                            },
                                            permanent: options.permanent,
                                            redirectContext:
                                                    options.redirectContext
                                        };

                                        processRedirect(
                                            redirectOptions,
                                            callback
                                        );
                                    }


                                    /**
                                     * @brief The party can invoke this routine
                                     *        to issue a temporary redirect for
                                     *        the current session to a new host.
                                     *
                                     * @param options Frozen object containing:
                                     *                address
                                     *                petName
                                     *                publicKey
                                     * @param callback function to be invoked
                                     *                 once the initiator has
                                     *                 been informed about the
                                     *                 redirect:
                                     *                 'function cb(error)'
                                     *
                                     * @return none
                                     */
                                    function temporaryRedirect(
                                        options,
                                        callback
                                    ) {
                                        let redirectOptions = Object.freeze({
                                            address: options.address,
                                            publickey: options.publicKey,
                                            petName: options.petName,
                                            redirectContext:
                                                    options.redirectContext,
                                            permanent: false
                                        });

                                        return redirect(
                                            redirectOptions,
                                            callback
                                        );
                                    }


                                    /**
                                     * @brief The party can invoke this routine
                                     *        to issue a permanent redirect for
                                     *        all future initiator connections.
                                     *
                                     * @param options Frozen object containing:
                                     *                address
                                     *                petName
                                     *                publicKey
                                     * @param callback function to be invoked
                                     *                 once the initiator has
                                     *                 been informed about the
                                     *                 redirect:
                                     *                 'function cb(error)'
                                     *
                                     * @return none
                                     */
                                    function permanentRedirect(
                                        options,
                                        callback
                                    ) {
                                        let redirectOptions = Object.freeze({
                                            address: options.address,
                                            publickey: options.publicKey,
                                            petName: options.petName,
                                            redirectContext:
                                                    options.redirectContext,
                                            permanent: true
                                        });

                                        return redirect(
                                            redirectOptions,
                                            callback
                                        );
                                    }


                                    /**
                                     * @brief Returns whether the party is
                                     *        redirecting the underlying
                                     *        connection.
                                     *
                                     * @return boolean true, if connection is
                                     *                 redirecting, else false
                                     */
                                    function isSeifRedirecting() {
                                        return isRedirecting;
                                    }


                                    /**
                                     * @brief Returns the connection properties
                                     *        including the connection id.
                                     *
                                     * @return object containing connection id
                                     */
                                    function seifConnectionProperties() {
                                        return connectionProperties;
                                    }


                                    /* Create the connection representation
                                     * to be used by the listening party's
                                     * application layer.
                                     */
                                    let messageSender = Object.freeze({
                                        send: listenerSend,
                                        sendStatus: listenerSendStatus,
                                        temporaryRedirect,
                                        permanentRedirect,
                                        isStillAlive,
                                        end: endConnection,
                                        seifMessageListener,
                                        isSeifRedirecting,
                                        initiator,
                                        seifConnectionProperties
                                    });

                                    /* Get a reference to the connection id
                                     * stored in the session.
                                     */
                                    let connectionId = seifListernerConnection
                                        .getCurrentSession()
                                        .connectionId;


                                    /**
                                     * @brief Function invoked when the new
                                     *        connection id is generated using
                                     *        the random number generator.
                                     *
                                     * @param randomBytes random number obtained
                                     *                    from seifRNG
                                     *
                                     * @return none
                                     */
                                    function randomCallback(randomBytes) {
                                        /* Assign the random bytes to the
                                         * session connection id.
                                         */
                                        seifListernerConnection
                                            .getCurrentSession()
                                            .connectionId = randomBytes;
                                        connectionProperties.connectionId =
                                                randomBytes;

                                        /* Invoke the callback with the new
                                         * connection representation object.
                                         */
                                        return callback(messageSender);
                                    }

                                    // Check if connection id is available.
                                    if (connectionId === undefined) {
                                        // Generate new id using seifRNG.
                                        let saveState = false;
                                        seifRNG.getBytes(
                                            32,
                                            saveState,
                                            randomCallback
                                        );
                                        return;
                                    }

                                    /* Invoke the callback with the new
                                     * connection representation object.
                                     */
                                    return callback(messageSender);
                                }


                                /**
                                 * @brief Function invoked by the protocol
                                 *        when the seif connection is
                                 *        established. The connection
                                 *        representation object is created and
                                 *        provided to the application connection
                                 *        handler.
                                 *
                                 * @param connectionInfo part of the
                                 *        initiating hello.
                                 *
                                 * @return none
                                 */
                                function connected(connectionInfo) {
                                    logger.trace('Connected pending auth.');

                                    // Create the connection wrapper object.
                                    createMessageSender(
                                        connectionInfo,
                                        function (messageSender) {
                                            newConnection = messageSender;
                                            /* Provide the connection wrapper
                                             * to the listening party's
                                             * application.
                                             */
                                            connectionListener(newConnection);
                                        }
                                    );
                                }


                                /**
                                 * @brief Function invoked by the protocol
                                 *        when there is data ready to be sent
                                 *        over the tcp connection.
                                 *
                                 * @return none
                                 */
                                function seifDataReady() {
                                    /* Get the seif records to be sent and
                                     * write them to the tcp connection.
                                     */
                                    seifListernerConnection.seifRecords.forEach(
                                        function (record) {
                                            socket.write(record);
                                        }
                                    );

                                    /* Empty the records array indicating all
                                     * records have been flushed.
                                     */
                                    seifListernerConnection
                                        .seifRecords.length = 0;
                                }


                                /**
                                 * @brief Function invoked when the party has
                                 *        received data and the data has been
                                 *        read and decrypted by the protocol.
                                 *        The messages are sent to the
                                 *        application via an event fired
                                 *        on the message listener.
                                 *
                                 * @param dataReceived decrypted data received
                                 *                     by the party.
                                 *
                                 * @return none
                                 */
                                function dataReady(dataReceived) {
                                    /* Parse the received message wrapper to get
                                     * the message id and the sent message.
                                     */

                                    let receivedMessage = dataReceived.message;
                                    let messageId = dataReceived.messageId;

                                    /* Send a pending confirmation if the
                                     * connection is being redirected.
                                     */
                                    if (
                                        newConnection.isSeifRedirecting() ===
                                        true
                                    ) {
                                        logger.trace("Connection redirecting.");
                                        seifListernerConnection
                                            .prepareApplicationDataConfirmation(
                                                {
                                                    messageId,
                                                    confirm: false
                                                }
                                            );

                                        return;
                                    }

                                    // Send a success confirmation.
                                    seifListernerConnection
                                        .prepareApplicationDataConfirmation(
                                            {
                                                messageId,
                                                confirm: true
                                            }
                                        );


                                    /* Fire a "message" event with the received
                                     * message to the listener application.
                                     */
                                    newConnection.seifMessageListener().emit(
                                        "message",
                                        receivedMessage
                                    );
                                }


                                /**
                                 * @brief The protocol invokes this function
                                 *        when seif connection has received a
                                 *        message delivery confirmation. At this
                                 *        point the message is removed from the
                                 *        message queue.
                                 *
                                 * @param confirmation object containing:
                                 *                     result - success/failure?
                                 *                     messageId - id of message
                                 *                                 confirmed
                                 *
                                 * @return none
                                 */
                                function receivedMessageConfirmation(
                                    confirmation
                                ) {
                                    let messageId = confirmation.messageId;

                                    // Check the confirmation result.
                                    if (confirmation.result === true) {
                                        /* If success, remove the message from
                                         * the queue.
                                         */
                                        logger.trace(
                                            {messageId},
                                            "Received confirmation." +
                                                    "Message removed from list"
                                        );

                                        let messageItem = connectionMessageQueue
                                            .removeFront();

                                        /* Fire an error if the message ids do
                                         * not match.
                                         */
                                        if (
                                            messageItem.messageId !==
                                            messageId
                                        ) {
                                            connectionMessageQueue
                                                .insertFront(messageItem);

                                            seifListernerConnection.error(
                                                new Error(
                                                    "Message out of order"
                                                )
                                            );
                                            return;
                                        }

                                        if (
                                            typeof messageItem.callback ===
                                            "function"
                                        ) {
                                            return messageItem.callback();
                                        }
                                    }
                                }


                                /**
                                 * @brief The protocol invokes this function
                                 *        when seif connection is being closed.
                                 *
                                 * @param error error due to which the
                                 *              connection closed
                                 *
                                 * @return none
                                 */
                                function closed(error) {
                                    logger.trace('Party disconnected.');

                                    // Error given to unconfirmed messages.
                                    if (error === undefined) {
                                        error = new Error(
                                            "Connection ended by other party."
                                        );
                                    }

                                    /* Invoke the callbacks of messages which
                                     * have not been confirmed yet, with above
                                     * error.
                                     */
                                    while (
                                        connectionMessageQueue.size() !== 0
                                    ) {

                                        let messageItem = connectionMessageQueue
                                            .removeFront();

                                        if (
                                            typeof messageItem.callback ===
                                            "function"
                                        ) {
                                            messageItem.callback(
                                                new Error(error.message)
                                            );
                                        }
                                    }

                                    // Emit a "close" event for the connection.
                                    if (newConnection !== undefined) {
                                        newConnection
                                            .seifMessageListener()
                                            .emit(
                                                "close",
                                                new Error(error.message)
                                            );
                                        newConnection = undefined;
                                    }
                                }

                                /**
                                 * @brief The protocol invokes this function
                                 *        when seif connection has encountered
                                 *        an error.
                                 *
                                 * @param error seif error encountered
                                 *
                                 * @return none
                                 */
                                function seifError(error) {
                                    logger.error(
                                        error,
                                        'Party error: ' + error.message
                                    );

                                    /* Emit a "seifError" event to the party
                                     * application.
                                     */
                                    if (newConnection !== undefined) {
                                        newConnection
                                            .seifMessageListener()
                                            .emit(
                                                "seifError",
                                                new Error(error.message)
                                            );
                                    }
                                }

                                // Creates the seif connection object.
                                seifListernerConnection = seif.createConnection(
                                    {
                                        listener: true,
                                        seifRNG,
                                        publicKey: keys.enc,
                                        privateKey: keys.dec,
                                        cipherSuite,
                                        localAddress: {
                                            host: socket.localAddress,
                                            port: socket.localPort
                                        },
                                        remoteAddress: {
                                            host: socket.remoteAddress,
                                            port: socket.remotePort
                                        },

                                        eccEncrypt,

                                        eccDecrypt,

                                        updateHostCache,

                                        connected,

                                        seifDataReady,

                                        dataReady,

                                        receivedMessageConfirmation,

                                        closed,

                                        disconnect,

                                        seifError

                                    }
                                );

                                /* Define socket event handlers for received
                                 * tcp connection.
                                 */
                                socket.on('data', function (data) {
                                    seifListernerConnection.process(data);
                                });

                                socket.on('end', function () {
                                    logger.info("[socket] ended");
                                    if (newConnection !== undefined) {
                                        newConnection.end();
                                    }
                                });

                                socket.on('close', function (hasError) {
                                    logger.trace("[seif] closing:" + hasError);
                                    logger.trace(
                                        'CLOSED: ' +
                                        socket.remoteAddress + ': ' +
                                        socket.remotePort
                                    );
                                    if (newConnection !== undefined) {
                                        newConnection.end();
                                    }
                                });

                                socket.on('error', function (error) {
                                    logger.error({error}, "[socket] Error");
                                    seifListernerConnection.error(error);
                                });
                            }

                            return seifConnectionListener;
                        }

                        // to do: if already listen give error

                        let listenPort = port || 8000;

                        /* Create a seif connection listener and create a new
                         * tcp server which uses it on new connections.
                         */
                        let server = net.createServer(
                            setupSeifConnectionListener(connectionListener)
                        );

                        // Listen on the given port.
                        server.listen(listenPort);
                    }
                    // end listen


                    /**
                     * @brief This is the cleanup function. It destroys the
                     *        corresponding seifRNG object.
                     *
                     * @return none
                     */
                    function destroy() {
                        seifRNG.destroy();
                    }


                    /**
                     * @brief Returns the party properties to the caller.
                     *
                     * @return object containing properties: publicKey
                     */
                    function properties() {
                        return Object.freeze({
                            publicKey: keys.enc
                        });
                    }

                    // Create the party object giving access to seif functions.
                    return Object.freeze({
                        connect,
                        send,
                        sendStatus,
                        end,
                        listen,
                        seifEventEmitter,
                        destroy,
                        properties
                    });
                }

                // Create party and provide it to the caller
                return callback(createParty);
            }

            // Perform party login to get the party's keys etc.
            entityManagementUtil.retrieveEntityIdentity({
                entity,
                password
            }, useIdentity);

        }

        return seifParty;
    }

    return seifPartyGenerator;
}

module.exports = initialize();
