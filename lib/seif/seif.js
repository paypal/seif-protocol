/** @file seif.js
 *  @brief File containing the implementation of the seif connection object
 *         responsible for setting up the connection and sending messages over
 *         the established connection.
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

function seifProtocol() {

    'use strict';

    let util = require("./util");
    let loggerGenerator = require("../log");

    let logger = loggerGenerator.child({componentName: "SEIF_PROTOCOL"});

    // Supported Version
    let currentVersion = 2;

    /**
     * Whether this party is considered the "client" or "server".
     * enum { server, client } connectionEnd;
     */
    let connectionEnd = {
        server: "server",
        initiator: "initiator"
    };

    // Different types of messages
    let contentType = {
        handshake: "handshake",
        applicationData: "appData",
        redirect: "redirect",
        applicationDataConfirm: "appDataConfirm",
        seifError: "seifError"
    };

    // Different types of handshakes
    let handshakeType = {
        hello: "hello",
        authHello: "authHello",
        handshakeFinished: "handshakeFinished",
        handshakeRedirect: "handshakeRedirect"
    };

    // Different types of alerts
    let alertType = {
        level: {
            warning: "warning",
            fatal: "fatal"
        },
        description: {
            unexpectedMessage: "unexpectedMessage",
            handshakeFailure: "handshakeFailure",
            seifVersion: "seifVersion",
            internalError: "internalError",
            cacheError: "cacheError",
            invalidSession: "invalidSession"
        }
    };

    // Types of protocol messages expected to be received next
    let expectType = {
        serverHello: "serverHello", // rcv server hello
        serverFinished: "serverFinished", // rcv server hello done
        serverAppData: "serverAppData", // rcv application data

        initiatorHello: "initiatorHello", // rcv client hello
        initiatorAppData: "initiatorAppData" // rcv application data
    };

    /**
     * @brief Creates a new seif connection.
     *
     * @param options options for this connection
     *
     * @return object new seif connection
     */
    function createConnection(options) {

        logger.trace({options}, 'Creating connection.');

        // Table to decide which handler to call for a particular message type
        let ctTable = {};
        ctTable[connectionEnd.initiator] = {};
        ctTable[connectionEnd.initiator][expectType.serverHello] = {};
        ctTable[connectionEnd.initiator][expectType.serverFinished] = {};
        ctTable[connectionEnd.initiator][expectType.serverAppData] = {};

        ctTable[connectionEnd.server] = {};
        ctTable[connectionEnd.server][expectType.initiatorHello] = {};
        ctTable[connectionEnd.server][expectType.initiatorAppData] = {};

        /* Table to decide which handler to call for a particular handshake
         * message
         */
        let hsTable = {};
        hsTable[connectionEnd.initiator] = {};
        hsTable[connectionEnd.initiator][expectType.serverHello] = {};
        hsTable[connectionEnd.initiator][expectType.serverFinished] = {};

        hsTable[connectionEnd.server] = {};
        hsTable[connectionEnd.server][expectType.initiatorHello] = {};
        hsTable[connectionEnd.server][expectType.initiatorAppData] = {};

        // Determine whether current party is an initiator or a server.
        let party = connectionEnd.initiator;
        if (options.server === true) {
            party = connectionEnd.server;
        }

        // invoked on disconnect
        let disconnect = options.disconnect;
        // invoked when party is connected
        let connected = options.connected;
        // invoked when protocol data is ready to be sent via tcp
        let seifDataReady = options.seifDataReady;
        // invoked when received data is decrypted and ready to be used
        let dataReady = options.dataReady;
        // invoked when connection has been closed
        let closed = options.closed;
        // invoked when the host cache needs to be updated
        let updateHostCache = options.updateHostCache;
        // invoked when an initiator is being asked to redirect
        let receivedRedirect = options.receivedRedirect;
        // invoked when a message confirmation is received
        let receivedMessageConfirmation = options.receivedMessageConfirmation;
        // invoked when the initiator of the redirect is connected to new server
        let redirectConnected = options.redirectConnected;
        // invoked when data needs to be encrypted using ECC
        let eccEncrypt = options.eccEncrypt;
        // invoked when data needs to be decrypted using ECC
        let eccDecrypt = options.eccDecrypt;
        // invoked when an error occurs
        let seifError = options.seifError;

        // cache for persisting sessions
        let sessionCache = options.sessionCache;
        // cipher suite to be used for link encryption/decryption
        let cipherSuite = options.cipherSuite;
        // public/private key of the party
        let privateKey = options.privateKey;
        let publicKey = options.publicKey;
        // public key of the party being connected to (server)
        let connectPublicKey = options.connectPublicKey;
        // address of the party with which connection has been established
        let remoteAddress = options.remoteAddress;
        // isaac rng object to be used
        let seifRNG = options.seifRNG;
        // option indicating whether this is an internal party, as in redirects
        let isInternal = options.isInternal;
        // number of retry attempts when handshake process fails
        let retryAttempts = options.retryAttempts;
        // boolean indicating whether the party wants to redirect a connection
        let redirectToServer = options.redirectToServer;
        // session data to be sent to the new server on redirect
        let redirectPayload = options.redirectPayload;

        // properties of party being connected to
        let hostInfo = {
            address: options.remoteAddress,
            publicKey: options.connectPublicKey
        };

        // buffer responsible for received data
        let input = util.createStringBuffer();
        // array of seif records to be sent over tcp
        let seifRecords = [];
        // indicator of connection status
        let fail = false;
        // boolean indicating if the party is currently in the handshaking phase
        let handshaking = false;
        // boolean indicating if the connection is open or not
        let open = false;
        // boolean indicating if the seif connection is established
        let isSeifConnected = false;

        // object to hold the received seif record
        let record;
        // session object
        let session;
        // connection state with read/write modes for AES
        let state;
        // type of seif record expected next
        let expect;


        /**
         * @brief Sets the address of the remote party being connected to.
         *
         * @param newRemoteAddress address of the party
         *
         * @return none
         */
        function updateRemoteAddress(newRemoteAddress) {
            if (remoteAddress === undefined) {
                remoteAddress = newRemoteAddress;
                return;
            }

            remoteAddress.host = newRemoteAddress.host;
            remoteAddress.port = newRemoteAddress.port;
        }


        /**
         * @brief Update the number of connection retry attempts
         *        (in case of handshake failures).
         *
         * @param numAttempts value for number of retry attempts
         *
         * @return none
         */
        function updateRetryAttempts(numAttempts) {
            retryAttempts = numAttempts;
        }


        /**
         * @brief Creates a seif record with the given type and data. The data
         *        is assigned to the record "fragment" for protocol messages.
         *        However, for application messages which could be of varying
         *        lengths, the "fragment" is not present and instead the "blob"
         *        attribute is assigned the blob properties following this seif
         *        record.
         *
         * @param options object containing:
         *                type: the record type
         *                data: the plain text data in a byte buffer
         *
         * @return object the created record
         */
        function createRecord(options) {
            logger.debug({options}, 'Creating record.');

            if (options.data === undefined) {
                return;
            }

            let blob, fragment = options.data;
            if (options.type === contentType.applicationData) {
                let data, originalType;
                if (options.data.message instanceof Buffer) {
                    data = options.data.message.toString("hex");
                    originalType = "blob";
                } else {
                    data = JSON.stringify(options.data.message);
                    originalType = "JSON";
                }

                blob = {
                    messageId: options.data.messageId,
                    originalType,
                    data
                };
                fragment = undefined;
            }

            // Build record object.
            let createdRecord = {
                to: remoteAddress,
                payload: {
                    type: options.type,
                    fragment,
                    blob
                }
            };

            return createdRecord;
        }


        /**
         * @brief Creates a seif error record to be sent to the other end point
         *        of the connection. Currently this error record is created and
         *        sent only in the case of seif version mismatch.
         *
         * @param seifError error object containing:
         *                  message: error message
         *                  alert: error type/description
         *
         * @return string the created error record string
         */
        function createSeifError(seifError) {
            // Build record fragment.
            let seifErrorRecord = {
                message: seifError.message,
                alert: seifError.alert
            };

            let recordJson = JSON.stringify(seifErrorRecord);
            return recordJson;
        }


        /**
         * @brief Encrypts, and queues a record for delivery. If the record
         *        being enqueued represents application data, then the data is
         *        split from the json seif record and encrypted as a blob which
         *        follows the encrypted seif record. The details of the blob
         *        itself is added to the seif record before it is encrypted.
         *
         * @param record the record to queue
         *
         * @return none
         */
        function queue(record) {

            logger.trace({record}, 'Queue record to send.');

            // Error during record creation.
            if (record === undefined) {
                return;
            }

            let blob; // represents application data
            let encryptedBlobRec; // encrypted application data
            let encryptedRec; // encrypted seif json record

            /* Current connection state write mode for encrypting record to be
             * queued.
             */
            let s = state.current.write;

            /* If record represents application data then the data is removed
             * from the seif record and encrypted using the connection state.
             */
            if (record.payload.type === contentType.applicationData) {
                blob = record.payload.blob;
                try {
                    encryptedBlobRec = s.update(blob.data);
                } catch (blobError) {
                    return error({
                        message: 'Could not encrypt record:'
                                + blobError.message,
                        alert: {
                            level: alertType.level.fatal,
                            description: alertType.description.internalError
                        }
                    });
                }

                // Add blob details to the json seif record.
                record.payload.blob = {
                    length: encryptedBlobRec.length,
                    originalType: blob.originalType,
                    messageId: blob.messageId
                };
            }

            // Stringify the record and update it using the connection state.
            let rec = JSON.stringify(record);
            try {
                encryptedRec = s.update(rec);
            } catch (encryptError) {
                return error({
                    message: 'Could not encrypt record:' + encryptError.message,
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.internalError
                    }
                });
            }

            /* Enqueue the updated seif record with the preceding length header
             * and blob if available.
             */
            let lengthRecord = util.getBytesFromNumber(encryptedRec.length);
            seifRecords.push(lengthRecord.result);
            seifRecords.push(encryptedRec);
            if (encryptedBlobRec !== undefined) {
                seifRecords.push(encryptedBlobRec);
            }

        }


        /**
         * @brief Calls the seifDataReady() handler on the given connection to
         *        send the records via tcp.
         *
         * @return none
         */
        function flush() {
            logger.trace(
                {numRecords: seifRecords.length},
                'Flushing record to be sent.'
            );

            // Call the data ready handler to send the data over the connection.
            seifDataReady();

            return;
        }


        /**
         * @brief This function is invoked when an error occurs. It in turn
         *        invokes the provided "seifError" function and disconnects the
         *        connection in case of fatal errors.
         *
         * @param ex error object containing:
         *           origin  - initiator/server
         *           fatal   - boolean indicating whether error is fatal
         *           message - description of error
         *           alert   - object describing level and type of error
         *
         * @return none
         */
        function error(ex) {
            logger.error({ex});
            // Set origin if not set.
            let origin = "server";
            if (party === connectionEnd.initiator) {
                origin = "client";
            }
            ex.origin = ex.origin || origin;

            // Error is fatal by default.
            let fatal = (ex.fatal !== false);
            if (fatal) {
                // set fail flag
                fail = true;
            }

            // Check if the error needs to be sent to the other party.
            if (ex.send === true) {
                // Create a seif error record and send it over the connection.
                queue(createRecord({
                    type: contentType.seifError,
                    data: createSeifError(ex)
                }));
                flush();
            }

            // Call error handler first.
            seifError(ex);

            if (fatal) {
                // Fatal error, close connection.
                disconnect(ex);
            }
        }


        /**
         * @brief Check whther the connection is in handshaking phase.
         *
         * @return boolean true if connection is in handshaking phase, false
         *                 if not
         */
        function isHandshaking() {
            return handshaking;
        }


        /**
         * @brief Creates a new initialized seif connection state. A connection
         *        state has a read mode and a write mode.
         *
         * cipher state:
         *   The current state of the encryption algorithm. This will consist
         *   of the scheduled key for that connection and cipher object to
         *   carry out the encryption/decryption functions.
         *
         * @return object the new initialized seif connection state.
         */
        function createConnectionState() {

            logger.trace('Creating connection state.');

            /**
             * @brief Creates the cipher mode based on read/write state.
             *
             * @return none
             */
            function createMode() {

                /**
                 * @brief Default function to be invoked on read/write without
                 *        any cipher state. This function just returns the
                 *        record as is without any encryption/decryption
                 *        operation.
                 *
                 * @param inputRecord record to be read or written
                 *
                 * @return object same record which is received as an argument
                 */
                function cipherFunction(inputRecord) {
                    return inputRecord;
                }

                let mode = {
                    cipherState: undefined,
                    cipherFunction
                };

                return mode;
            }

            // Create the connection state with read and write modes.
            let connectionState = {
                read: createMode(),
                write: createMode()
            };

            // Update function in read mode will decrypt a record
            connectionState.read.update = function (inputRecord) {

                return connectionState.read.cipherFunction(
                    inputRecord,
                    connectionState.read
                );

            };

            // Update function in write mode will encrypt a record
            connectionState.write.update = function (inputRecord) {
                return connectionState.write.cipherFunction(
                    inputRecord,
                    connectionState.write
                );
            };

            return connectionState;
        }


        /**
         * @brief Resets the connection state (after a disconnect).
         *
         * @return none
         */
        function reset() {
            record = undefined;
            session = undefined;
            state = {
                pending: undefined,
                current: undefined
            };
            expect = expectType.initiatorHello;
            if (party === connectionEnd.initiator) {
                expect = expectType.serverFinished;
            }
            seifRecords.length = 0;
            open = false;
            handshaking = false;
            isSeifConnected = false;
            fail = false;
            input.clear();
            state.current = createConnectionState();
        }


        /**
         * @brief Closes the connection and invoked the provided "closed"
         *        function
         *
         * @param error error object in case the connection closed due to an
         *              error
         *
         * @return none
         */
        function close(error) {
            logger.trace("Closing the connection.");

            if (open === true) {
                // Connection no longer open, clear the input.
                open = false;
                input.clear();

                // Resetting the seif connection and handshaking flag.
                isSeifConnected = false;
                handshaking = false;

                // Call connection closed handler.
                closed(error);
            } else {
                // Call connection closed handler.
                closed(error);
            }

            // Reset seif connection.
            reset();
        }


        /**
         * @brief Called when an unexpected record is encountered.
         *
         * @param record the record.
         */
        function handleUnexpected() {
            logger.trace("Handling unexpected record");

            /* If the party is an initiator and the connection is closed,
             * ignore unexpected messages.
             */
            let ignoreMessage = (!open && party === connectionEnd.initiator);

            if (ignoreMessage === false) {

                error({
                    message: 'Unexpected seif message received.',
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.unexpectedMessage
                    }
                });
            }
        }


        /**
         * @brief Reads the record header and initializes the record object on
         *        the given connection. The function attempts to read the length
         *        of the succeeding record from the first few bytes received and
         *        sets the length in the "record" object.
         *
         * @return boolean True if record header is received with the length
         *         bytes, False otherwise
         */
        function readRecordHeader() {

            logger.trace('Reading record header');

            // Get input buffer and its length.
            let currentInput = input;
            let len = currentInput.size();

            // Need at least 2 bytes to initialize a record.
            if (len < 2) {
                return false;
            }

            /* Get length of entire record from the initial bytes of
             * received data.
             */
            let lengthRecord = util.getNumberFromBytes(currentInput.getData());
            logger.trace({lengthRecord}, "Extracted number");

            /* "lengthRecord" contains the length of the succeeding record and
             * the number of received bytes used to encode this length.
             */
            if (
                lengthRecord === undefined
                || lengthRecord.result === 0
                || lengthRecord.length === 0
            ) {
                return false;
            }

            /* Removing the bytes representing the "length" from the input
             * buffer.
             */
            currentInput.removeData(lengthRecord.length);

            // Creating basic record based on received data.
            record = {
                type: undefined,
                length: lengthRecord.result,
                fragment: "",
                ready: false
            };

            return true;
        }


        /**
         * @brief Reads the application data blob received and appends its data
         *        to the "record" object's internal buffer (after decryption
         *        if necessary). All seif protocol messages are sent as json and
         *        the application data is sent as a blob following the
         *        seif record.
         *
         * @return boolean True if the complete blob is read without any
         *         errors, False otherwise
         */
        function readRecordBlob() {
            logger.trace('Reading record blob.');

            // Ensure there is enough input data to get the entire record.
            let currentInput = input;
            let len = currentInput.size();
            if (len < record.length) {
                // Not enough data yet.
                return false;
            }

            // There is enough data to parse the pending record.
            let length = record.length;
            let blob = currentInput.removeData(length);
            currentInput.compact();

            // Update record using current read state
            let s = state.current.read;

            // String containing the decrypted application data.
            let decryptedBlob;
            try {
                // Read and decrypt (if necessary) the blob data.
                decryptedBlob = s.update(blob);
            } catch (readError) {
                // Error reading/decrypting the record using the read mode.
                logger.error(readError);
                error({
                    message: 'Could not decrypt record:' + readError.message,
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.internalError
                    }
                });

                return false;
            }

            logger.trace(
                {record, length: decryptedBlob.length},
                "Adding the blob received"
            );

            // Add the decrypted data to the "record"'s internal buffer.
            record.fragment.message = decryptedBlob;

            // Record is now ready to be handled.
            record.ready = true;

            return true;
        }


        /**
         * @brief Reads the next record's contents and appends the data to
         *        the "record" object's internal buffer. All seif protocol
         *        messages are sent as json and the application data is sent as
         *        a blob following the seif record.
         *
         * @return boolean True if the record is read without any
         *         errors, False otherwise
         */
        function readRecord() {
            logger.trace('Reading the record.');

            // Ensure there is enough input data to get the entire record.
            let currentInput = input;
            let len = currentInput.size();
            if (len < record.length) {
                // Not enough data yet.
                return false;
            }

            logger.trace({currentInput}, 'Reading record');

            // There is enough data to parse the pending record.
            let length = record.length;
            let receivedRecord = currentInput.removeData(length);
            currentInput.compact();

            // Update the record using the current state's read mode.
            let s = state.current.read;

            // String containing the decrypted json record.
            let decryptedRecord;
            try {
                // Read and decrypt (if necessary) the seif record.
                decryptedRecord = s.update(receivedRecord);
                decryptedRecord = JSON.parse(decryptedRecord);
            } catch (readError) {
                // Error reading/decrypting the record using the read mode.
                if (decryptedRecord === undefined) {
                    try {
                        decryptedRecord = JSON.parse(receivedRecord);
                    } catch (parseError) {
                        logger.error(parseError);
                        error({
                            message: 'Bad JSON record. Error parsing: '
                                    + parseError.message,
                            alert: {
                                level: alertType.level.fatal,
                                description: alertType.description.internalError
                            }
                        });

                        return false;
                    }
                }

                if (
                    decryptedRecord !== undefined
                    && decryptedRecord.payload !== undefined
                    && decryptedRecord.payload.type !== contentType.seifError
                ) {
                    logger.error(readError);
                    error({
                        message: 'Could not decrypt record: ' + readError.message,
                        alert: {
                            level: alertType.level.fatal,
                            description: alertType.description.internalError
                        }
                    });

                    return false;
                }
            }


            // Fill the "record" object with data from received json record.
            record.type = decryptedRecord.payload.type;

            // Check if this seif record is indicating about a following blob.
            if (
                decryptedRecord.payload.fragment === undefined
                && decryptedRecord.payload.blob !== undefined
            ) {
                /* Get the blob details to facilitate reading of the following
                 * blob.
                 */
                record.length = decryptedRecord.payload.blob.length;
                record.fragment = {
                    messageId: decryptedRecord.payload.blob.messageId,
                    originalType: decryptedRecord.payload.blob.originalType
                };
                return readRecordBlob();
            }

            // Fill the "record"'s internal buffer with the received seif record
            record.fragment = decryptedRecord.payload.fragment;

            // Record is now ready.
            record.ready = true;

            return true;
        }


        /**
         * @brief Updates the current seif engine state based on the given
         *        record and handles the record based on its type.
         *
         * @return None
         */
        function handleRecord() {

            // Get record handler.
            let index = record.type;
            let handlers = ctTable[party][expect];

            logger.trace({expect, index}, "running next function:");

            if (handlers[index] !== undefined) {
                logger.trace({expect, index}, "Update to call next handler");
                /* Invoking appropriate function by looking up function table
                 * based on record type.
                 */
                handlers[index]();
            } else {

                // Unexpected record.
                logger.error({
                    recordType: record.type,
                    party: party,
                    expect: expect
                }, "Error handling record.");

                handleUnexpected();
            }
        }


        /**
         * @brief Called when seif protocol data has been received via
         *        tcp or when there is data which has not been processed and
         *        should be processed by the seif engine.
         *
         * @param data the seif protocol data, as a string, to process.
         *
         * @return boolean indicating success or failure
         */
        function process(data) {

            logger.trace(
                {dataLen: (data && data.length) || 0},
                'Processing next record.'
            );

            let rval;

            // Buffer input data.
            if (data !== undefined) {
                input.insertData(data);
            }

            /* Process next record if no failure, process will be called after
             * each record is handled (since handling can be asynchronous).
             */
            if (fail === false) {
                /* Reset record if ready and now empty. This means that the
                 * record has been handled.
                 */
                if (
                    record !== undefined
                    && record.ready === true
                    && record.fragment !== undefined
                    && record.fragment.length === 0
                ) {
                    record = undefined;
                }

                // If there is no pending record, try to read record header.
                if (record === undefined) {
                    logger.trace(
                        "Processing the record:Reading the record header."
                    );
                    rval = readRecordHeader();
                }

                // Read the following record/blob (if record not yet ready).
                if (
                    fail === false
                    && record !== undefined
                    && record.ready === false
                ) {
                    logger.trace('Processing the record:Reading the record.');
                    if (record.type === contentType.applicationData) {
                        rval = readRecordBlob();
                    } else {
                        rval = readRecord();
                    }

                }

                // Record ready to be handled, update engine state.
                if (
                    fail === false
                    && record !== undefined
                    && record.ready === true
                ) {
                    logger.trace('Processing the record: record ready.');
                    handleRecord();
                }
            }

            return rval;
        }



        /**
         * @brief Parses a hello message from a ClientHello or ServerHello
         *        record.
         *
         * @param record the record to parse
         *
         * @return object the parsed message
         */
        function parseHelloMessage(record) {
            logger.trace('Parsing hello message');

            let msg;
            let client = (party === connectionEnd.initiator);

            // Get the encrypted secret key from the record.
            let temp = new Buffer(record.key);

            let decryptKey = privateKey;

            let secret;
            try {
                /* Decrypt the "key" in the record (encrypted using the
                 * receiver's public key) using the private key of the party.
                 */
                secret = eccDecrypt(decryptKey, temp);
            } catch (decryptError) {
                // Error decrypting the secret key to be used for the session.
                logger.error(decryptError);
                return error({
                    message: "Handshake failure",
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.handshakeFailure
                    }
                });
            }

            logger.trace({record}, 'Parsing hello message');

            /* Construct the message object with below properties including the
             * secret obtained by decrypting the given encrypted secret key in
             * the message using the receiver's private key.
             */
            msg = {
                version: record.version,
                sessionId: record.sessionId,
                secret: secret.toString("hex")
            };

            // Create cipher state with given secret to decrypt "helloData"
            let cipherState = {
                key: msg.secret
            };

            let helloData;
            if (record.helloData !== undefined) {
                helloData = cipherSuite.decrypt(
                    cipherState,
                    record.helloData
                );
                try {
                    helloData = JSON.parse(helloData);
                } catch (parseError) {
                    logger.error(parseError);
                    return error({
                        message: "Handshake failure.",
                        alert: {
                            level: alertType.level.fatal,
                            description: alertType.description.handshakeFailure
                        }
                    });
                }
            } else if (client === false) {
                // "helloData" missing in the hello record
                return error({
                    message: "Error: Hello data is missing",
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.handshakeFailure
                    }
                });
            }

            // Setting the "msg" object properties based on the hello data.
            if (client === false) {
                // Public-key of the initiator party
                msg.initiatorPublicKey = helloData.initiatorPublicKey;
                /* Indicates the hello has been sent by an internal initiator
                 * for redirect.
                 */
                msg.isInternal = helloData.isInternal;
                // Flag indicating redirect
                msg.redirectToServer = helloData.redirectToServer;
                // Payload referring to the session of the redirected connection
                msg.redirectPayload = helloData.redirectPayload;
            }

            logger.trace({message: msg}, "Parsed hello message");
            return msg;
        }


        /**
         * @brief Creates security parameters for the given connection based
         *        on the given hello message.
         *
         * @param msg parsed hello message
         *
         * @return None
         */
        function createSecurityParameters(msg) {
            logger.trace('Creating Security Params in session object from msg');

            // Create new security parameters.
            session.sp = {
                party,
                secretKeyLength: undefined,
                blockLength: undefined,
                keys: {
                    secretKey: msg.secret
                },
                initiatorPublicKey: msg.initiatorPublicKey
            };

        }



        /**
         * @brief Generate the AES secret key using the isaac RNG.
         *
         * @param keyLength length of secret to be generated in bytes
         * @param callback function to be invoked once key is generated:
         *                 'function callback(keyObject)', where,
         *                 keyObject contains:
         *                 secretKey - AES key of length "keyLength"
         *
         * @return none
         */
        function generateKeys(keyLength, callback) {

            // Save the state everytime an AES key is generated.
            let saveState = true;

            seifRNG.getBytes(keyLength, saveState, function (randomBytes) {
                return callback({
                    secretKey: randomBytes
                });
            });
        }


        /**
         * @brief Updates the connection state with encryption parameters
         *        obtained. In case, the secret key has been set in the session,
         *        the cipher suite is initialized and ready to encrypt/decrypt
         *        messages over the connection. Otherwise, generate the secret
         *        key, update the session security params and initialize the
         *        cipher suite to be ready for encryption/decryption operations
         *        over the connection. This case usually occurs when the server
         *        needs to authenticate the initiator and generates a new secret
         *        key for further communication.
         *
         * @param state connection state object with read/write modes
         * @param callback function to be invoked once the conection state has
         *                 been updated, of the form: function callback()
         *
         * @return none
         */
        function updateConnectionState(state, callback) {

            // Determining if the current party is a client or a server.
            let isClient = (party === connectionEnd.initiator);

            // Check if session has been created.
            if (session !== undefined) {

                logger.trace('Session object exists when creating state.');

                // Initialize the cipher suite using the security parameters
                let sp = session.sp;
                cipherSuite.initSecurityParameters(sp);

                /* If secret key is present in the session, initialize the
                 * cipher suite using it and invoke the callback.
                 */
                if (sp.keys !== undefined && sp.keys.secretKey !== undefined) {
                    // Cipher suite setup.
                    cipherSuite.initConnectionState(state, isClient, sp);
                    return callback();
                }

                /* If secret key is not present in the session, generate a new
                 * secret and update the session and cipher suite using it.
                 */
                if (sp.keys === undefined) {
                    sp.keys = {};
                }

                // Generate a new secret key.
                generateKeys(sp.secretKeyLength, function (keysObject) {
                    sp.keys = keysObject;
                    logger.trace(
                        {secret: sp.keys.secretKey},
                        "Generating new secret key."
                    );

                    // Cipher suite setup.
                    cipherSuite.initConnectionState(state, isClient, sp);
                    return callback();
                });

                return;
            }

            return callback();
        }


        /**
         * @brief Creates a hello message with following attributes:
         *        recordType - type of record
         *        version    - protocol version info
         *        key        - secret key encrypted using the server's
         *                     public-key
         *        helloData  - object containing party/connection info
         *
         * @return string json stringified hello record
         */
        function createHello() {
            logger.trace('Creating hello.');

            // Get the secret key to be sent from the session security params.
            let sp = session.sp;
            let temp = new Buffer(sp.keys.secretKey, "hex");

            // Encrypt the secret using the server's public key (ECC).
            let encryptedSecretKey;
            try {
                encryptedSecretKey = eccEncrypt(connectPublicKey, temp);
            } catch (encryptError) {
                logger.error(encryptError);
                return error({
                    message: 'Handshake failure',
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.handshakeFailure
                    }
                });
            }

            // Create cipher state using the secret key to encrypt "helloData".
            let cipherState = {
                key: sp.keys.secretKey
            };

            // Initialize "helloData"
            let helloData = {
                initiatorPublicKey: publicKey, // initiator's public key
                isInternal,                    // internal party indicator
                redirectToServer               // redirect hello indicator
            };

            // Encrypt the helloData using the session secret.
            helloData = cipherSuite.encrypt(
                cipherState,
                JSON.stringify(helloData)
            );

            // Build the hello record.
            let helloRecord = {
                recordType: handshakeType.hello,
                version: currentVersion,
                key: encryptedSecretKey,
                helloData
            };

            // Return the stringified json record.
            let recordJson = JSON.stringify(helloRecord);
            return recordJson;
        }


        /**
         * @brief Creates a hello message. This function is invoked when a
         *        prior session exists with the destination. The message
         *        contains the following attributes:
         *        recordType - type of record
         *        version    - protocol version info
         *        sessionId  - session id given previously by the server
         *        helloData  - object containing party/connection info
         *
         * @return string json stringified hello record
         */
        function createSessionHello() {
            logger.trace('Creating hello from session object.');

            // Get the session id from the session and send it in the record.
            let sessionId = session.id;

            // Create cipher state using the secret key to encrypt "helloData".
            let sp = session.sp;
            let cipherState = {
                key: sp.keys.secretKey
            };

            // Initialize "helloData"
            let helloData = {
                isInternal: isInternal,             // internal party flag
                redirectToServer: redirectToServer, // redirect hello flag
                redirectPayload: redirectPayload    // redirected session info
            };

            // Encrypt the helloData using the session secret.
            helloData = cipherSuite.encrypt(
                cipherState,
                JSON.stringify(helloData)
            );

            // Build the hello record.
            let helloRecord = {
                recordType: handshakeType.hello,
                version: currentVersion,
                sessionId,
                helloData
            };

            // Return the stringified json record.
            let recordJson = JSON.stringify(helloRecord);
            return recordJson;
        }


        /**
         * @brief Creates a Server Hello message. This is sent when initiator
         *        authentication is required and the server wants to send the
         *        new secret generated in response to the initiator hello. The
         *        message contains the following attributes:
         *        recordType - type of record
         *        version    - protocol version info
         *        key        - secret key encrypted using the initiator's
         *                     public-key
         *        sessionId  - session id to be used for future connections
         *
         * @return string json stringified hello record
         */
        function createAuthHello() {
            logger.trace('Creating Server hello.');

            // Get the session id and secret key from the current session.
            let sessionId = session.id;
            let sp = session.sp;
            let temp = new Buffer(sp.keys.secretKey, "hex");

            /* Encrypt the secret key using the initiator's public key sent by
             * the initiator in its hello message.
             */
            let encryptedSecretKey;
            try {
                encryptedSecretKey = eccEncrypt(sp.initiatorPublicKey, temp);
            } catch (encryptError) {
                logger.error(encryptError);
                return error({
                    message: 'Handshake failure',
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.handshakeFailure
                    }
                });
            }

            // Build the hello record.
            let helloRecord = {
                recordType: handshakeType.authHello,
                version: currentVersion,
                key: encryptedSecretKey,
                sessionId
            };

            // Return the stringified json record.
            let recordJson = JSON.stringify(helloRecord);
            return recordJson;
        }


        /**
         * @brief Creates a finished message. This message is sent by the server
         *        acknowledging the hello message and indicating that the
         *        connection has been established. The message contains the
         *        following attributes:
         *        recordType - type of record
         *        sessionId  - session id to be used for future communication
         *        redirectSessionId - in case of redirect acknowledgement
         *
         * @return string json stringified hello record
         */
        function createHandshakeFinished() {
            logger.trace('Creating server hello done.');

            // Get redirected session id from the connection session object.
            let redirectSessionId;
            if (session.redirectSession !== undefined) {
                redirectSessionId = session.redirectSession.id;
            }

            // Build the finished record.
            let finishedRecord = {
                recordType: handshakeType.handshakeFinished,
                sessionId: session.id,
                redirectSessionId
            };

            // Return the stringified json record.
            let recordJson = JSON.stringify(finishedRecord);
            return recordJson;
        }


        /**
         * @brief Creates a confirmation message for a received application
         *        data message. The message will have pending status if the
         *        connection is being redirected. The message contains the
         *        following attributes:
         *        result    - flag indicating if message is confirmed or pending
         *        messageId - message id being confirmed
         *
         * @param messageData object containing confirmation details:
         *                    messageId - id of message being confirmed
         *                    result    - true if confirmed, false if pending
         *
         * @return string json stringified hello record
         */
        function createApplicationDataConfirmation(messageData) {
            logger.trace('Creating Applcation data confirmation');

            let confirmationRecord = {
                result: messageData.confirm,
                messageId: messageData.messageId
            };

            // Return the stringified json record.
            let recordJson = JSON.stringify(confirmationRecord);
            return recordJson;
        }


        /**
         * @brief Creates a handshake redirect record. This message is sent
         *        when the initiator of the redirect wants to inform a server
         *        about a new redirect via an internal connection (this message
         *        is not needed when a prior session id exists between the two
         *        parties, as in that case, the redirected session payload
         *        is sent in the hello message itself). The message is sent
         *        after the initiator receives a new secret key from the server.
         *        It contains the following:
         *        recordType - type of record
         *        redirectPayload - contains the session being redirected
         *
         * @return string json stringified hello record
         */
        function createHandshakeRedirect() {
            logger.trace('Creating redirect request');

            let redirectRecord = {
                recordType: handshakeType.handshakeRedirect,
                redirectPayload
            };

            expect = expectType.serverFinished;

            // Return the stringified json record.
            let recordJson = JSON.stringify(redirectRecord);
            return recordJson;
        }



        /**
         * @brief This is the auth hello message handler. When this type of
         *        message is received from the server, the initator parses it
         *        to get the user id, session id and the session secret. It
         *        updates the session and the connection state so as to use the
         *        new secret for all further communication, thus authenticating
         *        itself. The host cache is updated with the user id too for
         *        future connections.
         *
         * @param parsedRecord the parsed auth hello record object.
         *
         * @return none
         */
        function handleAuthHello(parsedRecord) {
            logger.trace("Handling server hello.");

            // Parse the server hello message.
            let msg = parseHelloMessage(parsedRecord);
            if (fail === true) {
                return;
            }

            // Ensure server seif version is compatible.
            if (msg.version !== currentVersion) {
                logger.error(
                    {
                        message: msg,
                        currentVersion
                    },
                    "Error while checking versions."
                );
                return error({
                    message: 'Incompatible seif version.',
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.seifVersion
                    }
                });
            }

            // Get the session ID from the message
            let sessionId = msg.sessionId;
            if (sessionId === undefined) {
                logger.error("No session id given in message");
            }

            /* Change the expect state to application data as the connection
             * has now been established.
             */
            expect = expectType.serverAppData;
            session.resuming = false;

            // Create new security parameters based on parsed hello message.
            createSecurityParameters(msg);
            logger.trace({sp: session.sp}, "Security parameters.");

            // Create pending connection state for all future reads and writes.
            state.pending = createConnectionState();

            /* Update the connection state to use the session secret key
             * provided in the hello message.
             */
            updateConnectionState(state.pending, function () {
                state.current.read = state.pending.read;
                state.current.write = state.pending.write;

                // Handshake complete.
                handshaking = false;

                /* Update the session cache with the current session for
                 * future connections.
                 */
                if (sessionId !== undefined) {
                    logger.trace(
                        {sessionObject: session},
                        "Writing to cache first time"
                    );
                    // Set new session ID.
                    session.id = sessionId;
                    sessionCache.write(
                        JSON.stringify(hostInfo),
                        JSON.stringify(session)
                    );
                }

                // Connection is now complete.
                isSeifConnected = true;

                /* If this connection was to inform about a redirect, then call
                 * the appropriate provided connection handler.
                 */
                if (redirectToServer === true) {
                    // redirectConnected();
                    queue(createRecord({
                        type: contentType.handshake,
                        data: createHandshakeRedirect()
                    }));
                    flush();
                } else {
                    connected();
                }

                // Continue to process the next record.
                process();
            });

            process();
        }


        /**
         * @brief This is the hello message handler. When this type of
         *        message is received from the initiator, the server checks if
         *        it contains a pre auth session id. If so, then the session
         *        details are updated using the session cache. If not, then the
         *        server parses the hello message to get the party/connection
         *        info and processes the connection. If the server is able to
         *        decrypt the secret using its private key and no further
         *        authentication is required, then it sends a finished message.
         *        Otherwise, the server will generate a new secret and send an
         *        auth hello message back to the initiator.
         *
         * @param parsedRecord the parsed hello record object.
         *
         * @return none
         */
        function handleHello(parsedRecord) {
            logger.trace('Handling client hello');

            /**
             * @brief Function to be called after the received record has been
             *        parsed and the server is ready to process it.
             *
             * @param msg data obtained from received record
             * @param sessionData session object, if avaialble, from the cache
             *
             * @return none
             */
            function sendDone(msg, sessionData) {
                // Ensure server version is compatible.
                if (msg.version !== currentVersion) {
                    logger.trace(
                        {
                            message: msg,
                            currentVersion
                        },
                        "checking versions."
                    );
                    return error({
                        message: 'Incompatible seif version.',
                        send: true,
                        alert: {
                            level: alertType.level.fatal,
                            description: alertType.description.seifVersion
                        }
                    });
                }

                // Create a new one time use session id, user id etc.
                let saveState = false;
                seifRNG.getBytes([32, 32], saveState, function (random) {
                    let sessionId = random[0]; // one time use session id
                    let newSessionId = random[1]; // id for redirected session

                    // Check if the hello message indicates a redirect.
                    if (
                        msg.redirectToServer === true
                        && msg.redirectPayload !== undefined
                        && msg.redirectPayload.session !== undefined
                    ) {
                        // Assign a new session id to the redirected session.
                        msg.redirectPayload.session.id = newSessionId;
                        // Store the redirected session in the current session.
                        session.redirectSession = msg.redirectPayload.session;
                    }

                    /**
                     * @brief Function to be called after the record has been
                     *        processed and the next message to be sent has been
                     *        queued. The connection is now established and the
                     *        provided connection handler is invoked after
                     *        updating the session cache.
                     *
                     * @return none
                     */
                    function authenticationDone() {
                        // Send records over tcp.
                        flush();

                        if (
                            session.redirectToServer !== true
                            || session.redirectSession !== undefined
                        ) {
                            // Handshake complete.
                            handshaking = false;

                            // The two ends are now connected.
                            isSeifConnected = true;
                        }

                        // Clearing the old session id + object.
                        if (msg.sessionId !== undefined) {
                            sessionCache.clear(msg.sessionId);
                        }

                        // Update session cache with the updated session object.
                        sessionCache.write(
                            session.id,
                            JSON.stringify(session),
                            function (reply, err) {
                                if (reply !== undefined) {
                                    return;
                                }

                                // Error updating the session cache.
                                logger.error({err});
                                error({
                                    message: "Unable to update session cache:"
                                            + session.id + ":" + err.message,
                                    fatal: false,
                                    alert: {
                                        level: alertType.level.warning,
                                        description:
                                                alertType.description.CacheError
                                    }
                                });
                            }
                        );

                        if (session.redirectToServer !== true) {
                            // Invoking the provided connection handler.
                            connected();

                            logger.trace("CONNNNNNNNNNNNEEEEEEEEECCCCCCCTTTTT");
                        }

                        // Continue to process the next record.
                        process();
                    }


                    /**
                     * @brief Function to be called after the record has been
                     *        processed and the next message to be sent is a
                     *        finished message. The current connection state
                     *        is updated and the finished message is queued.
                     *
                     * @param callback function to be invoked after message is
                     *                 queued: 'function callback()'
                     *
                     * @return none
                     */
                    function sendFinished(callback) {

                        // Update current connection state.
                        state.current.read = state.pending.read;
                        state.current.write = state.pending.write;

                        // Check if the hello message indicates a redirect.
                        if (
                            msg.redirectToServer === true
                            && msg.redirectPayload !== undefined
                            && msg.redirectPayload.session !== undefined
                        ) {
                            /* Update the session cache with the session object
                             * received in the record. This helps when the
                             * client connects to this party after being
                             * informed about the redirect.
                             */
                            sessionCache.write(
                                session.redirectSession.id,
                                JSON.stringify(session.redirectSession),
                                function (reply, err) {
                                    // Error updating session cache.
                                    if (
                                        err !== undefined
                                        || reply === undefined
                                    ) {
                                        let message;
                                        if (err !== undefined) {
                                            message = err.message;
                                        }
                                        error({
                                            message: "Unable to update cache:"
                                                    + session.redirectSession.id
                                                    + ":" + message,
                                            fatal: false,
                                            alert: {
                                                level: alertType.level.warning,
                                                description:
                                                        alertType
                                                    .description
                                                    .CacheError
                                            }
                                        });

                                        return;
                                    }

                                    // Queue Finished message.
                                    queue(createRecord({
                                        type: contentType.handshake,
                                        data: createHandshakeFinished()
                                    }));

                                    if (typeof callback === "function") {
                                        return callback();
                                    }
                                }
                            );

                            return;
                        }

                        // Queue Finished message.
                        queue(createRecord({
                            type: contentType.handshake,
                            data: createHandshakeFinished()
                        }));

                        if (typeof callback === "function") {
                            return callback();
                        }
                    }


                    /**
                     * @brief Function to be called after the record has been
                     *        processed and the next message to be sent is an
                     *        auth hello message. The current write state is
                     *        updated to use the secret key provided in the
                     *        hello message and auth hello record is queued. All
                     *        further read/writes will use the new secret
                     *        generated by the server. Also, the user-id is
                     *        stored in the host cache to speed up initiator
                     *        authentication on the next connection, as the
                     *        server wont need to create a new secret and
                     *        encrypt it using the initiator's public key.
                     *
                     * @param callback function to be invoked after message is
                     *                 queued: 'function callback()'
                     *
                     * @return none
                     */
                    function sendAuthHello(callback) {
                        // Use the initiator secret to write this message.
                        state.current.write = state.pending.write;

                        if (msg.redirectToServer === true) {
                            session.redirectToServer = true;
                        }

                        /* Throw away the initiator secret and create and
                         * update the connection state with a new secret.
                         */
                        session.sp.keys.secretKey = undefined;
                        state.pending = createConnectionState();
                        updateConnectionState(state.pending, function () {
                            // Queue Auth hello message.
                            queue(createRecord({
                                type: contentType.handshake,
                                data: createAuthHello()
                            }));

                            /* Use new connection state for all
                             * further read/writes.
                             */
                            state.current.read = state.pending.read;
                            state.current.write = state.pending.write;

                            if (typeof callback === "function") {
                                return callback();
                            }
                        });
                    }

                    isInternal = msg.isInternal;

                    // Update session object.
                    session.id = sessionId;
                    session.sp = {};

                    // The next message expected will be application data.
                    expect = expectType.initiatorAppData;

                    /* Update the session using sessionData from the cache or
                     * the parsed hello message.
                     */
                    if (sessionData !== undefined) {
                        // Use security parameters from resumed session.
                        session.sp = sessionData.sp;
                        session.connectionId = sessionData.connectionId;
                        session.resuming = true;
                    } else {
                        // New session. Create new security params.
                        session.resuming = false;
                        createSecurityParameters(msg);
                    }

                    /* Create and update the connection state to use the secret
                     * key provided in the hello message.
                     */
                    state.pending = createConnectionState();
                    updateConnectionState(state.pending, function () {
                        // Connection now open.
                        open = true;

                        // Check if this is a resuming session.
                        if (session.resuming === true) {
                            /* If this is a resuming session, send a finished
                             * message. We do not need to perfom any further
                             * authentication.
                             */
                            sendFinished(authenticationDone);
                        } else {
                            // This is a new session.
                            if (fail === true) {
                                return;
                            }

                            // Initiator authentication is required.
                            sendAuthHello(authenticationDone);
                        }
                    });

                });
            }

            // Check if the received hello message has a pre auth session id.
            if (parsedRecord.sessionId !== undefined) {
                /* Pre existing session id sent in the message.
                 * Read the session object from the cache using the given id.
                */
                sessionCache.read(
                    parsedRecord.sessionId,
                    function (reply, err) {
                        // Error reading session cache.
                        if (err !== undefined || reply === undefined) {
                            error({
                                message: 'Invalid Session. Please reconnect',
                                alert: {
                                    level: alertType.level.fatal,
                                    description:
                                            alertType.description.invalidSession
                                }
                            });

                            return;

                        }

                        // Parse the received session string.
                        let sessionData;
                        try {
                            sessionData = JSON.parse(reply);
                        } catch (sessionParseError) {
                            logger.error(sessionParseError);
                            return error({
                                message: "Handshake failure.",
                                alert: {
                                    level: alertType.level.fatal,
                                    description: alertType
                                        .description
                                        .handshakeFailure
                                }
                            });
                        }

                        // Get the secret key from session stored in the cache.
                        let secret;
                        if (
                            sessionData.sp !== undefined
                            && sessionData.sp.keys !== undefined
                        ) {
                            secret = sessionData.sp.keys.secretKey;
                        }

                        // Update msg using the received data.
                        let msg = {
                            version: parsedRecord.version,
                            sessionId: parsedRecord.sessionId,
                            secret
                        };

                        // Use given secret to decrypt the helloData received.
                        let cipherState = {
                            key: msg.secret
                        };
                        if (parsedRecord.helloData !== undefined) {
                            let helloData = cipherSuite.decrypt(
                                cipherState,
                                parsedRecord.helloData
                            );

                            try {
                                helloData = JSON.parse(helloData);
                            } catch (parseError) {
                                logger.error(parseError);
                                return error({
                                    message: "Error: Hello data is missing",
                                    alert: {
                                        level: alertType.level.fatal,
                                        description: alertType
                                            .description
                                            .handshakeFailure
                                    }
                                });
                            }

                            // Update the message using the decrypted helloData.
                            msg.isInternal = helloData.isInternal;
                            msg.redirectToServer = helloData.redirectToServer;
                            msg.redirectPayload = helloData.redirectPayload;
                        } else {
                            // Incomplete hello message.
                            return error({
                                message: "Error: Hello data is missing",
                                alert: {
                                    level: alertType.level.fatal,
                                    description: alertType
                                        .description
                                        .handshakeFailure
                                }
                            });
                        }

                        // Ready to process the received message.
                        sendDone(msg, sessionData);
                    }
                );

            } else {
                // No existing session. Parse the hello message.
                let msg = parseHelloMessage(parsedRecord);
                if (fail) {
                    return;
                }

                // Ready to process the received message.
                sendDone(msg);
            }

        }


        /**
         * @brief This is the finished message handler. When this type of
         *        message is received from the server, the initiator updates
         *        the session id with the id received in the message and
         *        updates its session cache with the session object. The
         *        provided connection handler is invoked after setting the
         *        connection to be established.
         *
         * @param parsedRecord the parsed finished record object.
         *
         * @return none
         */
        function handleHandshakeFinished(parsedRecord) {

            logger.trace("Handling finished");

            // Update the session id based on the received record.
            session.id = parsedRecord.sessionId;

            // Change current write state for all further read/writes
            state.current.read = state.pending.read;
            state.current.write = state.pending.write;

            // Expecting only application data as the next message.
            expect = expectType.serverAppData;

            // Handshake complete.
            handshaking = false;

            // to do: do something with userid ??

            /* Update the session cache with the current session for
             * future connections.
             */
            if (parsedRecord.sessionId !== undefined) {
                sessionCache.write(
                    JSON.stringify(hostInfo),
                    JSON.stringify(session)
                );
                logger.trace("Writing to cache first time");
            }

            // Connection is complete now.
            isSeifConnected = true;

            /* If this connection was to inform about a redirect, then call
             * the appropriate provided connection handler.
             */
            if (redirectToServer === true) {
                redirectConnected(parsedRecord.redirectSessionId);
            } else {
                connected();
            }

            // Continue to process the next record.
            process();
        }


        /**
         * @brief This is the handshake message handler. The server looks up the
         *        appropriate state table with the handshake record type to
         *        determine how to handle the received record. If the record is
         *        not of an expected type, the connection is closed.
         *
         * @return none
         */
        function handleHandshake() {
            // Get the handshake record type.
            let rec;
            try {
                rec = JSON.parse(record.fragment);
            } catch (parseError) {
                logger.error(parseError);
                handleUnexpected();
            }
            record.fragment = "";
            let type = rec.recordType;

            logger.trace({party, expect, type}, "handle handshake");

            // handle expected message
            if (hsTable[party][expect][type] !== undefined) {
                // Initialize server session
                if (
                    party === connectionEnd.server
                    && open === false
                    && fail === false
                ) {
                    handshaking = true;
                    session = {};
                }

                // handle specific handshake type record
                hsTable[party][expect][type](rec);
            } else {
                // Unexpected record received.
                handleUnexpected();
            }
        }


        /**
         * @brief This is the application data message handler. The party
         *        invoked the dataReady handler provided when setting up the
         *        connection.
         *
         * @return none
         */
        function handleApplicationData() {
            logger.trace("Handling Application data.");

            /* If data blob contains a JSON message, parse it, otherwise
             * create a blob.
             */
            let message;
            if (record.fragment.originalType === "JSON") {
                try {
                    message = JSON.parse(record.fragment.message);
                } catch (parseError) {
                    // Error parsing the json record.
                    logger.error(parseError);
                    error({
                        message: "Message error",
                        alert: {
                            level: alertType.level.fatal,
                            description: alertType.description.internalError
                        }
                    });
                }
            } else {
                message = new Buffer(record.fragment.message, "hex");
            }

            // Call the dataReady handler provided.
            dataReady({
                messageId: record.fragment.messageId,
                message
            });

            record.fragment = "";

            // Continue to process the next record.
            process();
        }


        /**
         * @brief This is the redirect message handler. When the initiator
         *        receives this message, it updates the session cache with the
         *        session id and address and/or public key (in case of
         *        permanent redirects), so that the initiator can connect to
         *        the new party. In case of permanent redirects, the host cache
         *        is updated too so that any future new connections go to the
         *        new host.
         *
         * @return None
         */
        function handleRedirect() {
            logger.trace("Handling redirect from server.");

            // Get the record fragment data and parse it.
            let dataReceived = record.fragment;
            record.fragment = "";
            try {
                let response = JSON.parse(dataReceived);
                if (response !== undefined) {
                    /* Update session cache with address/public-key and session
                     * id obtained from the message.
                     */
                    session.id = response.sessionId;

                    // Writing to the session cache.
                    sessionCache.write(
                        JSON.stringify({
                            address: response.address,
                            publicKey: response.publicKey || hostInfo.publicKey
                        }),
                        JSON.stringify(session)
                    );

                    // Update the host cache if the redirect is permanent.
                    if (response.permanent === true) {
                        let hostDetails = {
                            connectAddress: response.address,
                            connectPublicKey: response.publicKey
                        };

                        updateHostCache(
                            {value: JSON.stringify(hostDetails)},
                            function (reply, err) {
                                if (err !== undefined || reply === undefined) {
                                    logger.error(err);
                                }
                            }
                        );
                    }

                    // Invoke the provided redirect handler.
                    receivedRedirect(response);
                }
            } catch (err) {
                // Error parsing the json record.
                logger.error(err);
            }

            // Continue to process the next record.
            process();

        }


        /**
         * @brief This is the application data confirmation message handler.
         *        Invoke the provided confirmation handler.
         *
         * @return None
         */
        function handleApplicationDataConfirmation() {
            logger.trace("Handling application data confirmation");

            // Get the record fragment data and parse it.
            let dataReceived = record.fragment;
            record.fragment = "";
            let confirmation;
            try {
                confirmation = JSON.parse(dataReceived);
            } catch (parseError) {
                // Error parsing the json record.
                logger.error(parseError);
                error({
                    message: "Message error",
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.internalError
                    }
                });
            }

            // Invoke the received confirmation handler.
            if (confirmation !== undefined) {
                receivedMessageConfirmation(confirmation);
            }

            // Continue to process the next record.
            process();
        }


        /**
         * @brief This is the handshake redirect message handler. The redirected
         *        session is obtained from the received record and then stored
         *        in the session cache with a new session id, which is then sent
         *        back to the initator of the redirect via the handshake
         *        finished message.
         *
         * @param parsedRecord received decrypted redirect seif record
         *
         * @return none
         */
        function handleHandshakeRedirect(parsedRecord) {
            // Get the record fragment data and parse it.
            logger.trace({parsedRecord}, "handling redirect handshake");

            if (isInternal && parsedRecord.redirectPayload !== undefined) {
                let saveState = false;
                seifRNG.getBytes(32, saveState, function (random) {
                    // Assign a new session id to the redirected session.
                    parsedRecord.redirectPayload.session.id = random;
                    // Store the redirected session in the current session.
                    session.redirectSession
                            = parsedRecord.redirectPayload.session;

                    /**
                     * @brief Function to be called after the record has been
                     *        processed and the next message to be sent has been
                     *        queued. The connection is now established and the
                     *        provided connection handler is invoked after
                     *        updating the session cache.
                     *
                     * @return none
                     */
                    function redirectComplete() {
                        // Handshake complete.
                        handshaking = false;

                        // The two ends are now connected.
                        isSeifConnected = true;

                        // Update session cache with the updated session object.
                        sessionCache.write(
                            session.id,
                            JSON.stringify(session),
                            function (reply, err) {
                                if (reply !== undefined) {
                                    return;
                                }

                                // Error updating the session cache.
                                logger.error({err});
                                error({
                                    message: "Unable to update session cache:"
                                            + session.id + ":" + err.message,
                                    fatal: false,
                                    alert: {
                                        level: alertType.level.warning,
                                        description:
                                                alertType.description.CacheError
                                    }
                                });
                            }
                        );

                        logger.trace("CONNNNNNNNNNNNEEEEEEEEECCCCCCCTTTTTTT");

                        // Continue to process the next record.
                        process();
                    }


                    /**
                     * @brief Function to be called after the record has been
                     *        processed and the next message to be sent is a
                     *        finished message.
                     *
                     * @param callback function to be invoked after message is
                     *                 queued: 'function callback()'
                     *
                     * @return none
                     */
                    function sendHandshakeFinished(callback) {
                        /* Update the session cache with the session object
                         * received in the record. This helps when the
                         * client connects to this party after being
                         * informed about the redirect.
                         */
                        sessionCache.write(
                            session.redirectSession.id,
                            JSON.stringify(session.redirectSession),
                            function (reply, err) {
                                // Error updating session cache.
                                if (
                                    err !== undefined
                                    || reply === undefined
                                ) {
                                    let message;
                                    if (err !== undefined) {
                                        message = err.message;
                                    }
                                    error({
                                        message: "Unable to update cache:"
                                                + session.redirectSession.id
                                                + ":" + message,
                                        fatal: false,
                                        alert: {
                                            level: alertType.level.warning,
                                            description:
                                                    alertType
                                                .description
                                                .CacheError
                                        }
                                    });

                                    return;
                                }

                                // Queue Finished message.
                                queue(createRecord({
                                    type: contentType.handshake,
                                    data: createHandshakeFinished()
                                }));

                                // Send records over tcp.
                                flush();

                                if (typeof callback === "function") {
                                    return callback();
                                }
                            }
                        );
                    }

                    return sendHandshakeFinished(redirectComplete);
                });
            }
        }


        /**
         * @brief This is the handler for seif errors received from the other
         *        end point of the connection. This currently happens only in
         *        the case of seif version mismatch.
         *
         * @return none
         */
        function handleSeifError() {
            // Parse the received error record and call the error handler func.
            let rec;
            try {
                rec = JSON.parse(record.fragment);
            } catch (parseError) {
                logger.error(parseError);
                handleUnexpected();
            }
            return error({
                message: rec.message,
                alert: rec.alert,
                inform: true
            });
        }


        /**
         * @brief Performs a handshake using the seif Handshake Protocol,
         *        as a client. The function checks if we have an existing
         *        session with the party we are connecting to. If so, we create
         *        a hello message with the pre auth session id. Otherwise, we
         *        create a hello message which will contain a newly generated
         *        secret key encrypted using the server's public key and other
         *        party/connection info such as the user id, initiator's public
         *        key and indication of redirects.
         *
         * @return none
         */
        function handshake() {
            logger.trace("Handshaking");

            /**
             * @brief Starts a new session for the current connection. The
             *        connection state is also updated with a new session secret
             *        key for future communication.
             *
             * @return none
             */
            function startNewSession() {
                // set up session
                session = {
                    id: undefined,
                    sp: {
                        keys: undefined
                    }
                };

                // Create pending state.
                state.pending = createConnectionState();

                updateConnectionState(state.pending, function () {
                    /* Change current read state to pending read
                     * state to receive further messages.
                     */
                    state.current.read = state.pending.read;

                    // Connection now open.
                    open = true;

                    // Send client hello message.
                    queue(createRecord({
                        type: contentType.handshake,
                        data: createHello()
                    }));
                    flush();
                });

            }

            // Error to call this in server mode.
            if (party !== connectionEnd.initiator) {
                error({
                    message: 'Cannot initiate handshake as a server.',
                    fatal: false
                });
            } else if (handshaking === true && retryAttempts !== 1) {
                // Handshake is already in progress, fail but not fatal error.
                error({
                    message: 'Handshake already in progress.',
                    fatal: false
                });
            } else {
                // Clear fail flag on reuse.
                if (fail === true && open === false) {
                    fail = false;
                }

                // Now handshaking begins.
                handshaking = true;

                hostInfo = {
                    address: remoteAddress,
                    publicKey: connectPublicKey
                };

                // Start new session if we are retrying after a handshake fails.
                if (retryAttempts === 1) {
                    startNewSession();
                    return;
                }

                // Checking if the session info exists in the session cache.
                sessionCache.read(
                    JSON.stringify(hostInfo),
                    function (reply, err) {
                        if (reply === undefined || err !== undefined) {
                            // No prior session available in cache.
                            startNewSession();
                            return;
                        }

                        /* Prior session exists. Setting the session to value
                         * received from the cache.
                         */
                        try {
                            session = JSON.parse(reply);
                        } catch (parseError) {
                            logger.error(parseError);
                            return error({
                                message: 'Unable to parse session from cache.',
                                alert: {
                                    level: alertType.level.fatal,
                                    description: alertType
                                        .description
                                        .unexpectedMessage
                                }
                            });
                        }

                        // to do:need to validate sessions

                        /* Create pending connection state and update it to use
                         * the previously created secret key obtained from the
                         * session read from the cache.
                         */
                        state.pending = createConnectionState();
                        updateConnectionState(state.pending, function () {
                            /* Change current read state to pending read state
                             * to receive further messages.
                             */
                            state.current.read = state.pending.read;

                            // Connection now open.
                            open = true;

                            // Send client hello message with the session id.
                            queue(createRecord({
                                type: contentType.handshake,
                                data: createSessionHello()
                            }));
                            flush();
                        });
                    }
                );

            }
        }



        /**
         * @brief Packages the application data into a seif record.
         *
         * @param data the application data to be sent
         *
         * @return none
         */
        function prepare(data) {
            logger.trace("Preparing to send application data.");
            queue(createRecord({
                type: contentType.applicationData,
                data
            }));
            flush();
        }


        /**
         * @brief Packages the redirect request into a seif record. This happens
         *        when server prepares to send redirect info to the initiator
         *        to inform it to connect to another server.
         *
         * @param data the redirect data to be sent
         *
         * @return none
         */
        function prepareRedirectRequest(data) {
            logger.trace("Preparing to send redirect request.");
            queue(createRecord({
                type: contentType.redirect,
                data
            }));
            flush();

        }


        /**
         * @brief Packages the application data confirmation into a seif record.
         *        This is sent when the party receives and successfully decrypts
         *        an application data record.
         *
         * @param data confirmation message to be sent
         *
         * @return none
         */
        function prepareApplicationDataConfirmation(data) {
            queue(createRecord({
                type: contentType.applicationDataConfirm,
                data: createApplicationDataConfirmation(data)
            }));
            flush();
        }

        // map initiator current expect state and content type to function

        let initatorHelloTable
                = ctTable[connectionEnd.initiator][expectType.serverHello];
        let initatorFinishedTable
                = ctTable[connectionEnd.initiator][expectType.serverFinished];
        let initatorAppDataTable
                = ctTable[connectionEnd.initiator][expectType.serverAppData];

        initatorHelloTable[contentType.handshake] = handleHandshake;
        initatorHelloTable[contentType.redirect] = handleRedirect;
        initatorHelloTable[contentType.seifError] = handleSeifError;

        initatorFinishedTable[contentType.handshake] = handleHandshake;
        initatorFinishedTable[contentType.redirect] = handleRedirect;
        initatorFinishedTable[contentType.seifError] = handleSeifError;

        initatorAppDataTable[contentType.handshake] = handleHandshake;
        initatorAppDataTable[contentType.applicationData]
                = handleApplicationData;
        initatorAppDataTable[contentType.redirect] = handleRedirect;
        initatorAppDataTable[contentType.applicationDataConfirm]
                = handleApplicationDataConfirmation;


        let serverHelloTable
                = ctTable[connectionEnd.server][expectType.initiatorHello];
        let serverAppDataTable
                = ctTable[connectionEnd.server][expectType.initiatorAppData];

        serverHelloTable[contentType.handshake]
                = handleHandshake;

        serverAppDataTable[contentType.handshake] = handleHandshake;
        serverAppDataTable[contentType.applicationData]
                = handleApplicationData;
        serverAppDataTable[contentType.applicationDataConfirm]
                = handleApplicationDataConfirmation;

        // map initiator current expect state and handshake type to function

        let initiatorHsHelloTable
                = hsTable[connectionEnd.initiator][expectType.serverHello];
        let initiatorHsFinishedTable
                = hsTable[connectionEnd.initiator][expectType.serverFinished];

        initiatorHsHelloTable[handshakeType.authHello] = handleAuthHello;

        initiatorHsFinishedTable[handshakeType.authHello] = handleAuthHello;
        initiatorHsFinishedTable[handshakeType.handshakeFinished]
                = handleHandshakeFinished;

        let serverHsHelloTable
                = hsTable[connectionEnd.server][expectType.initiatorHello];
        let serverHsAppDataTable
                = hsTable[connectionEnd.server][expectType.initiatorAppData];

        serverHsHelloTable[handshakeType.hello] = handleHello;

        serverHsAppDataTable[handshakeType.handshakeRedirect]
                = handleHandshakeRedirect;

        // Reset the newly created connection object.
        reset();

        return Object.freeze({
            getCurrentSession: function () {
                return session;
            },
            isSeifConnected: function () {
                return isSeifConnected;
            },
            seifRecords,
            redirectToServer,
            updateRetryAttempts,
            disconnect,
            updateRemoteAddress,
            error,
            isHandshaking,
            close,
            process,
            handshake,
            prepare,
            prepareRedirectRequest,
            prepareApplicationDataConfirmation
        });
    } // end createConnection()

    return Object.freeze({
        createConnection
    });
}

module.exports = seifProtocol();