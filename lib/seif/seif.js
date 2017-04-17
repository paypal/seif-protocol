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

function seifProtocol() {

    'use strict';

    let util = require("./util");
    let loggerGenerator = require("../log");

    let logger = loggerGenerator.child({componentName: "SEIF_PROTOCOL"});

    // Supported Version
    let currentVersion = 0;

    /**
     * Whether this party is considered the "initiator" or "listener".
     * enum { listener, initiator } connectionEnd;
     */
    let connectionEnd = {
        listener: "listener",
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
            cacheError: "cacheError"
        }
    };

    // Types of protocol messages expected to be received next
    let expectType = {
        listenerHello: "listenerHello", // rcv listener hello
        listenerFinished: "listenerFinished", // rcv listener hello done
        listenerAppData: "listenerAppData", // rcv application data

        initiatorHello: "initiatorHello", // rcv initiator hello
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
        ctTable[connectionEnd.initiator][expectType.listenerHello] = {};
        ctTable[connectionEnd.initiator][expectType.listenerFinished] = {};
        ctTable[connectionEnd.initiator][expectType.listenerAppData] = {};

        ctTable[connectionEnd.listener] = {};
        ctTable[connectionEnd.listener][expectType.initiatorHello] = {};
        ctTable[connectionEnd.listener][expectType.initiatorAppData] = {};

        /* Table to decide which handler to call for a particular handshake
         * message
         */
        let hsTable = {};
        hsTable[connectionEnd.initiator] = {};
        hsTable[connectionEnd.initiator][expectType.listenerHello] = {};
        hsTable[connectionEnd.initiator][expectType.listenerFinished] = {};

        hsTable[connectionEnd.listener] = {};
        hsTable[connectionEnd.listener][expectType.initiatorHello] = {};
        hsTable[connectionEnd.listener][expectType.initiatorAppData] = {};

        // Determine whether current party is an initiator or a listener.
        let party = connectionEnd.initiator;
        if (options.listener === true) {
            party = connectionEnd.listener;
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

        // invoked when data needs to be encrypted using ECC
        let eccEncrypt = options.eccEncrypt;

        // invoked when data needs to be decrypted using ECC
        let eccDecrypt = options.eccDecrypt;

        // invoked when an error occurs
        let seifError = options.seifError;

        // cipher suite to be used for link encryption/decryption
        let cipherSuite = options.cipherSuite;

        // public/private key of the party
        let privateKey = options.privateKey;
        let publicKey = options.publicKey;

        // public key of the party being connected to (listener)
        let connectPublicKey = options.connectPublicKey;

        // address of the party with which connection has been established
        let remoteAddress = options.remoteAddress;

        // isaac rng object to be used
        let seifRNG = options.seifRNG;

        // properties of party being connected to
        let hostInfo = {
            address: options.remoteAddress,
            publicKey: options.connectPublicKey
        };

        // connectionInfo part of hello, sent unencrypted
        let connectionInfo = options.connectionInfo;

        // buffer responsible for received data
        let input = util.createBuffer();
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
         * @brief Creates a seif record with the given type and data.
         *
         * @param options object containing:
         *                type: record type
         *                data: record data
         *
         * @return object the created record
         */
        function createRecord(options) {

            let createdRecord = {
                to: remoteAddress,
                payload: {
                    type: options.type,
                    data: options.data
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
         * @return object the created error record
         */
        function createSeifError(seifError) {
            // Build record.
            let seifErrorRecord = {
                message: seifError.message,
                alert: seifError.alert
            };

            return {
                record: seifErrorRecord,
                blobs: []
            };
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
         *           origin  - initiator/listener
         *           fatal   - boolean indicating whether error is fatal
         *           message - description of error
         *           alert   - object describing level and type of error
         *
         * @return none
         */
        function error(ex) {
            logger.error({ex});
            // Set origin if not set.
            let origin = "listener";
            if (party === connectionEnd.initiator) {
                origin = "initiator";
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
         * @brief Encrypts and queues record and associated blobs for delivery.
         *        Two bytes encoding length of the encrypted details record
         *        is queued first, follwed by the encrypted details record which
         *        is finally follwed by encrypted blobs described in the details
         *        record.
         *
         * @param object the record to queue.
         *
         * @return none
         */
        function queue(thisRecord) {

            // Proceed to build identifier JSON from thisRecord.

            logger.trace('Queue record to send.');

            // Error during record creation.
            if (thisRecord === undefined) {
                return;
            }

            let encryptedRec; // encrypted seif json record

            /* Current connection state write mode for encrypting record to be
             * queued.
             */
            let s = state.current.write;

            /* If record has blobs, proceed to encrypt them and encode details
             * in the field 'blobs'.
             */
            let encryptedBlobs = [];
            let idx = -1;
            thisRecord.payload.data.blobs.forEach(
                function (blob) {
                    idx = idx + 1;
                    try {

                        let tempEncrypted = s.update(blob);

                        encryptedBlobs.push(tempEncrypted);

                        // Add blob details to indentifier JSON.
                        thisRecord.payload.data.record.blobs[idx].length =
                                tempEncrypted.length;

                    } catch (blobError) {
                        return error({
                            message: 'Could not encrypt record:' +
                                    blobError.message,
                            alert: {
                                level: alertType.level.fatal,
                                description: alertType.description.internalError
                            }
                        });
                    }
                }
            );

            // Delete blob data from identifier JSON.
            thisRecord.payload.data.blobs = [];
            logger.trace({identifierJSON: thisRecord});

            // Serialize identifier JSON before converting it into a buffer and
            // encrypting it.
            try {
                thisRecord = Buffer.from(JSON.stringify(thisRecord));
                encryptedRec = s.update(thisRecord);
            } catch (encryptError) {
                return error({
                    message: 'Could not encrypt record:' + encryptError.message,
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.internalError
                    }
                });
            }

            /* Enqueue length of encrypted identifier JSON, the encrypted
             * identifier JSON and finally associated encrypted blobs.
             */
            let lengthBytes = util.getBytesFromNumber(encryptedRec.length);

            seifRecords.push(lengthBytes);
            seifRecords.push(encryptedRec);
            encryptedBlobs.forEach(
                function (encryptedBlob) {
                    seifRecords.push(encryptedBlob);
                }
            );
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
                 * @return buffer record serialized and converted to a buffer.
                 */
                function cipherFunction(inputRecord) {
                    if (inputRecord instanceof Buffer) {
                        return inputRecord;
                    }
                    return Buffer.from(JSON.stringify(inputRecord));
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
                expect = expectType.listenerFinished;
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
         *        of the succeeding record from the first two bytes received and
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

            /* Get length of identifier record from the first two bytes of the
             * received data.
             */
            let length = util.getNumberFromBytes(currentInput.getData(2));
            logger.trace({length}, "Extracted number");

            // Check if sufficient data available to proceed.
            if (length === undefined || length <= 0) {
                return false;
            }

            /* Removing the bytes representing the "length" from the input
             * buffer.
             */
            currentInput.removeData(2);

            // Creating basic record based on received data.
            record = {
                type: undefined,
                length,
                ready: false,
                blobs: [],
                data: undefined,
                currentProcessingIdx: -1,
                processingBlobs: false
            };

            return true;
        }


        /**
         * @brief Reads and decrypts recieved blob and appends its data
         *        to the "record" object's internal buffer.
         *
         * @return boolean True if the complete blob is read without any
         *         errors, False otherwise
         */
        function readRecordBlob() {
            logger.trace('Attemping to read record blob.');

            // Ensure there is enough input data to get the entire record.
            let currentInput = input;
            let len = currentInput.size();
            if (len < record.length) {
                // Not enough data yet.
                return false;
            }

            logger.trace({inputSize: input.size()}, 'Reading record blob.');

            // There is enough data to parse the pending record.
            let length = record.length;
            let blob = currentInput.removeData(length);
            currentInput.compact();

            logger.trace(
                {
                    inputSize: input.size()
                },
                'Reading record blob After Compacting.'
            );

            // Update record using current read state
            let s = state.current.read;

            // Decrypted blob.
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

            // Add the decrypted blob to the "record"'s internal buffer.
            record.blobs.push(decryptedBlob);

            logger.trace(
                {length: decryptedBlob.length},
                "Adding the blob received"
            );

            // Check if all blobs described in the identifier JSON have been
            // recieved.
            if (record.blobs.length === record.data.blobs.length) {
                // Record is now ready to be handled.
                record.ready = true;
                return true;
            }

            // Update reading state to next expected blob described
            // in the identifier JSON.
            record.currentProcessingIdx = record.blobs.length;
            record.length =
                    record.data.blobs[record.currentProcessingIdx].length;
            return readRecordBlob();
        }


        /**
         * @brief Reads the identifier record's contents and appends the data to
         *        the "record" object's internal buffer.
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

            // There is enough data to parse the pending record.
            let length = record.length;
            let receivedRecord = currentInput.removeData(length);
            currentInput.compact();

            // Update the record using the current state's read mode.
            let s = state.current.read;

            // decrypted identifier JSON record.
            let decryptedRecord;
            try {
                // Read and decrypt (if necessary) the seif record.
                decryptedRecord = s.update(receivedRecord);
                decryptedRecord = decryptedRecord.toString();
                decryptedRecord = JSON.parse(decryptedRecord);
                logger.trace({decryptedRecord}, 'Decrypted Record.');
            } catch (readError) {
                // Error reading/decrypting the record using the read mode.
                logger.error(readError);
                error({
                    message: 'Bad JSON record. Error parsing: ' +
                            readError.message,
                    alert: {
                        level: alertType.level.fatal,
                        description: alertType.description.internalError
                    }
                });

                return false;
            }

            // Fill the "record" object with data from the identifier record.
            record.type = decryptedRecord.payload.type;
            record.data = decryptedRecord.payload.data.record;

            // Check if this seif record is indicating about a following blob.
            if (record.data.blobs.length > 0) {
                /* Get the blob details to facilitate reading of the following
                 * blob.
                 */
                record.currentProcessingIdx = record.blobs.length;
                record.length = record
                    .data.blobs[record.currentProcessingIdx].length;
                record.processingBlobs = true;
            } else {
                record.ready = true;
            }
            return true;
        }


        /**
         * @brief Updates the current seif engine state based on the given
         *        record and handles the record based on its type.
         *
         * @return None
         */
        function handleRecord() {

            logger.trace({type: record.type}, "Handling new record");

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
                {dataLen: (data && data.length) || 0, dataType: typeof data},
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
                    record !== undefined &&
                    record.ready === true
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
                    fail === false &&
                    record !== undefined &&
                    record.ready === false
                ) {
                    logger.trace('Processing the record:Reading the record.');
                    if (record.data === undefined) {
                        rval = readRecord();
                    }

                    if (
                        record.processingBlobs === true &&
                        record.ready !== true
                    ) {
                        rval = readRecordBlob();
                    }
                }

                // Record ready to be handled, update engine state.
                if (
                    fail === false &&
                    record !== undefined &&
                    record.ready === true &&
                    rval === true
                ) {
                    logger.trace('Processing the record: record ready.');
                    handleRecord();
                }
            }

            return rval;
        }



        /**
         * @brief Parses a hello message from an initiator or initiatorAuth
         *        record.
         *
         * @param record the record to parse
         *
         * @return object the parsed message
         */
        function parseHelloMessage() {
            logger.trace('Parsing hello message');

            let msg;
            let initiator = (party === connectionEnd.initiator);

            // Get the encrypted secret key from the record.
            let temp = record.blobs[0];

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

            /* Construct the message object with below properties including the
             * secret obtained by decrypting the given encrypted secret key in
             * the message using the receiver's private key.
             */
            msg = {
                version: record.data.version,
                secret
            };

            // Create cipher state with given secret to decrypt "helloData"
            let cipherState = {
                key: msg.secret
            };

            let helloData = record.blobs[1];
            if (record.data.recordType === handshakeType.hello) {

                helloData = cipherSuite.decrypt(
                    cipherState,
                    helloData
                );

                try {
                    helloData = JSON.parse(helloData.toString());
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
            } else if (initiator === false) {
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
            if (initiator === false) {
                // Public-key of the initiator party
                msg.initiatorPublicKey = helloData.initiatorPublicKey;
                msg.connectionInfo = record.data.connectionInfo;
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
                    secretKey: Buffer.from(randomBytes, 'hex')
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
         *        over the connection. This case occurs when the listener needs
         *        to authenticate the initiator and generates a new secret key
         *        for further communication.
         *
         * @param state connection state object with read/write modes
         * @param callback function to be invoked once the conection state has
         *                 been updated, of the form: function callback()
         *
         * @return none
         */
        function updateConnectionState(state, callback) {

            // Determining if the current party is an initiator or a listener.
            let isInitiator = (party === connectionEnd.initiator);

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
                    cipherSuite.initConnectionState(state, isInitiator, sp);
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
                    cipherSuite.initConnectionState(state, isInitiator, sp);
                    return callback();
                });

                return;
            }

            return callback();
        }


        /**
         * @brief Creates a hello message with following attributes:
         *        recordType     - type of record.
         *        version        - protocol version info.
         *        key            - secret key encrypted using the listening
         *                         party's public-key.
         *        helloData      - object containing party/connection info.
         *        connectionInfo - unencrypted context to the hello message.
         *
         * @return object hello record with blobs key and helloData.
         */
        function createHello() {
            logger.trace('Creating hello.');

            // Get the secret key to be sent from the session security params.
            let sp = session.sp;

            // Encrypt the secret using the listening party's public key (ECC).
            let encryptedSecretKey;
            try {
                encryptedSecretKey = eccEncrypt(
                    connectPublicKey,
                    sp.keys.secretKey
                );
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
                initiatorPublicKey: publicKey // initiator's public key
            };

            // Encrypt the helloData using the session secret.
            helloData = cipherSuite.encrypt(
                cipherState,
                Buffer.from(JSON.stringify(helloData))
            );

            // Build the hello record.
            let helloRecord = {
                recordType: handshakeType.hello,
                version: currentVersion,
                connectionInfo,
                blobs: [
                    {
                        id: "key",
                        length: encryptedSecretKey.length
                    },
                    {
                        id: "helloData",
                        length: helloData.length
                    }
                ]
            };

            logger.trace({helloRecord}, "Hello record after encryption");

            // Return the JSON object with blobs described in the helloRecord.
            return {
                record: helloRecord,
                blobs: [
                    encryptedSecretKey,
                    helloData
                ]
            };
        }


        /**
         * @brief Creates a Listener Hello message. This is sent to authenticate
         *        the initiator; the party sends a new secret generated in
         *        response to the initiator hello. The message contains the
         *        following attributes:
         *        recordType - type of record
         *        version    - protocol version info
         *        key        - secret key encrypted using the initiator's
         *                     public-key
         *
         * @return object authHello record with key blob.
         */
        function createAuthHello() {
            logger.trace('Creating Auth Hello.');

            // Get the secret key used for future communication.
            let sp = session.sp;

            /* Encrypt the secret key using the initiator's public key sent by
             * the initiator in the Hello.
             */
            let encryptedSecretKey;
            try {
                encryptedSecretKey = eccEncrypt(
                    sp.initiatorPublicKey,
                    sp.keys.secretKey
                );
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
            let authHelloRecord = {
                recordType: handshakeType.authHello,
                version: currentVersion,
                blobs: [
                    {
                        id: "key",
                        length: encryptedSecretKey.length
                    }
                ]
            };

            // Return the JSON object with blobs described
            // in the authHelloRecord.
            let recordJson = {
                record: authHelloRecord,
                blobs: [encryptedSecretKey]
            };
            return recordJson;
        }

        /**
         * @brief Creates record with application data.
         *
         * @return object record identifier and blobs encoding application data.
         */
        function createApplicationData(data) {

            // Application data identifier record.
            let applicationDataRecord = {};

            // Blobs encoding application data.
            let blobs = [];

            // Message ID to enable delivery confirmation.
            applicationDataRecord.messageId = data.messageId;

            // Check type of application data and encode appropriately.
            if (data.message instanceof Buffer) {
                // Identify as BLOB in the identifier record.
                applicationDataRecord.blobs = [
                    {
                        length: data.message.length,
                        type: "BLOB"
                    }
                ];
                blobs.push(data.message);
            } else if (data.message instanceof Array) {

                // Create blobs field to store identifying blob details.
                applicationDataRecord.blobs = [];

                // Identify as BLOB or JSON accordingly.
                data.message.forEach(
                    function (thisMessage) {

                        // Check if data is a buffer.
                        if (
                            thisMessage.blob !== undefined &&
                            thisMessage.blob instanceof Buffer
                        ) {
                            blobs.push(thisMessage.blob);
                            applicationDataRecord.blobs.push({
                                id: thisMessage.id,
                                length: thisMessage.blob.length,
                                type: "BLOB"
                            });
                        } else {

                            // Serialize JSON and encode as a blob.
                            let thisBlob = Buffer.from(
                                JSON.stringify(thisMessage)
                            );
                            blobs.push(thisBlob);
                            applicationDataRecord.blobs.push({
                                type: "JSON",
                                length: thisBlob.length
                            });
                        }
                    }
                );
            } else {
                // Serialize JSON and encode as a blob.
                let thisBlob = Buffer.from(JSON.stringify(data.message));
                blobs.push(thisBlob);
                applicationDataRecord.blobs = [{
                    type: "JSON",
                    length: thisBlob.length
                }];
            }

            // Return identifier JSON and associated blobs.
            return {
                record: applicationDataRecord,
                blobs
            };
        }

        /**
         * @brief Creates a confirmation message for a received application
         *        data. The message contains the following attributes:
         *        result    - flag indicating if message is confirmed or pending
         *        messageId - message id being confirmed
         *
         * @param messageData object containing confirmation details:
         *                    messageId - id of message being confirmed
         *                    result    - true if confirmed, false if pending
         *
         * @return object application data confirmation record.
         */
        function createApplicationDataConfirmation(messageData) {
            logger.trace('Creating Applcation data confirmation');

            let confirmationRecord = {
                result: messageData.confirm,
                messageId: messageData.messageId,
                blobs: []
            };

            // Return application data confirmation record.
            let recordJson = {
                record: confirmationRecord,
                blobs: []
            };

            return recordJson;
        }


        /**
         * @brief This is the auth hello message handler. When this type of
         *        message is received from the party, the initator parses it
         *        to get the session secret. It updates the session and the
         *        connection state so as to use the new secret for all further
         *        communication, thus authenticating itself.
         *
         * @param parsedRecord the parsed auth hello record object.
         *
         * @return none
         */
        function handleAuthHello(parsedRecord) {
            logger.trace("Handling auth hello.");

            // Parse the auth hello message.
            let msg = parseHelloMessage(parsedRecord);
            if (fail === true) {
                return;
            }

            // Ensure party seif version is compatible.
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

            /* Change the expect state to application data as the connection
             * has now been established.
             */
            expect = expectType.listenerAppData;
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

                // Connection is now complete.
                isSeifConnected = true;

                connected();

                // Continue to process the next record.
                process();
            });

            process();
        }


        /**
         * @brief This is the hello message handler. When this type of
         *        message is received from the initiator then the listening
         *        party parses the hello message to get the party/connection
         *        info and processes the connection. If the party is able to
         *        decrypt the secret using its private key, the party will
         *        generate a new secret and send an auth hello message back to
         *        the initiator.
         *
         * @param parsedRecord the parsed hello record object.
         *
         * @return none
         */
        function handleHello(parsedRecord) {
            logger.trace('Handling initiator hello');

            /**
             * @brief Function to be called after the received record has been
             *        parsed and the party is ready to process it.
             *
             * @param msg data obtained from received record
             *
             * @return none
             */
            function sendDone(msg) {
                // Ensure party version is compatible.
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

                    // Handshake complete.
                    handshaking = false;

                    // The two ends are now connected.
                    isSeifConnected = true;

                    // Invoking the provided connection handler.
                    connected(msg.connectionInfo);

                    // Continue to process the next record.
                    process();
                }


                /**
                 * @brief Function to be called after the record has been
                 *        processed and the next message to be sent is an
                 *        auth hello message. The current write state is
                 *        updated to use the secret key provided in the
                 *        hello message and auth hello record is queued. All
                 *        further read/writes will use the new secret
                 *        generated by the listening party.
                 *
                 * @param callback function to be invoked after message is
                 *                 queued: 'function callback()'
                 *
                 * @return none
                 */
                function sendAuthHello(callback) {
                    // Use the initiator secret to write this message.
                    state.current.write = state.pending.write;

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

                // Update session object.
                session.sp = {};

                // The next message expected will be application data.
                expect = expectType.initiatorAppData;

                // New session. Create new security params.
                session.resuming = false;
                createSecurityParameters(msg);

                /* Create and update the connection state to use the secret
                 * key provided in the hello message.
                 */
                state.pending = createConnectionState();
                updateConnectionState(state.pending, function () {
                    // Connection now open.
                    open = true;

                    // This is a new session.
                    if (fail === true) {
                        return;
                    }

                    // Initiator authentication is required.
                    sendAuthHello(authenticationDone);
                });

            }

            let msg = parseHelloMessage(parsedRecord);
            if (fail) {
                return;
            }

            // Ready to process the received message.
            sendDone(msg);

        }


        /**
         * @brief This is the handshake message handler. The party looks up the
         *        appropriate state table with the handshake record type to
         *        determine how to handle the received record. If the record is
         *        not of an expected type, the connection is closed.
         *
         * @return none
         */
        function handleHandshake() {

            let type = record.data.recordType;

            logger.trace({party, expect, type}, "handle handshake");

            // handle expected message
            if (hsTable[party][expect][type] !== undefined) {
                // Initialize session
                if (
                    party === connectionEnd.listener &&
                    open === false &&
                    fail === false
                ) {
                    handshaking = true;
                    session = {};
                }

                // handle specific handshake type record
                hsTable[party][expect][type]();
            } else {
                // Unexpected record received.
                handleUnexpected();
            }
        }

        /**
         * @brief This is a helper function that parses application data blobs.
         *
         * @param object blobMeta contains details of the blob to be parsed.
         * @param number blobIdx is the index into that array that contians
         *        blob data described by blobMeta.
         *
         * @return object parsed blob, either a JSON or buffer encoded as an
         *         object with fields id (buffer identifier) and blob (buffer).
         */
        function processBlob(blobMeta, blobIdx) {

            // Access blob from record object.
            let thisBlob = record.blobs[blobIdx];

            // Check if blob contains a buffer.
            if (blobMeta.type === "BLOB") {
                // encode buffer.
                return {
                    id: blobMeta.id,
                    blob: thisBlob
                };
            }

            // Check if blob contains a JSON object.
            if (blobMeta.type === "JSON") {
                return JSON.parse(thisBlob.toString());
            }

            logger.error("Unknown message format");

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

            // Container of parsed blobs.
            let message;

            /* If data blob contains a JSON message, parse it, otherwise
             * create an object to encode the blob.
             */

            // check if there are one or more blobs for the message.
            if (record.blobs.length === 1) {

                let blobMeta = record.data.blobs[0];

                if (blobMeta.type === "JSON") {
                    message = processBlob(blobMeta, 0);
                } else if (blobMeta.type === "BLOB") {
                    message = processBlob(blobMeta, 0).blob;
                }
            } else {
                // parse each blob recieved on the message.
                message = [];
                record.data.blobs.forEach(
                    function (thisBlobMeta, idx) {
                        message.push(
                            processBlob(
                                thisBlobMeta,
                                idx
                            )
                        );
                    }
                );
            }

            // Call the dataReady handler provided.
            dataReady({
                messageId: record.data.messageId,
                message
            });

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
            logger.trace("Handling redirect from party.");
            let response = record.data;

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

            receivedMessageConfirmation(record.data);

            // Continue to process the next record.
            process();
        }


        /**
         * @brief This is the handler for seif errors received from the other
         *        end point of the connection. This currently happens only in
         *        the case of seif version mismatch.
         *
         * @return none
         */
        function handleSeifError() {
            return error({
                message: record.data.message,
                alert: record.data.alert,
                inform: true
            });
        }


        /**
         * @brief Performs a handshake using the seif Handshake Protocol,
         *        as a initiator. We create a hello message which will contain
         *        a newly generated secret key encrypted using the party's
         *        public key and other party/connection info.
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
            function startSession() {
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

                    // Send initiator hello message.
                    queue(createRecord({
                        type: contentType.handshake,
                        data: createHello()
                    }));
                    flush();
                });

            }

            // Error to call this in listening mode.
            if (party !== connectionEnd.initiator) {
                error({
                    message: 'Cannot initiate handshake as a listener.',
                    fatal: false
                });
            } else if (handshaking === true) {
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

                logger.trace({hostInfo}, "Host info of party.");

                // Start new session if we are retrying after a handshake fails.
                startSession();
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
                data: createApplicationData(data)
            }));
            flush();
        }


        /**
         * @brief Packages the redirect request into a seif record. This happens
         *        when party prepares to send redirect info to the initiator
         *        to inform it to connect to another party.
         *
         * @param data the redirect data to be sent
         *
         * @return none
         */
        function prepareRedirectRequest(data) {
            logger.trace("Preparing to send redirect request.");
            // adding empty blobs field to data
            data.blobs = [];
            queue(createRecord({
                type: contentType.redirect,
                data: {
                    record: data,
                    blobs: []
                }
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
                = ctTable[connectionEnd.initiator][expectType.listenerHello];
        let initatorFinishedTable
                = ctTable[connectionEnd.initiator][expectType.listenerFinished];
        let initatorAppDataTable
                = ctTable[connectionEnd.initiator][expectType.listenerAppData];

        initatorHelloTable[contentType.handshake] = handleHandshake;
        initatorHelloTable[contentType.redirect] = handleRedirect;
        initatorHelloTable[contentType.seifError] = handleSeifError;

        initatorFinishedTable[contentType.handshake] = handleHandshake;
        initatorFinishedTable[contentType.redirect] = handleRedirect;
        initatorFinishedTable[contentType.seifError] = handleSeifError;

        initatorAppDataTable[contentType.handshake] = handleHandshake;
        initatorAppDataTable[contentType.applicationData] =
                handleApplicationData;
        initatorAppDataTable[contentType.redirect] = handleRedirect;
        initatorAppDataTable[contentType.applicationDataConfirm] =
                handleApplicationDataConfirmation;


        let listenerHelloTable =
                ctTable[connectionEnd.listener][expectType.initiatorHello];
        let listenerAppDataTable =
                ctTable[connectionEnd.listener][expectType.initiatorAppData];

        listenerHelloTable[contentType.handshake] = handleHandshake;

        listenerAppDataTable[contentType.handshake] = handleHandshake;
        listenerAppDataTable[contentType.applicationData] =
                handleApplicationData;
        listenerAppDataTable[contentType.applicationDataConfirm] =
                handleApplicationDataConfirmation;

        // map initiator current expect state and handshake type to function

        let initiatorHsHelloTable =
                hsTable[connectionEnd.initiator][expectType.listenerHello];
        let initiatorHsFinishedTable =
                hsTable[connectionEnd.initiator][expectType.listenerFinished];

        initiatorHsHelloTable[handshakeType.authHello] = handleAuthHello;

        initiatorHsFinishedTable[handshakeType.authHello] = handleAuthHello;

        let listenerHsHelloTable =
                hsTable[connectionEnd.listener][expectType.initiatorHello];

        listenerHsHelloTable[handshakeType.hello] = handleHello;

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
