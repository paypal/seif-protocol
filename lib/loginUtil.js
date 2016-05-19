/** @file loginUtil.js
 *  @brief File containing the functions responsible for logging in a party and
 *         registering a party.
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

    let fs = require('fs');
    let path = require("path");
    let prompt = require('prompt');
    let createRNG = require('./seif/isaacrng');
    let seifnode = require("seifnode");

    let loggerGenerator = require("./log");
    let logger = loggerGenerator.child({componentName: "LOGIN_UTIL"});


    /**
     * @brief Main function executed when the module is required to create the
     *        login utility object.
     *
     * @param args options to initialize the login utility object
     *
     * @return object login utility object
     */
    function loginUtil(args) {

        // Protocol data folder to store registration/login encrypted state
        let folder = args.folder || __dirname;
        folder += "/";

        function deleteFolderRecursive(path, callback) {
            fs.readdir(path, function (err, files) {
                if (err !== undefined && err !== null) {
                    // Pass the error on to callback
                    callback(err);
                    return;
                }

                let wait = files.length;
                let count = 0;

                function folderDone(err) {
                    count = count + 1;
                    // If we cleaned out all the files, continue
                    if (count >= wait || (err !== undefined && err !== null)) {
                        fs.rmdir(path, callback);
                    }
                }

                // Empty directory to bail early
                if (wait === 0) {
                    folderDone();
                    return;
                }

                // Remove one or more trailing slash to keep from doubling up
                path = path.replace(/\/+$/, "");
                files.forEach(function (file) {
                    let curPath = path + "/" + file;
                    fs.lstat(curPath, function (err, stats) {
                        if (err !== undefined && err !== null) {
                            callback(err);
                            return;
                        }
                        if (stats.isDirectory()) {
                            deleteFolderRecursive(curPath, folderDone);
                        } else {
                            fs.unlink(curPath, folderDone);
                        }
                    });
                });
            });
        }


        /**
         * @brief Registers a new entiry based on the given data and invoke the
         *        given callback when the user has been registered.
         *
         * As part of the registration process, the given password is hashed and
         * used to protect the public/private keys generated after initializing
         * the ECCISAAC object. Next, the RNG is initialized and the state file
         * is encrypted with the hash of the generated private key. At this
         * point the process is complete and the given callback is invoked.
         *
         * @param data options associated with the user to be registered
         *        (username, password)
         * @param callback function to be invoked when the registration process
         *        is complete
         *
         * @return None
         */
        function registerUser(data, callback) {

            // Associating the user with his/her own folder.
            let userFolder = folder + data.username + "/";
            if (!path.isAbsolute(userFolder)) {
                userFolder = path.resolve(userFolder) + "/";
            }

            // Initializing Cryptopp SHA3-256 hasher object.
            let hasher = seifnode.SEIFSHA3();

            // Hash the given password.
            let hash = hasher.hash(data.password);

            /* Initialize the ECCISAAC object using the hash and folder and use
             * it to generate the public/private key pair.
             */
            let ecc = new seifnode.ECCISAAC(hash, userFolder);
            let keys = ecc.generateKeys();

            // Return object with error as no keys were generated
            if (keys === undefined) {
                logger.error("Keys generation failure.");
                callback(
                    {
                        code: -1,
                        message: "Failed to Create New User"
                    }
                );
                return;
            }

            // Hash the generated private key.
            let dataKey = hasher.hash(keys.dec);

            let rngFileName = userFolder + data.username + "rng";

            // Prepare seifnode random generator.
            let generator = new seifnode.RNG();


            try {

                generator.initialize(dataKey, rngFileName);
                generator.destroy();

            } catch (ex) {

                logger.trace({ex}, "Could not initialize rng.");

                callback(
                    {
                        code: -1,
                        message: "Failed to Create New User"
                    }
                );
            }

            callback(undefined);
            return;

        }


        /**
         * @brief Function to process login of an existing party based on the
         *        given data and invoke the given callback when the user has
         *        been logged in.
         *
         * As part of the login process, the given password is hashed and
         * used to initialize the ECCISAAC object and decrypt and load the
         * public/private key pair. Next, the RNG is initialized by loading the
         * state decrypted using the hash of the private key. At this point the
         * process is complete and the given callback is invoked.
         *
         * @param data options associated with the user to be logged in
         *        (username, password)
         * @param callback function to be invoked when the login process is
         *        complete
         *
         * @return None
         */
        function loginUser(data, callback) {

            // Getting the associated user folder
            let userFolder = folder + data.username + "/";
            if (!path.isAbsolute(userFolder)) {
                userFolder = path.resolve(userFolder) + "/";
            }

            // Initializing Cryptopp SHA3-256 hasher object.
            let hasher = seifnode.SEIFSHA3();

            // Hash the given password.
            let hash = hasher.hash(data.password);

            /* Initialize the ECCISAAC object using the hash and folder and use
             * it to load the public/private key pair from the disk
             */
            let ecc = seifnode.ECCISAAC(hash, userFolder);
            ecc.loadKeys(function (status, keys) {
                logger.trace({status, keys}, "Loading keys done");

                // Checking for errors while logging in.
                if (
                    status !== undefined
                    && status.code !== 0
                    && status.code !== -2
                ) {

                    // Login error as registration process was interrupted.
                    logger.error({status}, "Incomplete registration.");
                    callback(
                        undefined,
                        {
                            code: -2,
                            message: "Incomplete registration."
                        }
                    );
                    return;
                }

                if (keys === undefined) {

                    // Error logging in due to an incorrect password.
                    logger.error({status}, "Incorrect Password.");
                    callback(
                        undefined,
                        {
                            code: -1,
                            message: "Incorrect Password."
                        }
                    );
                    return;
                }

                // Hash the loaded private key.
                let dataKey = hasher.hash(keys.dec);

                let rngFileName = userFolder + data.username + "rng";

                /* Initialize the RNG by decrypting the state with the hash of
                 * the private key
                 */
                createRNG(dataKey, rngFileName, function (rng) {
                    if (rng === undefined) {
                        logger.error("RNG failure.");
                        callback(
                            undefined,
                            {
                                code: -2,
                                message: "Failed to Load RNG"
                            }
                        );
                        return;
                    }

                    // Login process done. Invoke the given callback with details.
                    callback(
                        {
                            keys: keys,
                            loginDetails: {
                                username: data.username,
                                passwordHash: hash
                            },
                            seifECC: ecc,
                            seifRNG: rng
                        },
                        undefined
                    );
                });
            });

            return;
        }

        /**
         * @brief Function to process login based on the given data and invoke
         *        the given callback when the user has been logged in.
         *
         * If the party does not have an associated folder, the party is
         * registered. Otherwise, an attempt is made at party login. If this too
         * fails due to some reason, then the party is registered again.
         *
         * @param data options associated with the user to be logged in
         *        (username, password)
         * @param callback function to be invoked when the login process is
         *        complete
         *
         * @return None
         */
        function login(data, callback) {

            let userFolder = folder + data.username;

            // Check if folder associated with the party exists.
            fs.access(userFolder, function (error) {

                if (error !== undefined && error !== null) {

                    logger.trace(
                        {userFolder},
                        "Folder does not exist for this party."
                    );

                    logger.error(error);
                    callback(error);

                } else {

                    logger.trace(
                        {userFolder},
                        "Folder exists for this party. Logging in."
                    );

                    // Attempt at party login.

                    loginUser(data, function (partyDetails, error) {

                        // If there is any error due to incomplete registration.

                        if (error !== undefined && error.code === -2) {

                            logger.error({statusMessage: error.message});
                            callback(undefined, error);
                            return;
                        }

                        // Invoke the callback with the status.
                        callback(partyDetails, error);
                    });
                }
            });
        }


        /**
         * @brief Load the public/private key pair of the given party. If no
         *        keys are present or there is a decryption error then the keys
         *        are regenerated.
         *
         * @param data options associated with the party
         *        (username, password)
         * @param callback function to be invoked when the registration process
         *        is complete
         *
         * @return None
         */
        function getKeys(data, callback) {
            let userFolder = folder + data.username + "/";

            // Initialize the SHA3-256 hasher object and hashing the password.
            let hasher = seifnode.SEIFSHA3();
            let hash = hasher.hash(data.password);

            // Create ECCISAAC object and use it to load the keys from disk.
            let ecc = new seifnode.ECCISAAC(hash, userFolder);
            ecc.loadKeys(function (status, keys) {
                if (status.code !== 0) {

                    // Invoke callback with error status.
                    callback(status);

                } else {

                    // Invoke callback once the keys have been loaded.
                    callback(undefined, keys);
                }
            });

        }


        /**
         * @brief Obtain the party login details from the command prompt.
         *
         * @param callback function to be invoked when the details are obtained.
         *
         * @return None
         */
        function requestPartyLoginDetails(callback) {

            // Command prompt input properties
            let properties = [
                {
                    name: 'username',
                    validator: /^[a-zA-Z\s\-]+$/,
                    warning: 'Username must be only letters, spaces, or dashes'
                },
                {
                    name: 'password',
                    hidden: true
                }
            ];

            prompt.start();

            // Get the required details and invoke the callback
            prompt.get(properties, function (err, result) {

                if (err !== null) {
                    logger.error(err);
                    return;
                }

                logger.trace('Command-line input received:');
                logger.trace('  Username: ' + result.username);
                logger.trace('  Password: ' + result.password);

                // Initialize SHA3-256 hasher object.
                let hasher = seifnode.SEIFSHA3();

                // Hash the given password and get the associated party folder.
                result.passwordHash = hasher.hash(result.password);
                result.folder = folder + result.username + "/";

                // Invoke the callback with above details.
                callback(result);

            });
        }


        function registerParty(callback) {

            requestPartyLoginDetails(function (data) {

                let userFolder = data.folder;

                // Delete existing Party details to register afresh.

                deleteFolderRecursive(userFolder, function (error) {
                    if (error !== undefined && error !== null) {
                        if (error.code !== 'ENOENT') {
                            return callback(error);
                        }
                    }

                    // Create the directory
                    fs.mkdir(userFolder, function (error) {

                        if (error !== undefined && error !== null) {
                            return callback(error);
                        }

                    });

                    // Register the party.
                    registerUser(data, function (error) {
                        return callback(error);
                    });

                });

            });
        }


        // Returns the login utility object.
        return Object.freeze({
            login,
            getKeys,
            registerParty
        });
    }

    return loginUtil;
}

module.exports = initialize();