/** @file entityManagementUtil.js
 *  @brief File containing the functions responsible for authenticating an
 *         entity or creating an entity's identity.
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

    let fs = require('fs');
    let path = require("path");
    let createRNG = require('./seif/isaacrng');
    let seifnode = require("seifnode");

    let loggerGenerator = require("./log");
    let logger = loggerGenerator.child({componentName: "AUTH_UTIL"});


    /**
     * @brief Main function executed when the module is required to create the
     *        entity management utility object.
     *
     * @param args options to initialize the entity management utility object
     *
     * @return object entity management utility object
     */
    function entityManagementUtil(args) {

        // Protocol data folder to store entity's identity encrypted state
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
         * @brief Creates and secures a new entity identity using the data
         *        provided and invokes the given callback. The entity
         *        is uniquely identified by its public/private key pair and RNG
         *        state used to generate session secrets.
         *
         * In an effort to secure the identity, the given password is hashed and
         * used to protect the public/private keys generated after initializing
         * the ECCISAAC object. Next, the RNG is initialized and the state file
         * is encrypted with the hash of the generated private key. At this
         * point the process is complete and the given callback is invoked.
         *
         * @param data options associated with the entity to be created
         *        (entity, password)
         * @param callback function to be invoked when the registration process
         *        is complete
         *
         * @return None
         */
        function createEntityIdentity(data, callback) {

            // Associating the entity with a folder.
            let entityFolder = folder + data.entity + "/";
            if (!path.isAbsolute(entityFolder)) {
                entityFolder = path.resolve(entityFolder) + "/";
            }

            // Delete existing Party details to register afresh.

            deleteFolderRecursive(
                entityFolder,
                function (error) {
                    if (error !== undefined && error !== null) {
                        if (error.code !== 'ENOENT') {
                            return callback(error);
                        }
                    }

                    // Create the directory
                    fs.mkdir(entityFolder, function (error) {

                        if (error !== undefined && error !== null) {
                            return callback(error);
                        }

                    });

                    // Initializing Cryptopp SHA3-256 hasher object.
                    let hasher = seifnode.SEIFSHA3();

                    // Hash the given password.
                    let hash = hasher.hash(data.password);

                    /* Initialize the ECCISAAC object using the hash and folder and use
                     * it to generate the public/private key pair.
                     */
                    let ecc = new seifnode.ECCISAAC(hash, entityFolder);

                    logger.info("Entropy strength: " + ecc.entropyStrength());

                    if (ecc.entropyStrength() === "WEAK") {
                        logger.error("[WARNING] USING LOW ENTROPY STRENGTH.");
                    }

                    let keys = ecc.generateKeys();

                    // Return object with error as no keys were generated
                    if (keys === undefined) {
                        logger.error("Keys generation failure.");
                        callback(
                            {
                                code: -1,
                                message: "Failed to Create Identity for this Entity."
                            }
                        );
                        return;
                    }

                    // Hash the generated private key.
                    let dataKey = hasher.hash(keys.dec);

                    let rngFileName = entityFolder + data.entity + "rng";

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
                                message: "Failed to Create Identity for this Entity."
                            }
                        );
                    }

                    return callback(undefined);
                }
            );
        }


        /**
         * @brief Function to process authentication of an existing entity using
         *        given data and invoke the given callback with the entity's
         *        identity once it has been authenticated.
         *
         * As part of the auth process, the given password is hashed and
         * used to initialize the ECCISAAC object and decrypt and load the
         * public/private key pair. Next, the RNG is initialized by loading the
         * state decrypted using the hash of the private key. At this point the
         * process is complete and the given callback is invoked.
         *
         * @param data options associated with the entity to be authenticated
         *        (entity, password)
         * @param callback function to be invoked when the auth process is
         *        complete
         *
         * @return None
         */
        function authenticateAndGetEntityIdentity(data, callback) {

            // Getting the associated entity folder
            let entityFolder = folder + data.entity + "/";
            if (!path.isAbsolute(entityFolder)) {
                entityFolder = path.resolve(entityFolder) + "/";
            }

            // Initializing Cryptopp SHA3-256 hasher object.
            let hasher = seifnode.SEIFSHA3();

            // Hash the given password.
            let hash = hasher.hash(data.password);

            /* Initialize the ECCISAAC object using the hash and folder and use
             * it to load the public/private key pair from the disk
             */
            let ecc = seifnode.ECCISAAC(hash, entityFolder);
            ecc.loadKeys(function (status, keys) {
                logger.trace({status, keys}, "Loading keys done");

                // Checking for errors while authenticating.
                if (
                    status !== undefined &&
                    status.code !== 0 &&
                    status.code !== -2
                ) {

                    // Error as enitity identity is incomplete.
                    logger.error({status}, "Incomplete identity.");
                    callback(
                        undefined,
                        {
                            code: -2,
                            message: "Incomplete identity."
                        }
                    );
                    return;
                }

                if (keys === undefined) {

                    // Error authenticating in due to an incorrect password.
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

                let rngFileName = entityFolder + data.entity + "rng";

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

                    // Authentication done. Invoke the given callback with
                    // with entity identity.
                    callback(
                        {
                            keys: keys,
                            entityDetails: {
                                entity: data.entity,
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
         * @brief Function to retrieve entity identity using given data and
         *        invoke the provided callback on entity authentication.
         *
         * @param data options associated with the entity to be authenticated
         *        (entity, password).
         * @param callback function to be invoked when authentication is
         *        complete.
         *
         * @return None
         */
        function retrieveEntityIdentity(data, callback) {

            let entityFolder = folder + data.entity;

            // Check if folder associated with the entity exists.
            fs.access(entityFolder, function (error) {

                if (error !== undefined && error !== null) {

                    logger.trace(
                        {entityFolder},
                        "Folder does not exist for this entity."
                    );

                    logger.error(error);
                    callback(error);

                } else {

                    logger.trace(
                        {entityFolder},
                        "Folder exists for this entity. Retrieving identity."
                    );

                    // Attempt at entity authentication.
                    authenticateAndGetEntityIdentity(
                        data,
                        function (entityIdentity, error) {

                            // If there is any error due to incomplete identity.
                            if (error !== undefined && error.code === -2) {

                                logger.error({statusMessage: error.message});
                                callback(undefined, error);
                                return;
                            }

                            // Invoke the callback with the status.
                            callback(entityIdentity, error);
                        }
                    );
                }
            });
        }


        /**
         * @brief Load the public/private key pair of the given entity.
         *
         * @param data options associated with the entity
         *        (entity, password)
         * @param callback function to be invoked with the keys
         *
         * @return None
         */
        function getKeys(data, callback) {
            let entityFolder = folder + data.entity + "/";

            // Initialize the SHA3-256 hasher object and hashing the password.
            let hasher = seifnode.SEIFSHA3();
            let hash = hasher.hash(data.password);

            // Create ECCISAAC object and use it to load the keys from disk.
            let ecc = new seifnode.ECCISAAC(hash, entityFolder);
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


        // Returns the entity management utility object.
        return Object.freeze({
            retrieveEntityIdentity,
            getKeys,
            createEntityIdentity
        });
    }

    return entityManagementUtil;
}

module.exports = initialize();
