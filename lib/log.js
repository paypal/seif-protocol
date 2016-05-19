/** @file log.js
 *  @brief File containing the implementation of the logger.
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
 *        logger object.
 *
 * @param options options to initialize the logger object
 *
 * @return object bunyan logger object
 */
function initialize() {
    'use strict';

    let bunyan = require("bunyan");

    // main logger object
    let logger;
    let children = [];

    function create() {

        /* If the logger has already been initalized then the object is returned
         * immediately.
         */
        if (logger) {
            return logger;
        }

        logger = bunyan.createLogger({
            name: "seif",
            src: true,
            streams: [
                {
                    level: "info",
                    stream: process.stdout,
                    name: "infolog"
                }
            ]
        });

        return logger;
    }



    function updateLogger(currentLogger, newLogger) {
        currentLogger.level(newLogger.level());
        currentLogger.streams = [];
        newLogger.streams.forEach(function (stream) {
            let path, newStream;
            if (stream.path !== undefined) {
                path = stream.path;
            } else {
                newStream = stream.stream;
            }
            currentLogger.addStream({
                level: stream.level,
                stream: newStream,
                path,
                type: stream.type
            });
        });
    }


    function update(newLogger) {
        if (newLogger === undefined) {
            return;
        }

        updateLogger(logger, newLogger);
        children.forEach(function (child) {
            updateLogger(child, newLogger);
        });
    }


    function child(options) {
        if (logger === undefined) {
            logger = create();
        }

        let newChild = logger.child(options);

        children.push(newChild);

        return newChild;
    }

    return Object.freeze({
        create,
        update,
        child
    });
}

module.exports = initialize();


