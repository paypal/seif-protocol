/** @file secnet.js
 *  @brief Main file invoked when the module is required. This file contains
 *         functions responsible for initialization.
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

    let loggerGenerator = require("./log");
    let defaultLogger = loggerGenerator.create();

    let getConfig = require('./config');
    let seifPartyGenerator = require('./seifParty');

    let loginUtil = require('./loginUtil');

    /**
     * @brief Main function executed when the module is required to create the
     *        protocol object.
     *
     * @param properties options to initialize the protocol object
     *
     * @return function function to create a seif party
     */
    function initializeProtocol(properties) {

        // Initializes the logger level based on the given options.
        if (properties !== undefined && properties.logLevel !== undefined) {
            defaultLogger.level(properties.logLevel);
        }

        let config = getConfig(properties);

        defaultLogger.info(
            {
                currentLevel: defaultLogger.level(),
                config
            },
            'Default log level'
        );

        // Returns the function to create/register an external seif party.
        return Object.freeze({
            initializeParty: seifPartyGenerator(false),
            registerParty: loginUtil(properties).registerParty
        });

    }

    return initializeProtocol;
}


module.exports = initialize();


