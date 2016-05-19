/*jslint node: true */

function initialize() {
    'use strict';
    const prompt = require('prompt');

    prompt.start();
    prompt.get(
        [
            {
                name: 'dir',
                description: 'Enter location to save party credentials'
            }
        ],
        function (err, results) {

            if (err !== null) {
                console.log("Undefined Input.");
                return;
            }

            const seif = require('seif')({folder: results.dir});
            seif.registerParty(function (error) {
                if (error !== undefined) {
                    console.log(error);
                }
            });
        }
    );
}

initialize();