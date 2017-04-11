/*jslint node: true */
// jshint esversion: 6

function initialize() {
    'use strict';
    const prompt = require('prompt');
    prompt.start();
    prompt.get(
        [
            {
                name: 'dir',
                description: 'Enter location to save entity credentials'
            },
            {
                name: 'entity',
                validator: /^[a-zA-Z\s\-]+$/,
                warning: 'Entity must be only letters, spaces, or dashes'
            },
            {
                name: 'password',
                hidden: true
            }
        ],
        function (err, results) {

            if (err !== null) {
                console.log("Undefined Input.");
                return;
            }

            const seif = require('seif-protocol')({folder: results.dir});

            seif.createEntityIdentity(
                results,
                function (error) {
                    if (error !== undefined) {
                        console.log(error);
                    }
                }
            );
        }
    );
}

initialize();
