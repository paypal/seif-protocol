/*jslint node: true */
// jshint esversion: 6
function runClient(hostCache) {
    'use strict';

    let seif = require('seif-protocol')({folder: __dirname});
    let prompt = require('prompt');

    let properties = [
        {
            name: 'entity',
            validator: /^[a-zA-Z\s\-]+$/,
            warning: 'Entity must be only letters, spaces, or dashes'
        },
        {
            name: 'password',
            hidden: true
        }
    ];

    function onErr(err) {
        console.log(err);
        return 1;
    }

    function runapp(entity, password) {
        seif.initializeEntity({
            entity: entity,
            password,
            hostCache
        }, function (partyGenerator, error) {

            if (error !== undefined) {
                console.log("quitting");
                console.log(error);
                process.exit(1);
            }

            let party = partyGenerator();

            let connectRequest = {
                petName: "PayPal",
                connectionInfo: {
                    connectionContext: "Optional Context"
                }
            };

            party.connect(connectRequest, function (error) {

                if (error !== undefined) {
                    console.log(error);
                    console.log("quitting");
                    process.exit(1);
                }

                process.on(
                    'exit',
                    function () {
                        party.destroy();
                    }
                );

                let request = {
                    message: [
                        {
                            key: "JSON"
                        },
                        {
                            id: "buff",
                            blob: new Buffer([64, 65, 66, 67, 68, 69, 70])
                        }
                    ]
                };

                party.seifEventEmitter().on("message", function (response) {
                    console.log("Message event");
                    console.log(response);
                });

                party.seifEventEmitter().on("error", function (error) {
                    console.log("Error event");
                    console.log(error);

                });

                party.seifEventEmitter().on("close", function (error) {
                    console.log("Close event");
                    console.log(error);
                });

                party.send(request, function (error) {
                    if (error !== undefined) {
                        console.log(error);
                        return;
                    }
                    console.log("Success!!");
                });

            });

        });
    }

    prompt.start();

    prompt.get(properties, function (err, result) {
        if (err) {
            return onErr(err);
        }

        console.log('Command-line input received:');

        runapp(result.entity, result.password);

    });
}

let hostCache = function createHostCache() {
    'use strict';

    let jsonfile = require('jsonfile');

    return {
        write: function (key, value) {
            jsonfile.writeFile('../' + key, value);
        },
        read: function (key, callback) {
            jsonfile.readFile(
                '../' + key,
                function (error, val) {
                    console.log(val);
                    if (error === null) {
                        error = undefined;
                    }
                    callback(JSON.stringify(val), error);
                }
            );
        }
    };

}();

runClient(hostCache);
