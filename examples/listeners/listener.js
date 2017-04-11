/*jslint node: true */
// jshint esversion: 6

function run(hostCache) {
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

    function runapp(entity, password) {

        seif.initializeEntity({
            entity,
            password,
            hostCache
        }, function (partyGenerator, error) {

            if (error !== undefined) {
                console.log("Error creating party.");
                process.exit(1);
            }

            let party = partyGenerator();

            process.on(
                'exit',
                function () {
                    party.destroy();
                }
            );

            let thisPartyInfo = {
                connectAddress: {
                    host: "::ffff:127.0.0.1",
                    port: 8040
                },
                connectPublicKey  : party.properties().publicKey
            };

            hostCache.write(entity, thisPartyInfo);

            process.on('exit', function () {party.destroy();});
            process.on('SIGINT', function() {process.exit(1);});

            party.listen(8040, function (connection) {
                console.log("Received connection");
                console.log(connection.seifConnectionProperties());
                console.log("Redirecting this Connection");
                connection.temporaryRedirect({
                    petName: "PayPalRedirect",
                    redirectContext: {
                        msg: "Redirect Context",
                        origin: party.properties().publicKey
                    }
                });

                connection.seifMessageListener().on("message", function(request) {
                    console.log(request);

                    connection.send({message: request}, function(error) {
                        console.log("Recieved Confirmation!!!");
                    });
                });
            });
        });

    }

    function onErr(err) {
        console.log(err);
        return 1;
    }

    prompt.start();

    prompt.get(properties, function (err, result) {
        if (err) {
            return onErr(err);
        }

        console.log('Command-line input received.');
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
                    if (error === null) {
                        error = undefined;
                    }
                    callback(JSON.stringify(val), error);
                }
            );
        }
    };

}();

run(hostCache);
