'use strict';

let seif = require('seif-protocol')({folder: __dirname});
let prompt = require('prompt');
let redis = require('redis');
let createCache = require('./cache');
let client = redis.createClient(6379, '127.0.0.1', {return_buffers:true});
let hostCache = createCache(client);
let sessionCache = createCache(redis.createClient(6389));
console.log(sessionCache);

var properties = [
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

prompt.get(properties, function (err, result) {
  if (err) { return onErr(err); }
  console.log('Command-line input received:');
  console.log('  Username: ' + result.username);
  console.log('  Password: ' + result.password);

  runapp(result.username, result.password);

});

function onErr(err) {
  console.log(err);
  return 1;
}

function lookupUserId(userId, callback) {
    hostCache.read(userId, function (response, error) {
        callback(JSON.parse(response), error);
    });
}


function runapp(username, password) {
    let userId = username + "listener0123456789";
    seif.initializeParty({
        username, 
        password,
        hostCache,
        sessionCache,
        userId
    }, function (party, error) {
        if (error !== undefined) {
          console.log("Error creating party.");
          process.exit(1);
        }

        hostCache.write(userId, JSON.stringify({publicKey: party.properties().publicKey}));

        process.on(
          'exit',
          function () {
            party.destroy();
          }
        );

        var serverData = {
            connectAddress: {
                host: "::ffff:127.0.0.1"
              , port: 8040
            }
            , connectPublicKey  : party.properties().publicKey
            , initiatorAuthNeeded: false
        };
        client.set(username, JSON.stringify(serverData), redis.print);
        process.on('exit', function () {party.destroy()});
        process.on('SIGINT', function() {process.exit(1)});
        let count = 0;

        party.listen(8040, {lookupUserId}, function (connection) {
            console.log("Received connection");
            console.log(connection);
            console.log(connection.initiator());
            connection.temporaryRedirect({
                petName: "harchua",
            });
            // connection.end();
            // connection.seifMessageListener().on("message", function(request, requestor) {
            //     console.log("SENDER TO LISTENER");
            //     console.log(request);
            //     console.log(requestor);
            //     console.log(request.startsWith("GET"));
            //     if (request.startsWith("GET") === true) {
            //         count++;
            //         connection.sendMessage("DONE" + request, function(error) {
            //             console.log("CONFIRMATION!!!!");
            //         });
            //     }
            // });
        });
    });

}
