seif
====

Node.js Implementation of the Seif protocol

Getting Started
===============

From your project directory, run (see below for requirements):

```
$ npm install seif
```

Alternatively, to use the latest development version from Github:

```
$ npm install <git-path>
```

Requirements
============

1. bunyan
2. prompt
3. seifnode (https://github.com/paypal/seifnode)

Examples
========

Please refer to the "examples" directory to see examples of how to use the protocol.

Usage
=====

**Creating a party identity:**

Seif protocol enables communication between seif parties. A seif party is capable of
connecting and communicating with another seif party.

The identity of a seif party is uniquely characterized by its login credentials, i.e., username and password.

Given an username and password, the party is initialized with a ECC-512 (Elliptic curve cryptography) {publickey, privatekey}, making this party uniquely identifiable in the world. The {publickey, privatekey} pair is generated from an entropy pool mined from available external sources, including camera, microphone and the OS.

The party is also associated with a random number generator (ISAAC) which is seeded at this time from available external sources of entropy, including camera, microphone and the OS.

A party can be uniquely created by running:

```
$ node install.js
```

Prompts will be made to aquire location where party details are to be saved and
login credentials, i.e., username and password, to enable instantiation of the same.

**Initializing a party:**

The protocol can be used in node.js just like any other module.

```javascript
let seif = require("seif");
```

To instantiate the protocol interface, the exported function can be used as below:

```javascript
let seif = require("seif");
let seif = seif.initializeProtocol({
    folder: __dirname
});
// Folder is the location with party identifying {publickey, privatekey},
// random number state and other party specific files.
```

The returned "seif" object contains the following functions:

**function initializeParty(details, function callback(party, error){...})**

This function initializes a party from the specifed location using provided
login credentials. This information should be presented to the protocol as an
object which can include optional parameters.

```javascript
seif.initializeParty(
    {
        username,
        password,
        hostCache,
        sessionCache,
        persistentQueue
    },
    function callback(party, error){
        if (error === undefined) {
            console.log("Initialized party successfully.");
        } else {
            console.log("Error initializing party.");
            console.log(error);
        }
    }
);

// 'username'        is the name that identifies the party; it is the name of the
//                   folder location holding party identity. [Required].
//
// 'password'        is the encryption/decryption string enabling access to party
//                   identity. [Required].
//
// 'hostCache'       is a key value store with read, write and clear capabilities. This
//                   cache is used to store/lookup connection specific information such
//                   as publickeys, userid etc. [Optional].
//
// 'sessionCache'    is a key value store with read, write and clear capabilities. This
//                   cache is used to store session specific information with another
//                   party. [Optional].
//
// 'persistentQueue' is a queue with enqueue, dequeue and forEach capabilities. This
//                   queue is used to cache reliable messages until confirmation. The
//                   queue is expected to persist its contents. [Optional].
//
// 'callback'        is a function invoked with an initialized party capable of
//                   connecting, listening and sending messages to other parties. If
//                   initialization fails, error will be populated leaving the party
//                   undefined.
```

**function registerParty(function callback(error){...})**

This function uniquely creates a party identity. Prompts will be made to gather
login credentials. The party identity will be saved at the location indicated while
initializing the protocol.

```javascript
seif.registerParty(function callback(error){
    if (error === undefined) {
        console.log("Party identity created successfully.")
    } else {
        console.log("Error creating party identity.");
        console.log(error);
    }
}
```

**Using a party to communicate with other parties:**

An initialized party is capable of:
#####1. Connecting to another party.
#####2. Listening for connections from other parties.
#####3. Sending messages on a successful connection.

Any number of parties can be instantiated with the same identity. However, a single
instance of a party can either connect to another party or be a listener. In the case
where a party identity needs to communicate with several other parties, a party will
be required to be initialized with the party identity for each such connection.

**party.connect(properties, function connectCallback (error) {...})**

Connects to a listening seif party using seif protocol. Callback is invoked with an error in case the connection is unsuccessful.

```javascript
party.connect(
    {
        petname: "PayPal"
    },
    function connectCallback(error) {
        if (error !== undefined) {
            logger.fatal({error}, "Exiting since connect failed");
            process.exit(1);
        }
    }
);

// properties is a frozen Object (the function freezes it if it isnt already frozen)
//            containing the listening party's details and connection options:
//                   connectAddress: ip-address + port
//                   petName: short name to lookup
//                   connectPublicKey: public-key
//            In the presence of a hostCache, the petname will be looked up.
//            If such a cache isn’t available the connectAddress and connectPublicKey
//            parameters are required.
//
// connectCallback is a function invoked with no error on a successful connection
//                 with the listening party.
```

**party.seifEventEmitter()**

This function returns a reference to the event emitter. This is used by the caller to
handle "message", "reliableMessageConfirmation", "seifError" and "close" events.

"message": This event is emitted when a message is received by the protocol for the
           party.

"reliableMessageConfirmation": This event is emitted when a delivery confirmation is
                               received by the protocol for a reliable message sent by
                               the party.

"seifError": This event is emitted on fatal and non-fatal errors relevant to the party,
             examples may be, lost connection, unable to read/write to caches etc.

"close": This event is emitted on connection close.

```javascript
let seifEventEmitter = party.seifEventEmitter();

seifEventEmitter.on(
    "message",
    function (message) {
        console.log("Received Message...");
        console.log(message);
    }
);

seifEventEmitter.on(
    "reliableMessageConfirmation",
    function (message) {
        console.log("Recieved confirmation for message:");
        console.log(message);
    }
);

seifEventEmitter.on(
    "seifError",
    function (error) {
        console.log("Seif Error!!");
        console.log(error);
    }
);

seifEventEmitter.on(
    "close",
    function (error) {
        if (error === undefined) {
            console.log("Connection closed without errors");
        } else {
            console.log("Connection closed with error");
            console.log(error);
        }
    }
);
```


**party.sendMessage(options, function confirmationCallback(error) {...})**

Sends a message to the connected listening party using the seif protocol.

```javascript
party.sendMessage(
    {
        message: "message"
    },
    function confirmationCallback(error) {
        if (error === undefined) {
            console.log("Message successfully sent.")
        }
    }
);

// options is a frozen object containing message details:
//              message - message to be sent to server
//
// confirmationCallback is a function invoked on receiving delivery confirmation.
//                      error is defined in the case of failure.
```

**party.sendReliableMessage(options)**

Sends a reliable message to the connected listening party using the seif protocol. These type of messages are guaranteed to be sent by the protocol, even if the connection is broken for what ever reason; The message will be sent once a connection is resumed. The
persistence of the message is guaranteed by the persistent queue. Hence, a reliable
message is guaranteed to be sent only if the party has access to a persistent queue.

Delivery of reliable messages are notified on the reliableMessageConfirmation event.

```javascript
party.sendReliable(
    {
        message: "message"
    }
);

// options is a frozen object containing message details:
//              message - message to be sent to server
```

**party.sendUnreliableMessage(options)**

Sends a message to the connected listening party using the seif protocol. These type of messages are not guaranteed to be sent by the protocol, i.e., there isn't a message
delivery confirmation. This can be used for log/status messages etc.

```javascript
party.sendUnreliableMessage(
    {
        message: "message"
    }
);

// options is a frozen object containing message details:
//              message - message to be sent to server
```

**party.listen(port, listenOptions, connectionListener)**

This function enables a party to listen to incomming connections.

```javascript
party.listen(
    port,
    {

    },
    function (connection) {

        // Returns the connecting party's properties.

        let connectionInitiator = connection.initiator();



        // Returns the message event listener.

        let messageListener = connection.seifMessageListener();
        messageListener.on("message", function (message) {
            // Do something with the recieved message.
        });



        // Send a message to the connected party. Callback is invoked with no
        // error on successful delivery.

        let message = {message: "Hello!"};
        connection.send(message, function (error) {
            if (error === undefined) {
                console.log("Sent message successfully");
            }
        });



        // Redirect current session to another listening party.

        // Options can contain a petname to be looked up in the hostCache, or
        // a connect address and a public key.

        let options = {
            petname: "PayPalCheckout"
        };

        connection.temporaryRedirect(options, function (error) {
            if (error === undefined) {
                console.log("Successfully redirected connection.");
            }
        });



        // Redirect current and future sessions to another listening party.

        // Options can contain a petname to be looked up in the hostCache, or
        // a connect address and a public key.

        let options = {
            petname: "PayPalAlternate"
        };

        connection.permanentRedirect(options, function (error) {
            if (error === undefined) {
                console.log("Successfully redirected connection.");
            }
        });

        // On a permanent redirect, the connecting party's hostCache is updated
        // with the redirect connect address and public key.



        // Returns a boolean whether the server is redirecting the connection.

        let isRedirecting = connection.isSeifRedirecting();
        if (isRedirecting === true) {
            console.log("Connection is being redirected.");
        } else if (isRedirecting === false) {
            console.log("Connection is not being redirected.");
        }



        // Returns the connection properties including the connection id, which
        // is a random number identifying the connection. The connection id is
        // part of the session object and hence can enable ways to identify the
        // same connection across redirects.

        let connectionProperties = connection.seifConnectionProperties();
        console.log("Connection ID: " + connectionProperties.connectionId);



        // Returns the connection status.

        let status = connection.isStillAlive();
        if (status === true) {
            console.log("Connection is still alive.");
        } else if (status === false) {
            console.log("Connection has been terminated.")
        }



        // Ends the seif connection with the connected party.

        connection.end();
    }
);
```

**party.end(function endCallback(error) {...})**

Ends connection with the listening party. Errors if end is called before a connection
has or is being established.

```javascript
party.end(
    function (error) {
        if (error === undefined) {
            console.log("Successfully ended connection.")
        }
    }
);
```

**party.properties()**

This function returns the identity properties of the party including the publicKey.

```javascript
let partyProperties = party.properties();
console.log("Public key:");
console.log(partyProperties.publickey);
```

License
=======

The MIT License (MIT)

Copyright (c) 2016 PayPal

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


