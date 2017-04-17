seif-protocol
=============

Node.js Implementation of the Seif protocol

Getting Started
===============

From your project directory, run (see below for requirements):

```
$ npm install seif-protocol
```

Alternatively, to use the latest development version from Github:

```
$ npm install <git-path>
```

Requirements
============

1. seifnode (https://github.com/paypal/seifnode)
2. bunyan


Examples
========

Please refer to the "examples" directory to see examples of how to use the protocol.

Usage
=====

**Creating an entity's identity:**

Seif protocol enables communication between seif parties. A seif party is capable of
connecting and communicating with another seif party.The identity of a seif party is
uniquely characterized by the associated entity.

An entity's identity is composed of an ECC-512 (Elliptic curve cryptography) {publickey, privatekey} pair and a RNG (Random Number Generator) state. The {publickey, privatekey} pair is generated using an entropy pool mined from available external sources, including camera, microphone and the OS. The RNG too is seeded from a different entropy pool mined similarly.

An entity's identity can be created by running:

```
$ node install.js
```

Prompts will be made to aquire location where the entity's identity is to be saved,
the entity's ID and a password. The entity's ID is used to locate the identity in
the provided location and the password is used to secure it.

**Initializing a party:**

The protocol can be used in node.js just like any other module.

```javascript
let seifProtocolModule = require("seif-protocol");
```

To instantiate the protocol interface, the exported function can be used as below:

```javascript
let seifProtocolModule = require("seif-protocol");
let seifProtocol = seifProtocolModule.initializeProtocol({
    folder: __dirname
});
// Folder is the location with identities of entities.
```

The returned "seif" object contains the following functions:

**function initializeEntity(authDetails, function callback(partyGenerator, error){...})**

This function provides access to a party generator linked to the entity's identity
from the specifed location.

```javascript
seif.initializeParty(
    {
        entity,
        password,
        hostCache
    },
    function callback(partyGenerator, error){
        if (error === undefined) {
            console.log("Retrieved identity successfully. Can create a party now.");
            let party = partyGenerator();
            // party cen be used as an initiator or a listener.
        } else {
            console.log("Error retrieving identity.");
            console.log(error);
        }
    }
);

// 'entity'          locates the folder with the entity's identity. [Required].
//
// 'password'        is the encryption/decryption string used to secure the entity's
//                   identity. [Required].
//
// 'hostCache'       is a key value store with read, write and clear capabilities. This
//                   cache is used to store/lookup publickeys. [Optional].
//
// 'callback'        is a function invoked with an party generator capable of
//                   creating parties with the ability to connect, listen and send messages
//                   to other parties. If initialization fails, error will be populated
//                   leaving the party generator undefined.
```

**function createEntityIdentity(function callback(error){...})**
Creates and secures a new entity identity using the data provided and invokes
the given callback. The entity is uniquely identified by its public/private key
pair and RNG state used to generate session secrets.

In an effort to secure the identity, the password provided in data is hashed and
used to protect the public/private keys generated after initializing the ECCISAAC
object. Next, the RNG is initialized and the state file is encrypted with the
hash of the generated private key. At this point the process is complete and the
given callback is invoked.


```javascript
seif.createEntityIdentity(
    {
        entity,
        password
    },
    function callback(error){
        if (error === undefined) {
            console.log("Party identity created successfully.")
        } else {
            console.log("Error creating party identity.");
            console.log(error);
        }
    }
);
// 'entity'          locates the folder with the entity's identity. [Required].
//
// 'password'        is the encryption/decryption string used to secure the entity's
//                   identity. [Required].
```


**Using a party to communicate with other parties:**

A party is capable of:

##### 1. Connecting to another party.

##### 2. Listening for connections from other parties.

##### 3. Sending messages on a successful connection.

Any number of parties can be created with the same entity's identity.
However, a party can either be an initiator of a connection or be a listener.
As an initiator a party can communicate to only one other party at any given
time. In the case where an entity needs to communicate with several other parties,
each connection should be initiated by a different party. As a listener a party
can be in communication with several initiating parties.

**party.connect(properties, function connectCallback (error) {...})**

Connects to a listening seif party using seif protocol.
Callback is invoked with an error in case the connection is unsuccessful.

```javascript
party.connect(
    {
        petname: "PayPal",
        connectAddress,
        connectPublicKey,
        connectionInfo
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
//                   connectPublicKey: public-key                   
//                   petName: short name to lookup
//                   connectionInfo: unencrypted options sent in the hello initiating a new connection.
//                      
//            In the presence of a hostCache, the petname will be looked up.
//            If such a cache isn’t available the connectAddress and connectPublicKey
//            parameters is required.
//
// connectCallback is a function invoked with no error on a successful connection.
```

**party.seifEventEmitter()**

This function returns a reference to the event emitter. This is used by the caller to
handle "message", "seifError" and "close" events.

"message": This event is emitted when a message is received by the protocol for the
           party.

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

**party.send(options, function confirmationCallback(error) {...})**

Sends a message on an establised secure connection using the seif protocol.

```javascript
party.send(
    {
        message: JSON or BLOB or [JSON, {id, blob: BLOB}..., JSON]
    },
    function confirmationCallback(error) {
        if (error === undefined) {
            console.log("Message successfully sent.")
        }
    }
);

// options is a frozen object containing message details:
//              message - message to be sent to server. A message can be an
//                        object serializable to JSON or a BLOB or an array of
//                        both with the BLOBs associated with an optional id
//                        for identification.
// confirmationCallback is a function invoked on receiving delivery confirmation.
//                      error is defined in the case of failure.
```

**party.sendStatus(options)**

Sends a message on an establised secure connection using the seif protocol. This type of message is not guaranteed to be sent by the protocol, i.e., there isn't an
associated delivery confirmation. This can be used for log/status/gaming messages.

```javascript
party.sendStatus(
    {
        message: JSON or BLOB or [JSON, {id, blob: BLOB}..., JSON]
    }
);

// options is a frozen object containing message details:
//              message - message to be sent to server. A message can be an
//                        object serializable to JSON or a BLOB or an array of
//                        both with the BLOBs associated with an optional id
//                        for identification.
```

**party.listen(port, connectionListener)**

This function enables a party to listen to connection initiators.

```javascript
party.listen(
    port,
    function (connection) {

        // Returns the connecting party's properties.
        let connectionInitiator = connection.initiator();



        // Returns the message event listener.
        let messageListener = connection.seifMessageListener();
        messageListener.on("message", function (message) {
            // Do something with the recieved message.
        });



        // Send a normal message on the establised secure connection.
        // Callback is invoked with no error on successful delivery.
        let message = {message: "Hello!"};
        // {message: new Buffer([..])}, {message: [JSON, ..., {id, blob: new Buffer([..])}]}
        connection.sendNormal(message, function (error) {
            if (error === undefined) {
                console.log("Sent message successfully");
            }
        });

        // Send a status message on the establised secure connection. There is no delivery confirmation.
        let message = {message: "Hello!"};
        // {message: new Buffer([..])}, {message: [JSON, ..., {id, blob: new Buffer([..])}]}
        connection.sendStatus(message);



        // Redirect temporarily to another listening party.

        // Options can contain a petname to be looked up in the hostCache, or
        // a connect address and a public key. Options can also include
        // connectionInfo which will be sent unencrypted on the initiating Hello
        // to the redirect party.
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
        // a connect address and a public key. Options can also include
        // connectionInfo which will be sent unencrypted on the initiating Hello
        // to the redirect party.
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



        // Returns a boolean whether the party is redirecting the connection.
        let isRedirecting = connection.isSeifRedirecting();
        if (isRedirecting === true) {
            console.log("Connection is being redirected.");
        } else if (isRedirecting === false) {
            console.log("Connection is not being redirected.");
        }



        // Returns the connection properties including the connection id, which
        // is a random number identifying the connection. This can be useful
        // when initiating parties share the same entity's identity.
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

Ends an established connection. Error is populated if the end is called before a connection
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

This function returns the publicKey of the associated entity.

```javascript
let partyProperties = party.properties();
console.log("Public key:");
console.log(partyProperties.publickey);
```

License
=======

The MIT License (MIT)

Copyright (c) 2016, 2017 PayPal

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
