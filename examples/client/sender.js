'use strict';

let seif = require('seif')({folder: __dirname});
let prompt = require('prompt');
let redis = require('redis');
let createCache = require('./cache');
let PersistentQueue = require('./persistentQueue')

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

let count = 0;

let persistentQueue = PersistentQueue('./reliableMsgs.txt')
function runapp(username, password) {
	let userId = username + "sender0123456789";
	seif.initializeParty({
        username,
        password,
        hostCache,
        sessionCache,
        persistentQueue,
        userId
    }, function (party, error) {

		console.log(party);

		hostCache.write(userId, JSON.stringify({publicKey: party.properties().publicKey}));

		let connectRequest = {
	        petName: "harchu",
	    };
		party.connect(connectRequest, function (error) {

			process.on('exit', function () {party.destroy()});

			let request = {
				message: "GET" + count,
				petName: "harchu"
			};

			console.log("BACK AT SENDER");
			console.log(error);
			if (error !== undefined) {
				console.log("quitting");
				process.exit(1);
			}

			party.seifEventEmitter().on("message", function(response) {
				console.log("Message event");
				console.log(response);
				++count;
				// request.message = "GET" + count;
				// persistentQueue.persist();
				// function timoutCallback () {
				// 	party.sendReliableMessage(request, function() {
				// 		console.log("Wow Such Reliable Wow");
				// 	});
				// 	persistentQueue.persist();
				// }
				// setTimeout(timoutCallback, 10000);
			});

			let autoConnectInProgress = false;

			party.seifEventEmitter().on("error", function(error) {
				console.log("Error event");
				console.log(error);

			});

			party.seifEventEmitter().on("close", function(error) {
				console.log("Close event");
				console.log(error);



				// // if (error.SEIF_CODE === -1) {

				// 	function autoConnect () {
				// 		autoConnectInProgress = true;
				// 		function reconnect() {
				// 			party.connect(
				// 				connectRequest,
				// 				function (error) {
				// 					console.log(error);
				// 					if (error === undefined) {
				// 						console.log("Connected!!!");
				// 						autoConnectInProgress = false;
				// 					} else {
				// 						console.log("Will try again in 5s");
				// 						setTimeout(autoConnect, 5000);
				// 					}
				// 				}
				// 			);
				// 		}
				// 		reconnect();
				// 	}
				// 	if (autoConnectInProgress === false && error !== undefined) {
				// 		// party.end(autoConnect);
				// 		autoConnect();
				// 	}
				// }
			});

			party.sendMessage(request, function(error) {
				console.log("YAYAYAYAYYAYAYAYAYAYAYAYAYAYAYAYYYYYYYYY!!!!!!");
				console.log(error);
			});
		});

	});

}


