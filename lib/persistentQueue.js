'use strict';
let fs = require('fs')

function PersistentQueue(persistentFile) {

	let queue = [];

	let intervalObject;

	function enqueue(item) {
		queue.push(item);
	}

	function dequeue() {
		return queue.shift();
	}

	function size() {
		return queue.length;
	}

	function persist(callback) {
		fs.access(
			persistentFile,
			fs.W_OK,
			function (error) {
				if (error === undefined || error === null) {
					let writeData = {queue};
					fs.writeFile(
						persistentFile,
						JSON.stringify(writeData),
						'utf8',
						function(error) {
							if (error === null) {
								error = undefined;
							}
							if (callback !== undefined) {
								callback(error);
							}
						}
					);
				} else {
					if (callback !== undefined) {
						callback(error);
					}
				}
			}
		);
	}

	function loadFromFile() {

		function returnSuccessfulObj() {
			return Object.freeze({
				enqueue,
				dequeue,
				persist,
				size,
				forEach: function(callback){
					queue.forEach(callback);
				}
			});
		}

		try {
			fs.accessSync(persistentFile, fs.W_OK);
			let fileData = fs.readFileSync(persistentFile, 'utf8');
			if (fileData !== '') {
				queue = JSON.parse(fileData).queue;
			}
			console.log("Successfully loaded from file");
			return returnSuccessfulObj();
		} catch (error) {
			try {
				fs.accessSync(persistentFile, fs.F_OK);
				console.log("Persistent file is not writable, please check permissions");
				return undefined;
			} catch (error) {
				console.log("Persistent file does not exist, creating one.");
				fs.writeFileSync(persistentFile, "", 'utf8');
				return returnSuccessfulObj();
			}
		}
	}

	return loadFromFile();
}


module.exports = PersistentQueue;