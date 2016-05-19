'use strict';

function createCache(cache) {

	function read(key, callback) {
		cache.get(key, function (error, response) {
			if (error === null) {
				error = undefined;
			}
			if (response === null) {
				response = undefined;
			}
			if (callback !== undefined) {
				callback(response, error);	
			}
		});
	}

	function write(key, value, callback) {
		cache.set(key, value, function (error, response) {
			if (error === null) {
				error = undefined;
			}
			if (response === null) {
				response = undefined;
			}
			if (callback !== undefined) {
				callback(response, error);	
			}
			
		});
	}

	function clear(key, callback) {
		cache.del(key, function (error, response) {
			if (error === null) {
				error = undefined;
			}
			if (response === null) {
				response = undefined;
			}
			if (callback !== undefined) {
				callback(response, error);	
			}
		});
	}

	return Object.freeze({
		read,
		write,
		clear
	});
}


module.exports = createCache;