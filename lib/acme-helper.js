/**
 * ACME helper
 * @module AcmeHelper
 * @author Martin Springwald
 * @license MIT
 * @requires child_process
 * @requires fs
 * @requires rsapemtojwk
 */

 /******************************************************************************
 * Imports
 *****************************************************************************/
var child_process = require('child_process');
var fs = require('fs');
var rsapemtojwk = require('rsa-pem-to-jwk');

/******************************************************************************
 * AcmeHelper Class
 *****************************************************************************/

/**
 * @class AcmeHelper
 * @constructor
 * @description AcmeHelper functions
 */
function AcmeHelper() {}

/**
 * processOptions
 * @static
 * @description asynchronously handle program options as strings or key-value pairs
 * @param {function} handle - key and value are populated as arguments
 */
AcmeHelper.processOptions = function (handle) {
	if (typeof handle != "function")
		return;
	process.argv.forEach(function (entry) {
		if (typeof entry != "string")
			return;
		var pos = entry.indexOf("=");
		var key = entry.slice(0, pos);
		var value = entry.slice(pos + 1);
		if (pos == -1)
			key = entry;
		handle(key, value);
	});
	// dereference
	handle = null;
};

/**
 * createUserKeyPair
 * @static
 * @description create user account key
 * @param {number} bit - key strength, expected to be already sanitized
 * @param {string} filename - expected to be already sanitized
 * @param {function} callback - first argument is result object of child process
 * @param {boolean} verbose
 */
AcmeHelper.createUserKeyPair = function (bit, filename, callback, verbose) {
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	var cmd = "openssl genrsa %bit% > \"%filename%\"";
	var openssl = cmd
		.replace(/%bit%/g, bit)
		.replace(/%filename%/g, filename);
	console.error("Action : Creating key file");
	if (verbose)
		console.error("Running:", openssl);
	child_process.exec(openssl, function (e) {
		if (!e)
			console.error("Result : done");
		else
			console.error("Result : failed");
		callback(e);
		// dereference
		callback = null;
		e = null;
	});
};

/**
 * getUserKeyPair
 * @static
 * @description read and determine user key pair from private key file
 * @param {string} key_file
 * @param {function} callback - first argument will be the key pair object
 * @param {boolean} verbose
 */
AcmeHelper.getUserKeyPair = function (key_file, callback, verbose) {
	/*jshint -W069 */
	var user_key_pair = {};
	if (typeof key_file != "string")
		key_file = "";
	if (typeof callback != "function")
		callback = function () {};
	fs.readFile(key_file, function (err, data) {
		if (err instanceof Object) {
			if (verbose)
				console.error("Error  : File system error", err["code"], "while reading key from file");
			callback();
			// dereference
			callback = null;
			data = null;
			err = null;
			user_key_pair = null;
		} else {
			user_key_pair.private_pem = data.toString(); // private key
			user_key_pair.public_jwk = rsapemtojwk(user_key_pair.private_pem, 'public'); // public key
			callback(user_key_pair);
			// dereference
			callback = null;
			data = null;
			err = null;
			user_key_pair = null;
		}
	});
};

/**
 * makeAcmePath
 * @static
 * @description ensure existence of "well-known" path
 * @param {string} dir - expected to be already sanitized
 * @param {function} callback - first argument will be success indicator (boolean)
 */
AcmeHelper.makeAcmePath = function (dir, callback) {
	if (typeof dir != "string")
		dir = "";
	if (typeof callback != "function")
		callback = function () {};
	// try root
	fs.stat(dir, function (err, stats) {
		if (!err & stats.isDirectory()) {
			// reset
			err = null;
			stats = null;
			// try root/.well-known
			fs.stat(dir + "/.well-known", function (err, stats) {
				if (!err && stats.isDirectory()) {
					// reset
					err = null;
					stats = null;
					// try root/.well-known/acme-challenge
					fs.stat(dir + "/.well-known/acme-challenge", function (err, stats) {
						if (!err && stats.isDirectory()) {
							callback(true);
							// dereference
							callback = null;
							err = null;
							stats = null;
						}
						else {
							// reset
							err = null;
							stats = null;
							// create root/.well-known/acme-challenge
							fs.mkdir(dir + "/.well-known/acme-challenge", function (err, stats) {
								callback(err ? false : true);
								// dereference
								callback = null;
								err = null;
								stats = null;
							});
						}
					});
				} else {
					// reset
					err = null;
					stats = null;
					// create root/.well-known
					fs.mkdir(dir + "/.well-known", function (err, stats) {
						if (!err) {
							// reset
							err = null;
							stats = null;
							// create root/.well-known/acme-challenge
							fs.mkdir(dir + "/.well-known/acme-challenge", function (err, stats) {
								callback(!err);
								// dereference
								callback = null;
								err = null;
								stats = null;
							});
						}
						else {
							callback(false);
							// dereference
							callback = null;
							err = null;
							stats = null;
						}
					});
				}
			});
		} else {
			callback(false);
			// dereference
			callback = null;
			err = null;
			stats = null;
		}
	});
};

/******************************************************************************
 * MODULE Export
 *****************************************************************************/
module.exports = AcmeHelper;
