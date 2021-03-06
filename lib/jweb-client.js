/**
 * JSON-Web-Client
 * @module JWebClient
 * @author Martin Springwald
 * @license MIT
 * @requires base64url
 * @requires http
 * @requires https
 * @requires jwa
 * @requires url
 */

 /******************************************************************************
 * Imports
 *****************************************************************************/
var base64url = require('base64url');
var https = require("https");
var jwa = require('jwa');
var url = require('url');

/******************************************************************************
 * Additional helper
 *****************************************************************************/

/**
 * json_to_utf8base64url
 * @private
 * @description convert JSON to base64-url encoded string using UTF-8 encoding
 * @param {Object} obj
 * @return {string}
 * @throws Exception if object cannot be stringified or contains cycle
 */
var json_to_utf8base64url = function (obj) {
	return base64url.encode(new Buffer(JSON.stringify(obj), 'utf8'));
};

/******************************************************************************
 * JWebClient Class
 *****************************************************************************/

/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
function JWebClient() {
	/**
	 * @member {Object} module:JWebClient~JWebClient#key_pair
	 * @desc User account key pair
	 */
	this.key_pair = null; //{Object}
	/**
	 * @member {string} module:JWebClient~JWebClient#last_nonce
	 * @desc Cached nonce returned with last request
	 */
	this.last_nonce = null; //{string}
	/**
	 * @member {boolean} module:JWebClient~JWebClient#verbose
	 * @desc Determines verbose mode
	 */
	this.verbose = false; //{boolean}
}

/******************************************************************************
 * JWT-Section
 *****************************************************************************/

/**
 * createJWT
 * @description create JSON-Web-Token signed object
 * @param {string|undefined} nonce
 * @param {Object|string|number|boolean} payload
 * @param {string} alg
 * @param {Object|string} key
 * @param {Object} jwk
 * @return {string}
 */
JWebClient.prototype.createJWT = function (nonce, payload, alg, key, jwk) {
	/*jshint -W069 */
	// prepare key
	if (key instanceof Object)
		key = base64url.toBuffer(key["k"]);
	// prepare header
	var header = {};
	header.typ = "JWT";
	header.alg = alg;
	header.jwk = jwk;
	if (nonce != void 0)
		header.nonce = nonce;
	// concatenate header and payload
	var input = [
		json_to_utf8base64url(header),
		json_to_utf8base64url(payload)
	].join(".");
	// sign input
	var hmac = jwa(alg);
	var sig = hmac.sign(input, key);
	// concatenate input and signature
	var output = [
		input,
		sig
	].join(".");
	// dereference
	header = null;
	hmac = null;
	input = null;
	jwk = null;
	key = null;
	payload = null;
	// output
	return output;
};

/******************************************************************************
 * REQUEST-Section
 *****************************************************************************/

/**
 * request
 * @description make GET or POST request over HTTPS and use JOSE as payload type
 * @param {string} query
 * @param {string} payload
 * @param {function} callback
 * @param {function} errorCallback
 */
JWebClient.prototype.request = function (query, payload, callback, errorCallback) {
	/*jshint -W069 */
	if (typeof query != "string")
		query = ""; // ensure query is string
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	if (typeof errorCallback != "function")
		errorCallback = this.emptyCallback; // ensure callback is function
	// prepare options
	var uri = url.parse(query);
	var options = {
		hostname : uri.hostname,
		port : uri.port,
		path : uri.path
	};
	if (typeof payload == "string") {
		options.method = "POST";
		options.headers = {
			'Content-Type' : 'application/jose',
			'Content-Length' : payload.length
		};
	} else {
		options.method = "GET";
	}
	// prepare request
	var req = https.request(options, function (res) {
			// receive data
			var data = [];
			res.on('data', function (block) {
				if (block instanceof Buffer)
					data.push(block);
				// dereference
				block = null;
			});
			res.on('end', function () {
				var buf = Buffer.concat(data);
				var isJSON = (res instanceof Object) && (res["headers"] instanceof Object) && (typeof res.headers["content-type"] == "string") && (res.headers["content-type"].indexOf("json") > -1);
				if (isJSON && buf.length > 0) {
					try {
						// convert to JSON
						var json = JSON.parse(buf.toString('utf8'));
						callback(json, res);
						// dereference
						buf = null;
						callback = null;
						data = null;
						errorCallback = null;
						json = null;
						options = null;
						payload = null;
						req = null;
						res = null;
						uri = null;
					} catch (e) {
						// error (if empty or invalid JSON)
						errorCallback(void 0, e);
						// dereference
						callback = null;
						data = null;
						errorCallback = null;
						options = null;
						payload = null;
						req = null;
						res = null;
						uri = null;
					}
				} else {
					callback(buf, res);
					// dereference
					buf = null;
					callback = null;
					data = null;
					errorCallback = null;
					options = null;
					payload = null;
					req = null;
					res = null;
					uri = null;
				}
			});
		}).on('error', function (e) {
			console.error("Error occured", e);
			// error
			errorCallback(void 0, e);
			// dereference
			callback = null;
			data = null;
			e = null;
			errorCallback = null;
			options = null;
			payload = null;
			req = null;
			res = null;
			uri = null;
		});
	// write POST body if payload was specified
	if (typeof payload == "string")
		req.write(payload);
	// make request
	req.end();
};

/**
 * get
 * @description make GET request
 * @param {string} uri
 * @param {function} callback
 * @param {function} errorCallback
 */
JWebClient.prototype.get = function (uri, callback, errorCallback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	this.request(uri, void 0, function (ans, res) {
		ctx.evaluateStatus(uri, null, ans, res);
		// save replay nonce for later requests
		if ((res instanceof Object) && (res["headers"]instanceof Object))
			ctx.last_nonce = res.headers['replay-nonce'];
		callback(ans, res);
		// dereference
		ans = null;
		callback = null;
		ctx = null;
		res = null;
	}, errorCallback);
	// dereference
	errorCallback = null;
};

/**
 * post
 * @description make POST request
 * @param {string} uri
 * @param {Object|string|number|boolean} payload
 * @param {function} callback
 * @param {function} errorCallback
 */
JWebClient.prototype.post = function (uri, payload, callback, errorCallback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	var key_pair = this.key_pair;
	if (!(key_pair instanceof Object))
		key_pair = {}; // ensure key pair is object
	var jwt = this.createJWT(this.last_nonce, payload, "RS256", key_pair["private_pem"], key_pair["public_jwk"]);
	this.request(uri, jwt, function (ans, res) {
		ctx.evaluateStatus(uri, payload, ans, res);
		// save replay nonce for later requests
		if ((res instanceof Object) && (res["headers"] instanceof Object))
			ctx.last_nonce = res.headers['replay-nonce'];
		callback(ans, res);
		// dereference
		ans = null;
		callback = null;
		ctx = null;
		key_pair = null;
		payload = null;
		res = null;
	}, errorCallback);
	// dereference
	errorCallback = null;
};

/******************************************************************************
 * EVALUATION-Section
 *****************************************************************************/

/**
 * evaluateStatus
 * @description check if status is expected and log errors
 * @param {string} uri
 * @param {Object|string|number|boolean} payload
 * @param {Object|string} ans
 * @param {Object} res
 */
JWebClient.prototype.evaluateStatus = function (uri, payload, ans, res) {
	/*jshint -W069 */
	if (this.verbose) {
		if ((payload instanceof Object) || (typeof payload == "string") || (typeof payload == "number") || (typeof payload == "boolean"))
			console.error("Send   :", payload); // what has been sent
	}
	var uri_parsed = url.parse(uri);
	if (res["statusCode"] >= 100 && res["statusCode"] < 400) {
		console.error("HTTP   :", res["statusCode"], uri_parsed.path); // response code if successful
	}
	if (res["statusCode"] >= 400 && res["statusCode"] < 500) {
		console.error("HTTP   :", res["statusCode"], uri_parsed.path); // response code if error
		if (ans instanceof Object) {
			if (typeof ans["detail"] == "string")
				console.error("Message:", ans.detail.split(" :: ").pop()); // error message if any
		}
	}
	if (this.verbose) {
		console.error("Receive:", res["headers"]); // received headers
		console.error("Receive:", ans); // received data
	}
	// dereference
	ans = null;
	payload = null;
	res = null;
	uri_parsed = null;
};

/******************************************************************************
 * HELPER-Section
 *****************************************************************************/

/**
 * Helper: Empty callback
 */
JWebClient.prototype.emptyCallback = function () {
	// nop
};

/******************************************************************************
 * MODULE Export
 *****************************************************************************/
module.exports = JWebClient;
