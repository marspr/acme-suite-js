/**
 * ACME client API
 * @module AcmeClient
 * @author Martin Springwald
 * @license MIT
 * @requires base64url
 * @requires child_process
 * @requires crypto
 * @requires fs
 * @requires readline
 */

 /******************************************************************************
 * Imports
 *****************************************************************************/
var base64url = require('base64url');
var child_process = require('child_process');
var crypto = require('crypto');
var fs = require('fs');
var readline = require('readline');

/******************************************************************************
 * Additional helper
 *****************************************************************************/

/**
 * json_to_utf8buffer
 * @private
 * @description convert JSON to Buffer using UTF-8 encoding
 * @param {Object} obj
 * @return {Buffer}
 * @throws Exception if object cannot be stringified or contains cycle
 */
var json_to_utf8buffer = function (obj) {
	return new Buffer(JSON.stringify(obj), 'utf8');
};

/******************************************************************************
 * AcmeClient Class
 *****************************************************************************/

/**
 * @class AcmeClient
 * @constructor
 * @description ACME protocol implementation from client perspective
 * @param {string} directory_url - Address of directory
 * @param {module:JWebClient~JWebClient} jWebClient - Reference to JSON-Web-Client
 */
function AcmeClient(directory_url, jWebClient) {
	/**
	 * @member {Object} module:AcmeClient~AcmeClient#clientProfilePubKey
	 * @desc Cached public key obtained from profile
	 */
	this.clientProfilePubKey = {}; //{Object}
	/**
	 * @member {number} module:AcmeClient~AcmeClient#days_valid
	 * @desc Validity period in days
	 * @default 1
	 */
	this.days_valid = 1; //{number}
	/**
	 * @member {number} module:AcmeClient~AcmeClient#defaultRsaKeySize
	 * @desc Key strength in bits
	 * @default 4096
	 */
	this.defaultRsaKeySize = 4096; //{number}
	/**
	 * @member {Object} module:AcmeClient~AcmeClient#directory
	 * @desc Hash map of REST URIs
	 */
	this.directory = {}; //{Object}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#directory_url
	 * @desc Address of directory
	 */
	this.directory_url = directory_url; //{string}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#emailDefaultPrefix
	 * @desc Prefix of email address if constructed from domain name
	 * @default "hostmaster"
	 */
	this.emailDefaultPrefix = "hostmaster"; //{string}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#emailOverride
	 * @desc Email address to use
	 */
	this.emailOverride = null; //{string}
	/**
	 * @member {module:JWebClient~JWebClient} module:AcmeClient~AcmeClient#jWebClient
	 * @desc Reference to JSON-Web-Client
	 */
	this.jWebClient = jWebClient; //{JWebClient}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#regLink
	 * @desc Cached registration URI
	 */
	this.regLink = null; //{string}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#tosLink
	 * @desc Cached terms of service URI
	 */
	this.tosLink = null; //{string}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#webroot
	 * @desc Path to server web root (or path to store challenge data)
	 * @default "."
	 */
	this.webroot = "."; //{string}
	/**
	 * @member {string} module:AcmeClient~AcmeClient#well_known_path
	 * @desc Directory structure for challenge data
	 * @default "/.well-known/acme-challenge/"
	 */
	this.well_known_path = "/.well-known/acme-challenge/"; //{string}
	/**
	 * @member {boolean} module:AcmeClient~AcmeClient#withInteraction
	 * @desc Determines if interaction of user is required
	 * @default true
	 */
	this.withInteraction = true; //{boolean}
}

/******************************************************************************
 * REQUEST-Section
 *****************************************************************************/

/**
 * getDirectory
 * @description retrieve directory entries (directory url must be set prior to execution)
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.getDirectory = function (callback) {
	this.jWebClient.get(this.directory_url, callback, callback);
	// dereference
	callback = null;
};

/**
 * newRegistration
 * @description try to register (directory lookup must have occured prior to execution)
 * @param {Object} payload
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.newRegistration = function (payload, callback) {
	if (!(payload instanceof Object))
		payload = {}; // ensure payload is object
	payload.resource = "new-reg";
	this.jWebClient.post(this.directory['new-reg'], payload, callback, callback);
	// dereference
	callback = null;
	payload = null;
};

/**
 * getRegistration
 * @description get information about registration
 * @param {string} uri - will be exposed when trying to register
 * @param {Object} payload - update information
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.getRegistration = function (uri, payload, callback) {
	/*jshint -W069 */
	var ctx = this;
	if (!(payload instanceof Object))
		payload = {}; // ensure payload is object
	payload["resource"] = "reg";
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	this.jWebClient.post(uri, payload, function (ans, res) {
		if (ans instanceof Object) {
			ctx.clientProfilePubKey = ans.key; // cache or reset returned public key
			if ((res instanceof Object) && (res["headers"] instanceof Object)) {
				var linkStr = res.headers["link"];
				if (typeof linkStr == "string") {
					var tosLink = ctx.getTosLink(linkStr);
					if (typeof tosLink == "string") ctx.tosLink = tosLink; // cache TOS link
					else ctx.tosLink = null; // reset TOS link
				}
				else
					ctx.tosLink = null; // reset TOS link
			}
			else
				ctx.tosLink = null; // reset TOS link
			callback(ans, res);
		} else
			callback(false);
		// dereference
		ans = null;
		callback = null;
		ctx = null;
		res = null;
	});
	// dereference
	payload = null;
};

/**
 * authorizeDomain
 * @description authorize domain using challenge-response-method
 * @param {string} domain
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.authorizeDomain = function (domain, callback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	this.getProfile(function (profile) {
		if (!(profile instanceof Object)) {
			callback(false); // no profile returned
			// dereference
			callback = null;
			ctx = null;
		}
		else {
			ctx.jWebClient.post(ctx.directory['new-authz'], ctx.makeDomainAuthorizationRequest(domain), function (ans, res) {
				if ((res instanceof Object) && (res["statusCode"] == 403)) { // if unauthorized
					ctx.agreeTos(ctx.tosLink, function (ans_, res_) { // agree to TOS
						if ((res_ instanceof Object) && (res_["statusCode"] >= 200) && (res_["statusCode"] <= 400)) // if TOS were agreed successfully
							ctx.authorizeDomain(domain, callback); // try authorization again
						else
							callback(false); // agreement failed
						// dereference
						ans = null;
						ans_ = null;
						callback = null;
						ctx = null;
						profile = null;
						res = null;
						res_ = null;
					});
				} else {
					if ((res instanceof Object) && (res["headers"] instanceof Object) && (typeof res.headers['location'] == "string") && (ans instanceof Object)) {
						var poll_uri = res.headers['location']; // status URI for polling
						var challenge = ctx.selectChallenge(ans, "http-01"); // select simple http challenge
						if (challenge instanceof Object) { // desired challenge is in list
							ctx.prepareChallenge(domain, challenge, function () { // prepare all objects and files for challenge
								// reset
								ans = null;
								res = null;
								// accept challenge
								ctx.acceptChallenge(challenge, function (ans, res) {
									if ((res instanceof Object) && (res["statusCode"] < 400)) // if server confirms challenge acceptance
										ctx.pollUntilValid(poll_uri, callback); // poll status until server states success
									else
										callback(false); // server did not confirm challenge acceptance
									// dereference
									ans = null;
									callback = null;
									challenge = null;
									ctx = null;
									profile = null;
									res = null;
								});
							});
						} else {
							callback(false); // desired challenge is not in list
							// dereference
							ans = null;
							callback = null;
							ctx = null;
							profile = null;
							res = null;
						}
					} else {
						callback(false); // server did not respond with status URI
						// dereference
						ans = null;
						callback = null;
						ctx = null;
						profile = null;
						res = null;
					}
				}
			});
		}
	});
};

/**
 * acceptChallenge
 * @description tell server which challenge will be accepted
 * @param {Object} challenge
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.acceptChallenge = function (challenge, callback) {
	/*jshint -W069 */
	if (!(challenge instanceof Object))
		challenge = {}; // ensure challenge is object
	this.jWebClient.post(challenge["uri"], this.makeChallengeResponse(challenge), callback);
	// dereference
	callback = null;
	challenge = null;
};

/**
 * pollUntilValid
 * @description periodically (with exponential back-off) check status of challenge
 * @param {string} uri
 * @param {function} callback - first argument will be the answer object
 * @param {number} retry - factor of delay
 */
AcmeClient.prototype.pollUntilValid = function (uri, callback, retry) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	if ((typeof retry != "number") || (isNaN(retry)) || (retry === 0))
		retry = 1; // reset retry value
	if (retry > 128)
		callback(false); // stop if retry value exceeds maximum
	else {
		this.jWebClient.get(uri, function (ans, res) {
			if (!(ans instanceof Object)) {
				callback(false); // invalid answer
				// dereference
				callback = null;
				ctx = null;
				res = null;
			}
			else {
				if (ans["status"] == "pending") { // still pending
					setTimeout(function () {
						ctx.pollUntilValid(uri, callback, retry * 2); // retry
						// dereference
						ans = null;
						callback = null;
						ctx = null;
						res = null;
					}, retry * 500);
				} else {
					callback(ans, res); // challenge complete
					// dereference
					ans = null;
					callback = null;
					ctx = null;
					res = null;
				}
			}
		});
	}
};

/**
 * pollUntilIssued
 * @description periodically (with exponential back-off) check status of CSR
 * @param {string} uri
 * @param {function} callback - first argument will be the answer object
 * @param {number} retry - factor of delay
 */
AcmeClient.prototype.pollUntilIssued = function (uri, callback, retry) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	if ((typeof retry != "number") || (isNaN(retry)) || (retry === 0))
		retry = 1; // reset retry value
	if (retry > 128)
		callback(false); // stop if retry value exceeds maximum
	else {
		this.jWebClient.get(uri, function (ans, res) {
			if ((ans instanceof Buffer) && (ans.length > 0)) {
				callback(ans); // certificate was returned with answer
				// dereference
				ans = null;
				callback = null;
				ctx = null;
				res = null;
			} else {
				if ((res instanceof Object) && (res["statusCode"] < 400)) { // still pending
					setTimeout(function () {
						ctx.pollUntilIssued(uri, callback, retry * 2); // retry
						// dereference
						ans = null;
						callback = null;
						ctx = null;
						res = null;
					}, retry * 500);
				} else {
					callback(false); // CSR complete
					// dereference
					ans = null;
					callback = null;
					ctx = null;
					res = null;
				}
			}
		});
	}
};

/**
 * requestSigning
 * @description send CSR
 * @param {string} domain - expected to be already sanitized
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.requestSigning = function (domain, callback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	fs.readFile(domain + ".csr", function(err, csr) {
		if (err instanceof Object) { // file system error
			if (ctx.jWebClient.verbose)
				console.error("Error  : File system error", err["code"], "while reading key from file");
			callback(false);
			// dereference
			callback = null;
			csr = null;
			ctx = null;
			err = null;
		}
		else
			ctx.jWebClient.post(ctx.directory["new-cert"], ctx.makeCertRequest(csr, ctx.days_valid), function (ans, res) {
				if ((ans instanceof Buffer) && (ans.length > 0)) { // answer is buffer
					callback(ans); // certificate was returned with answer
					// dereference
					ans = null;
					callback = null;
					csr = null;
					ctx = null;
					err = null;
					res = null;
				}
				else {
					if (res instanceof Object) {
						if ((res["statusCode"] < 400) && !ans) { // success response, but no answer was provided
							var headers = res["headers"];
							if (!(headers instanceof Object)) headers = {}; // ensure headers is object
							ctx.pollUntilIssued(headers['location'], callback); // poll provided status URI
							// dereference
							headers = null;
						}
						else
							callback((res["statusCode"] < 400) ? ans : false); // answer may be provided as string or object
					}
					else
						callback(false); // invalid response
					// dereference
					ans = null;
					callback = null;
					csr = null;
					ctx = null;
					err = null;
					res = null;
				}
			});
	});
};

/**
 * getProfile
 * @description retrieve profile of user (will make directory lookup and registration check)
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.getProfile = function (callback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	this.getDirectory(function (dir) {
		if (!(dir instanceof Object)) {
			callback(false); // server did not respond with directory
			// dereference
			callback = null;
			ctx = null;
		}
		else {
			ctx.directory = dir; // cache directory
			ctx.newRegistration(null, function (ans, res) { // try new registration to get registration link
				if ((res instanceof Object) && (res['headers'] instanceof Object) && (typeof res.headers['location'] == "string")) {
					ctx.regLink = res.headers['location'];
					ctx.getRegistration(ctx.regLink, null, callback); // get registration info from link
				} else
					callback(false); // registration failed
				// dereference
				ans = null;
				callback = null;
				ctx = null;
				dir = null;
				res = null;
			});
		}
	});
};

/**
 * createAccount
 * @description create new account (assumes directory lookup has already occured)
 * @param {string} email
 * @param {function} callback - first argument will be the registration URI
 */
AcmeClient.prototype.createAccount = function (email, callback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof email == "string") {
		if (typeof callback != "function")
			callback = this.emptyCallback; // ensure callback is function
		ctx.newRegistration({
			contact: [
				"mailto:" + email
			]
		}, function (ans, res) {
			if ((res instanceof Object) && (res['statusCode'] == 201) && (res['headers'] instanceof Object) && (typeof res.headers['location'] == "string")) {
				ctx.regLink = res.headers['location'];
				callback(ctx.regLink); // registration URI
			} else
				callback(false); // registration failed
			// dereference
			ans = null;
			callback = null;
			ctx = null;
			res = null;
		});
	}
	else {
		callback(false); // no email address provided
		// dereference
		callback = null;
		ctx = null;
	}
};

/**
 * agreeTos
 * @description agree with terms of service (update agreement status in profile)
 * @param {string} tosLink
 * @param {function} callback - first argument will be the answer object
 */
AcmeClient.prototype.agreeTos = function (tosLink, callback) {
	this.getRegistration(this.regLink, {
		"Agreement" : tosLink // terms of service URI
	}, callback);
	// dereference
	callback = null;
};

/******************************************************************************
 * ENTRY-Section
 *****************************************************************************/

/**
 * Entry-Point: Request certificate
 * @param {string} domain
 * @param {string} organization
 * @param {string} country
 * @param {function} callback
 */
AcmeClient.prototype.requestCertificate = function (domain, organization, country, callback) {
	/*jshint -W069 */
	var ctx = this;
	if (typeof domain != "string")
		domain = ""; // ensure domain is string
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	this.getProfile(function (profile) {
		var email = ctx.extractEmail(profile); // try to determine email address from profile
		if (typeof ctx.emailOverride == "string") email = ctx.emailOverride; // override email address if set
		else if (typeof email != "string") email = ctx.emailDefaultPrefix + "@" + domain; // or set default
		var bit = ctx.defaultRsaKeySize;
		// sanitize
		bit = Number(bit);
		country = ctx.makeSafeFileName(country);
		domain = ctx.makeSafeFileName(domain);
		email = ctx.makeSafeFileName(email);
		organization = ctx.makeSafeFileName(organization);
		// create key pair
		ctx.createKeyPair(bit, country, organization, domain, email, function (e) { // create key pair
			if (!e)
				ctx.requestSigning(domain, function (cert) { // send CSR
					if ((cert instanceof Buffer) || (typeof cert == "string")) // valid certificate data
						fs.writeFile(domain + ".der", cert, function(err) { // sanitize domain name for file path
							if (err instanceof Object) { // file system error
								if (ctx.jWebClient.verbose)
									console.error("Error  : File system error", err["code"], "while writing certificate to file");
								callback(false);
							}
							else
								callback(true); // CSR complete and certificate written to file system
							// dereference
							callback = null;
							cert = null;
							ctx = null;
							e = null;
							err = null;
							profile = null;
						});
					else {
						callback(false); // invalid certificate data
						// dereference
						callback = null;
						cert = null;
						ctx = null;
						e = null;
						profile = null;
					}
				});
			else {
				callback(false); // could not create key pair
				// dereference
				callback = null;
				ctx = null;
				e = null;
				profile = null;
			}				
		});
	});
};

/******************************************************************************
 * EXTERNAL-Section
 *****************************************************************************/

/**
 * External: Create key pair
 * @param {number} bit - key strength, expected to be already sanitized
 * @param {string} c - country code, expected to be already sanitized
 * @param {string} o - organization, expected to be already sanitized
 * @param {string} cn - common name (domain name), expected to be already sanitized
 * @param {string} e - email address, expected to be already sanitized
 * @param {function} callback
 */
AcmeClient.prototype.createKeyPair = function (bit, c, o, cn, e, callback) {
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	var cmd = "openssl req -new -nodes -newkey rsa:%bit% -sha256 -subj \"/C=%c%/O=%o%/CN=%cn%/emailAddress=%e%\" -keyout \"%cn%.key\" -outform der -out \"%cn%.csr\"";
	var openssl = cmd
		.replace(/%bit%/g, bit)
		.replace(/%c%/g, c)
		.replace(/%o%/g, o)
		.replace(/%cn%/g, cn)
		.replace(/%e%/g, e);
	console.error("Action : Creating key pair");
	if (this.jWebClient.verbose)
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
		}
	);
};

/******************************************************************************
 * HELPER-Section
 *****************************************************************************/

/**
 * Helper: Empty callback
 */
AcmeClient.prototype.emptyCallback = function () {
	// nop
};

/**
 * Helper: Make safe file name or path from string
 * @param {string} name
 * @param {boolean} withPath - optional, default false
 * @return {string}
 */
AcmeClient.prototype.makeSafeFileName = function (name, withPath) {
	if (typeof name != "string") name = "";
	// respects file name restrictions for ntfs and ext2
	var regex_file = "[<>:\"/\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]";
	var regex_path = "[<>:\"\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]";
	return name.replace(new RegExp(withPath ? regex_path : regex_file, "g"), function (charToReplace) {
		if (typeof charToReplace == "string") {
			return "%" + charToReplace.charCodeAt(0).toString(16).toLocaleUpperCase();
		}
		return "%00";
	});
};

/**
 * Helper: Write challenge file to disk
 * @param {string} domain
 * @param {Object} challenge
 * @param {string} authorization
 * @param {function} callback
 */
AcmeClient.prototype.writeChallenge = function(domain, challenge, authorization, callback) {
	var path = this.webroot + this.well_known_path + challenge["token"]; // webroot and well_known_path are expected to be already sanitized
	fs.writeFile(path, authorization, callback);
}

/**
 * Helper: Prepare challenge
 * @param {string} domain
 * @param {Object} challenge
 * @param {function} callback
 */
AcmeClient.prototype.prepareChallenge = function (domain, challenge, callback) {
	/*jshint -W069, unused:false*/
	var ctx = this;
	if (typeof callback != "function")
		callback = this.emptyCallback; // ensure callback is function
	if (challenge instanceof Object) {
		if (challenge["type"] == "http-01") { // simple http challenge
			ctx.writeChallenge(domain, challenge, this.makeKeyAuthorization(challenge), function(err) { // create challenge file
				if (err instanceof Object) { // file system error
					if (ctx.jWebClient.verbose)
						console.error("Error  : File system error", err["code"], "while writing challenge data to file");
					callback();
					// dereference
					callback = null;
					challenge = null;
					ctx = null;
					err = null;
				}
				else {
					//var uri = "http://" + domain + this.well_known_path + challenge["token"];
					var rl = readline.createInterface(process.stdin, process.stdout);
					if (ctx.withInteraction)
						rl.question("Press enter to proceed", function (answer) { // wait for user to proceed
							rl.close();
							callback();
							// dereference
							callback = null;
							challenge = null;
							ctx = null;
							rl = null;
						});
					else {
						rl.close();
						callback(); // skip interaction prompt if desired
						// dereference
						callback = null;
						challenge = null;
						ctx = null;
						rl = null;
					}
				}
			});
		}
		else { // no supported challenge
			console.error("Error  : Challenge not supported");
			callback();
			// dereference
			callback = null;
			challenge = null;
			ctx = null;
		}
	}
	else { // invalid challenge response
		console.error("Error  : Invalid challenge response");
		callback();
		// dereference
		callback = null;
		challenge = null;
		ctx = null;
	}
};

/**
 * Helper: Extract TOS Link, e.g. from "&lt;http://...&gt;;rel="terms-of-service"
 * @param {string} linkStr
 * @return {string}
 */
AcmeClient.prototype.getTosLink = function (linkStr) {
	var match = /(<)([^>]+)(>;rel="terms-of-service")/g.exec(linkStr);
	if ((match instanceof Array) && (match.length > 2)) {
		var result = match[2];
		// dereference
		match = null;
		return result;
	}
	// dereference
	match = null;
	return void 0;
};

/**
 * Helper: Select challenge by type
 * @param {Object} ans
 * @param {string} challenge_type
 * @return {Object}
 */
AcmeClient.prototype.selectChallenge = function (ans, challenge_type) {
	/*jshint -W069 */
	if ((ans instanceof Object) && (ans["challenges"] instanceof Array))
		return ans.challenges.filter(function (entry) {
			var type = entry["type"];
			// dereference
			entry = null;
			if (type == challenge_type) // check for type match
				return true;
			return false;
		}).pop(); // return first match or undefined
	// dereference
	ans = null;
	return void 0; // challenges not available or in expected format
};

/**
 * Helper: Extract first found email from profile (without mailto prefix)
 * @param {Object} profile
 * @return {string}
 */
AcmeClient.prototype.extractEmail = function (profile) {
	/*jshint -W069 */
	if (!(profile instanceof Object) || !(profile["contact"] instanceof Array)) {
		// dereference
		profile = null;
		return void 0; // invalid profile
	}
	var prefix = "mailto:";
	var email = profile.contact.filter(function (entry) {
			if (typeof entry != "string") return false;
			return !entry.indexOf(prefix); // check for mail prefix
		}
	).pop();
	// dereference
	profile = null;
	if (typeof email != "string") return void 0; // return default
	return email.substr(prefix.length); // only return email address without protocol prefix
};

/******************************************************************************
 * MAKE-Section
 *****************************************************************************/

/**
 * Make ACME-Reques: Domain-Authorization Request - Object: resource, identifier
 * @param {string} domain
 * @return {{resource: string, identifier: Object}}
 */
AcmeClient.prototype.makeDomainAuthorizationRequest = function (domain) {
	return {
		"resource" : "new-authz",
		"identifier" : {
			"type" : "dns",
			"value" : domain
		}
	};
};

/**
 * Make ACME-Object: Key-Authorization (encoded) - String: Challenge-Token . Encoded-Account-Key-Hash
 * @param {Object} challenge
 * @return {string}
 */
AcmeClient.prototype.makeKeyAuthorization = function (challenge) {
	/*jshint -W069 */
	if (challenge instanceof Object) {
		if (this.clientProfilePubKey instanceof Object) {
			var jwk = json_to_utf8buffer({
					e : this.clientProfilePubKey["e"],
					kty : this.clientProfilePubKey["kty"],
					n : this.clientProfilePubKey["n"]
				}
			);
			var hash = crypto.createHash('sha256').update(jwk.toString('utf8'), 'utf8').digest();
			var account_key = base64url.encode(hash); // create base64 encoded hash of account key
			var token = challenge["token"];
			// dereference
			challenge = null;
			jwk = null;
			return token + "." + account_key;
		}
	}
	else return ""; // return default (for writing to file)
};

/**
 * Make ACME-Request: Challenge-Response - Object: resource, keyAuthorization
 * @param {Object} challenge
 * @return {{resource: string, keyAuthorization: string}}
 */
AcmeClient.prototype.makeChallengeResponse = function (challenge) {
	return {
		"resource" : "challenge",
		"keyAuthorization" : this.makeKeyAuthorization(challenge)
	};
};

/**
 * Make ACME-Request: CSR - Object: resource, csr, notBefore, notAfter
 * @param {string} csr
 * @param {number} days_valid
 * @return {{resource: string, csr: string, notBefore: string, notAfter: string}}
 */
AcmeClient.prototype.makeCertRequest = function (csr, days_valid) {
	if (typeof csr != "string" && !(csr instanceof Buffer))
		csr = ""; // default string for CSR
	if ((typeof days_valid != "number") || (isNaN(days_valid)) || (days_valid === 0))
		days_valid = 1; // default validity duration (1 day)
	var domain_csr_der = base64url.encode(csr); // create base64 encoded CSR
	var current_date = (new Date()).toISOString(); // set start date to current date
	var after_date = (new Date((+new Date()) + 1000 * 60 * 60 * 24 * Math.abs(days_valid))).toISOString(); // set end date to current date + days_valid
	return {
		"resource" : "new-cert",
		"csr" : domain_csr_der,
		"notBefore" : current_date,
		"notAfter" : after_date
	};
};

/******************************************************************************
 * MODULE Exports
 *****************************************************************************/
module.exports = AcmeClient;
