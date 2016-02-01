#!/usr/bin/env node

/**
 * ACME client CLI
 * @module acme-client-cli
 * @author Martin Springwald
 * @license MIT
 * @requires AcmeClient
 * @requires AcmeHelper
 * @requires JWebClient
 */

/******************************************************************************
 * Imports
 *****************************************************************************/
var AcmeClient = require('./lib/acme-client.js');
var helper = require('./lib/acme-helper.js');
var JWebClient = require('./lib/jweb-client.js');

/******************************************************************************
 * Version
 *****************************************************************************/
var version = require('./package.json').version; //{string}

/******************************************************************************
 * Defaults
 *****************************************************************************/
var command = null; //{string}
var country = "ZZ"; //{string}
var days_valid = 1; //{number}
var domain = null; //{string}
var directory_url = "https://acme-v01.api.letsencrypt.org/directory"; //{string]
var email = null; //{string}
var interactive = true; //{boolean}
var organization = "Private"; //{string}
var rsa_keysize = 4096; //{number}
var user_key_file = "account.key"; //{string}
var verbose = false; //{boolean}
var webroot = "."; //{string}

/******************************************************************************
 * Clients
 *****************************************************************************/
var acme_client; //{AcmeClient}
var jweb_client; //{JWebClient}

/******************************************************************************
 * Steps
 *****************************************************************************/

/**
 * process options
 */
function prepare() {
	helper.processOptions(function (key, value) {
		switch (key) {
		case "-c":
		case "--cmd":
			command = value;
			break;
		case "-d":
		case "--dns":
			domain = value;
			break;
		case "-e":
		case "--email":
			email = value;
			break;
		case "-h":
		case "--help":
			command = "help";
			break;
		case "-k":
		case "--key":
			user_key_file = value;
			break;
		case "-l":
		case "--loc":
			country = value;
			break;
		case "-n":
		case "--ndays":
			days_valid = Number(value);
			break;
		case "-o":
		case "--org":
			organization = value;
			break;
		case "-r":
		case "--rsa":
			rsa_keysize = Number(value);
			break;
		case "-u":
		case "--url":
			directory_url = value;
			break;
		case "-v":
		case "--verbose":
			verbose = true;
			break;
		case "-w":
		case "--www":
			webroot = value;
			break;
		case "-y":
		case "--yes":
			interactive = false;
			break;
		}
	});
}

/**
 * greeting
 */
function greeting() {
	process.stdout.write("ACME Client for node.js\n");
	console.error("Version: " + version);
}

/**
 * getOrCreateUserKeyPair
 * @param {function} callback
 */
function getOrCreateUserKeyPair(callback) {
	// sanitize user key filename
	user_key_file = acme_client.makeSafeFileName(user_key_file, true);
	// get or create user key pair
	helper.getUserKeyPair(user_key_file, function (key_pair) {
		if (key_pair instanceof Object) {
			console.error("Result : done");
			callback(key_pair);
			// dereference
			callback = null;
			key_pair = null;
		} else {
			console.error("Result : failed");
			// rsa_keysize is ensured to be of type number, null or NaN (see prepare : case handler for '-n')
			// user_key_file is ensured to be sanitized (see user_key_file ~ makeSafeFileName)
			helper.createUserKeyPair(rsa_keysize, user_key_file, function(e) {
				if (!e) {
					console.error("Action : Reading key file");
					helper.getUserKeyPair(user_key_file, function (key_pair) {
						if (key_pair instanceof Object) {
							console.error("Result : done");
							callback(key_pair);
						} else {
							console.error("Result : failed");
							callback();
						}
						// dereference
						callback = null;
						e = null;
						key_pair = null;
					});
				}
				else {
					callback();
					// dereference
					callback = null;
					e = null;
				}
			}, verbose);
		}
	}, verbose);
}

/**
 * initialization
 * @param {function} callback
 * @param {boolean} suppress
 */
function init(callback) {
	console.error("Using  : Verbose =", verbose);
	console.error("Using  : Key file =", user_key_file);
	jweb_client = new JWebClient();
	acme_client = new AcmeClient(directory_url, jweb_client);
	console.error("Action : Reading key file");
	getOrCreateUserKeyPair(function(key_pair) {
		if (key_pair instanceof Object)
			jweb_client.key_pair = key_pair;
		jweb_client.verbose = verbose;
		acme_client.days_valid = days_valid;
		acme_client.defaultRsaKeySize = rsa_keysize;
		acme_client.email = email;
		acme_client.webroot = acme_client.makeSafeFileName(webroot, true); // sanitize webroot
		acme_client.withInteraction = interactive;
		console.error("Using  : Directory URL =", acme_client.directory_url);
		callback();
		// dereference
		JWebClient = null;
		callback = null;
		jweb_client = null;
		key_pair = null;
	});
}

/**
 * execute
 * @param {function} callback
 */
function exec(callback) {
	switch (command) {
	case "info": {
			/*jshint -W069 */
			acme_client.getProfile(function (profile) {
				if (typeof profile != "object") {
					console.error("Error  : Could not retrieve profile");
				} else {
					process.stdout.write("User ID: " + profile["id"] + "\n");
					if (profile["contact"] instanceof Array) process.stdout.write("Contact: " + profile.contact.join(", ") + "\n");
					process.stdout.write("Created: " + profile["createdAt"] + " from " + profile["initialIp"] + "\n");
					if (typeof profile["agreement"] == "string") process.stdout.write("Terms  : " + profile.agreement);
					else if (typeof acme_client.tosLink == "string") process.stdout.write("Terms? : " + acme_client.tosLink);
				}
				// callback
				callback();
				// dereference
				callback = null;
				profile = null;
			});
		}
		break;
	case "reg": {
			if (typeof email != "string") {
				console.error("Error  : Missing email address");
				command = "help";
			} else {
				acme_client.getDirectory(function (directory) {
					if (directory instanceof Object) {
						acme_client.directory = directory;
						acme_client.createAccount(email, function (regLink) {
							if (regLink !== false) {
								process.stdout.write("Reg-URI: " + regLink + "\n");
							}
							else
								console.error("Error  : Registration failed");
							// callback
							callback();
							// dereference
							callback = null;
						});
					} else {
						console.error("Error  : Registration failed");
						// callback
						callback();
						// dereference
						callback = null;
					}
					// dereference
					directory = null;
				});
			}
		}
		break;
	case "add": {
			if (typeof domain != "string") {
				console.error("Error  : Missing domain");
				command = "help";
			} else {
				console.error("Using  : Domain =", "'" + domain + "'");
				console.error("Using  : Interactive mode =", acme_client.withInteraction);
				console.error("Using  : Web root =", "'" + acme_client.webroot + "'");
				console.error("Action : Trying to create ACME path at", acme_client.webroot);
				// webroot is ensured to be sanitized (see init : acme_client.webroot ~ makeSafeFileName)
				helper.makeAcmePath(acme_client.webroot, function (success) {
					console.error("Result :", success);
					if (success)
						acme_client.authorizeDomain(domain, function (success) {
							if (success)
								process.stdout.write("Success: " + "Domain authorized\n");
							else
								console.error("Error  : Could not authorize domain");
							// callback
							callback();
							// dereference
							callback = null;
						});
				});
			}
		}
		break;
	case "csr": {
			if (typeof domain != "string") {
				console.error("Error  : Missing domain");
				command = "help";
			} else {
				console.error("Using  : Country code =", "'" + country + "'");
				console.error("Using  : Days valid =", "'" + days_valid + "'");
				console.error("Using  : Domain =", "'" + domain + "'");
				if (typeof email == "string")
					console.error("Using  : Email =", "'" + email + "'");
				console.error("Using  : Organization =", "'" + organization + "'");
				console.error("Using  : RSA Key size =", acme_client.defaultRsaKeySize);
				acme_client.requestCertificate(domain, organization, country, function (success) {
					if (success)
						process.stdout.write("Success: " + "Certificate signed\n");
					else
						console.error("Error  : Certificate signing request failed");
					// callback
					callback();
					// dereference
					callback = null;
				});
			}
		}
		break;
	default: {
			command = "help";
		}
		break;
	}

	if (command == "help") {
		process.stdout.write("Usage  :\n");
		process.stdout.write(" -c=CMD --cmd=CMD: Command, default 'help'\n");
		process.stdout.write("    'add' : Authorize domain (Parameters: -d, -w, -y)\n");
		process.stdout.write("            Terms of service will be accepted automatically\n");
		process.stdout.write("    'csr' : Certificate signing request (Parameters: -d, -e, -l, -n, -o, -r)\n");
		process.stdout.write("    'help': Help (same as -h)\n");
		process.stdout.write("    'info': Profile info (e.g. ID, contacts and terms of service)\n");
		process.stdout.write("    'reg' : Register new account (Parameters: -e)\n");
		process.stdout.write("            Any command except help will register new account if unregistered\n");
		process.stdout.write(" -d=DOMAIN --dns=DOMAIN: Domain\n");
		process.stdout.write(" -e=EMAIL --email=EMAIL: Specify email address, default from profile\n");
		process.stdout.write(" -h --help: Help\n");
		process.stdout.write(" -k=FILE --key=FILE: User private key, default 'account.key'\n");
		process.stdout.write("    New key will be created if file does not exist\n");
		process.stdout.write(" -l=CC --loc=CC: Country Code, default 'ZZ'\n");
		process.stdout.write(" -n=DAYS --ndays=DAYS: Number of days for certificate validity, default 1\n");
		process.stdout.write(" -o=ORG --org=ORG: Organization, default 'Private'\n");
		process.stdout.write(" -r=BIT --rsa=BIT: RSA Key size, default 4096\n");
		process.stdout.write(" -u=URL --URL=URL: ACME URL, default acme-v01.api.letsencrypt.org/directory\n");
		process.stdout.write(" -v --verbose: Verbose mode\n");
		process.stdout.write(" -w=PATH --web=PATH: Web root, default '.'\n");
		process.stdout.write(" -y --yes: Non-interactive mode\n");
		// callback
		callback();
		// dereference
		callback = null;
	}
}

/**
 * cleanup
 */
function cleanup() {
	// dereference
	acme_client = null;
	AcmeClient = null;
	helper = null;
}

/******************************************************************************
 * Entry point
 *****************************************************************************/

/**
 * main
 */
(function () {
	prepare();
	greeting();
	init(function () {
		exec(cleanup);
	});
})();
