/**
 * Mocha test unit: AcmeClient
 * @author Martin Springwald
 * @license MIT
 * @requires assert
 * @requires base64url
 * @requires child_process
 * @requires fs
 * @requires https
 * @requires JWebClient
 * @requires path
 */

/******************************************************************************
 * Imports
 *****************************************************************************/
var assert = require('assert');
var base64url = require('base64url');
var child_process = require('child_process');
var fs = require('fs');
var https = require('https');
var JWebClient = require('../lib/jweb-client.js');
var AcmeClient = require('../lib/acme-client.js');
var path = require('path');

var unit = new AcmeClient("https://www.example.com", new JWebClient());

/******************************************************************************
 * Dummy HTTPS request service
 *****************************************************************************/

function applyHttpsRequest(input, statusCode) {
	var cbs = {};
	var _request = https.request;
	https.request = function (options, callback) {
		options = null;
		var res = {
			on : function (name, cb) {
				cbs[name] = cb;
			},
			statusCode : statusCode,
			headers : {
				"content-type" : "json"
			}
		};
		return {
			on : function () {
				return {
					write : function () {},
					end : function () {
						callback(res);
						cbs.data(new Buffer(input));
						cbs.end();
					}
				};
			}
		};
	};
	return _request;
}

/******************************************************************************
 * UNIT AcmeClient
 *****************************************************************************/
describe('AcmeClient', function () {
	// AcmeClient.getDirectory
	describe('#getDirectory', function () {
		it('makes directory request', function (done) {
			var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
			unit.getDirectory(function (ans) {
				https.request = _request;
				assert.equal(ans instanceof Object, true);
				assert.equal(ans.hello, "world");
				done();
			});
		});
	});
	// AcmeClient.newRegistration
	describe('#newRegistration', function () {
		it('makes new-reg request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				unit.directory = {
					"new-reg" : "https://www.example.com"
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.newRegistration(void 0, function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					unit.jWebClient.key_pair = {};
					unit.directory = {};
					done();
				});
			});
		});
	});
	// AcmeClient.getRegistration
	describe('#getRegistration', function () {
		this.timeout(5000);
		it('makes reg request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				unit.directory = {
					"reg" : "https://www.example.com"
				};
				unit.clientProfilePubKey = {};
				var _request = applyHttpsRequest("{\"hello\":\"world\",\"key\":\"abc\"}", 200);
				unit.getRegistration("https://www.example.com", {}, function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					assert.equal(unit.clientProfilePubKey, "abc");
					unit.jWebClient.key_pair = {};
					unit.directory = {};
					unit.clientProfilePubKey = {};
					done();
				});
			});
		});
	});
	// AcmeClient.authorizeDomain
	describe('#authorizeDomain', function () {
		it('initiates domain authorization', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.authorizeDomain("www.example.com", function (ans) {
					https.request = _request;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.acceptChallenge
	describe('#acceptChallenge', function () {
		it('makes challenge acceptance request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.acceptChallenge({
					uri : "https://www.example.com"
				}, function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.pollUntilValid
	describe('#pollUntilValid', function () {
		it('makes polling request for challenge status', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.pollUntilValid("https://www.example.com", function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.pollUntilIssued
	describe('#pollUntilIssued', function () {
		it('makes polling request for CSR status', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest({}, 404);
				unit.pollUntilIssued("https://www.example.com", function (ans) {
					https.request = _request;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.requestSigning
	describe('#requestSigning', function () {
		it('initiates signing request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.requestSigning("www.example.com", function (ans) {
					https.request = _request;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.getProfile
	describe('#getProfile', function () {
		it('makes profile request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.getProfile(function (ans) {
					https.request = _request;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.createAccount
	describe('#createAccount', function () {
		it('makes new registration request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.createAccount(void 0, function (ans) {
					https.request = _request;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.agreeTos
	describe('#agreeTos', function () {
		this.timeout(5000);
		it('makes TOS agreement request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				unit.clientProfilePubKey = {};
				unit.regLink = "https://www.example.com";
				var _request = applyHttpsRequest("{\"hello\":\"world\",\"key\":\"abc\"}", 200);
				unit.agreeTos("https://www.example.com", function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					assert.equal(unit.clientProfilePubKey, "abc");
					unit.jWebClient.key_pair = {};
					unit.clientProfilePubKey = {};
					unit.regLink = null;
					done();
				});
			});
		});
	});
	// AcmeClient.requestCertificate
	describe('#requestCertificate', function () {
		it('initiates certificate request', function (done) {
			var _exec = child_process.exec;
			child_process.exec = function (command, callback) {
				command = null;
				callback(false);
			};
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err) throw new Error("Key file not found.");
				unit.jWebClient.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.requestCertificate("www.example.com", "Example", "US", function (ans) {
					https.request = _request;
					child_process.exec = _exec;
					assert.equal(ans, false);
					unit.jWebClient.key_pair = {};
					done();
				});
			});
		});
	});
	// AcmeClient.createKeyPair
	describe('#createKeyPair', function () {
		it('creates openssl request for key and csr', function (done) {
			var _exec = child_process.exec;
			child_process.exec = function (command, callback) {
				assert.equal(command, "openssl req -new -nodes -newkey rsa:1024 -sha256 -subj \"/C=C/O=O/CN=CN/emailAddress=E\" -keyout \"CN.key\" -outform der -out \"CN.csr\"");
				callback();
			};
			unit.createKeyPair(1024, "C", "O", "CN", "E", function () {
				child_process.exec = _exec;
				done();
			});
		});
	});
	// AcmeClient.makeSafeFileName
	describe('#makeSafeFileName', function () {
		it('sanitizes value', function () {
			var name = unit.makeSafeFileName("/my/file\"| cat passwd", true);
			assert.equal(name, "/my/file%22%7C cat passwd");
		});
	});
	// AcmeClient.prepareChallenge
	describe('#prepareChallenge', function () {
		it('handles invalid challenge response', function (done) {
			unit.prepareChallenge("www.example.com", void 0, function () {
				done();
			});
		});
	});
	// AcmeClient.getTosLink
	describe('#getTosLink', function () {
		it('extracts TOS link from header value', function () {
			var toslink = unit.getTosLink("<https://www.example.com>;rel=\"terms-of-service\"");
			assert.equal(toslink, "https://www.example.com");
		});
	});
	// AcmeClient.selectChallenge
	describe('#selectChallenge', function () {
		it('selects challenge by type', function () {
			var challenge1 = {
				type : "test1",
				value : "test1"
			};
			var challenge2 = {
				type : "test2",
				value : "test2"
			};
			var challenge = unit.selectChallenge({
					"challenges" : [challenge1, challenge2]
				}, "test2");
			assert.equal(challenge, challenge2);
		});
	});
	// AcmeClient.extractEmail
	describe('#extractEmail', function () {
		it('extracts email address from profile', function () {
			var email = unit.extractEmail({
					"contact" : ["tel:+1234", null, "mailto:info@example.com"]
				});
			assert.equal(email, "info@example.com");
		});
	});
	// AcmeClient.makeDomainAuthorizationRequest
	describe('#makeDomainAuthorizationRequest', function () {
		it('creates domain authorization request', function () {
			var dar = unit.makeDomainAuthorizationRequest("www.example.com");
			assert.equal(dar instanceof Object, true);
			assert.equal(dar.resource, "new-authz");
			assert.equal(dar.identifier instanceof Object, true);
			assert.equal(dar.identifier.type, "dns");
			assert.equal(dar.identifier.value, "www.example.com");
		});
	});
	// AcmeClient.makeKeyAuthorization
	describe('#makeKeyAuthorization', function () {
		it('creates key authorization value', function () {
			unit.clientProfilePubKey = {
				e : "d",
				kty : "e",
				n : "f"
			};
			var key_auth = unit.makeKeyAuthorization({
					token : "abc"
				});
			assert.equal(typeof key_auth, "string");
			var parts = key_auth.split(".");
			assert.equal(parts.length, 2);
			assert.equal(parts[0], "abc");
			assert.equal(typeof parts[1], "string");
			unit.clientProfilePubKey = {};
		});
	});
	// AcmeClient.makeChallengeResponse
	describe('#makeChallengeResponse', function () {
		it('creates challenge response', function () {
			var cr = unit.makeChallengeResponse({});
			assert.equal(cr instanceof Object, true);
			assert.equal(cr.resource, "challenge");
			assert.equal(typeof cr.keyAuthorization, "string");
		});
	});
	// AcmeClient.makeCertRequest
	describe('#makeCertRequest', function () {
		it('creates CSR', function () {
			var csr = unit.makeCertRequest("Hello World!", 1);
			assert.equal(csr instanceof Object, true);
			assert.equal(csr.resource, "new-cert");
			assert.equal(csr.csr, base64url.encode("Hello World!"));
		});
	});
});
