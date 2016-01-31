/**
 * Mocha test unit: JWebClient
 * @author Martin Springwald
 * @license MIT
 * @requires assert
 * @requires base64url
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
var fs = require('fs');
var https = require('https');
var JWebClient = require('../lib/jweb-client.js');
var path = require('path');

var unit = new JWebClient();

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
 * UNIT JWebClient
 *****************************************************************************/
describe('JWebClient', function () {
	// JWebClient.createJWT
	describe('#createJWT', function () {
		it('creates valid JWT', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err)
					throw new Error("Key file not found.");
				var jwt = unit.createJWT(void 0, {
						"hello" : "world"
					}, "RS256", test_key.toString(), {});
				assert.equal(typeof jwt, "string");
				var parts = jwt.split(".");
				assert.equal(parts.length, 3);
				var part1 = parts.shift();
				assert.equal(typeof part1, "string");
				var part1_decoded = base64url.decode(part1);
				assert.equal(typeof part1_decoded, "string");
				var part2 = parts.shift();
				assert.equal(typeof part2, "string");
				var part2_decoded = base64url.decode(part2);
				assert.equal(typeof part2_decoded, "string");
				var part2_json = JSON.parse(part2_decoded);
				assert.equal(part2_json.hello, "world");
				var part3 = parts.shift();
				assert.equal(typeof part3, "string");
				var part3_decoded = base64url.decode(part3);
				assert.equal(typeof part3_decoded, "string");
				done();
			});
		});
	});
	// JWebClient.request
	describe('#request', function () {
		it('sends request and interpretes result', function (done) {
			var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
			unit.request("https://www.example.com", {}, function (ans) {
				https.request = _request;
				assert.equal(ans instanceof Object, true);
				assert.equal(ans.hello, "world");
				done();
			});
		});
	});
	// JWebClient.get
	describe('#get', function () {
		it('sends get request', function (done) {
			var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
			unit.get("https://www.example.com", function (ans) {
				https.request = _request;
				assert.equal(ans instanceof Object, true);
				assert.equal(ans.hello, "world");
				done();
			});
		});
	});
	// JWebClient.post
	describe('#post', function () {
		it('sends post request', function (done) {
			fs.readFile(path.dirname(__filename) + path.sep + "test.private.key", function (err, test_key) {
				if (err)
					throw new Error("Key file not found.");
				unit.key_pair = {
					private_pem : test_key.toString(),
					public_jwk : {}
				};
				var _request = applyHttpsRequest("{\"hello\":\"world\"}", 200);
				unit.post("https://www.example.com", {}, function (ans) {
					https.request = _request;
					assert.equal(ans instanceof Object, true);
					assert.equal(ans.hello, "world");
					unit.key_pair = {};
					done();
				});
			});
		});
	});
});
