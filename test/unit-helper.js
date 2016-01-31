/**
 * Mocha test unit: AcmeHelper
 * @author Martin Springwald
 * @license MIT
 * @requires assert
 * @requires fs
 * @requires path
 * @requires AcmeHelper
 */
 
 /******************************************************************************
 * Imports
 *****************************************************************************/
var assert = require('assert');
var child_process = require('child_process');
var fs = require('fs');
var path = require('path');
var unit = require('../lib/acme-helper.js');

 /******************************************************************************
 * UNIT AcmeHelper
 *****************************************************************************/
describe('AcmeHelper', function () {
	// AcmeHelper.processOptions
	describe('#processOptions', function () {
		it('correctly splits options', function () {
			var expected = [{
					key : "-a",
					value : "b"
				}, {
					key : "--c",
					value : "d"
				}, {
					key : "e",
					value : "f"
				}, {
					key : "g",
					value : "g"
				}
			];
			var input = ["-a=b", "--c=d", "e=f", "g"];
			var _argv = process.argv;
			process.argv = input;
			unit.processOptions(function (key, value) {
				var _expected = expected.shift();
				assert.equal(key, _expected.key);
				assert.equal(value, _expected.value);
			});
			process.argv = _argv;
		});
	});
	// AcmeHelper.createUserKeyPair
	describe('#createUserKeyPair', function () {
		this.timeout(2500);
		it('generates key pair', function (done) {
			var _exec = child_process.exec;
			child_process.exec = function(command, callback) {
				assert.equal(command, "openssl genrsa 1024 > \"test.private.key\"");
				callback();
			};
			unit.createUserKeyPair(1024, "test.private.key", function () {
				child_process.exec = _exec;
				done();
			});
		});
	});
	// AcmeHelper.getUserKeyPair
	describe('#getUserKeyPair', function () {
		this.timeout(5000);
		it('reads and interprets key file', function (done) {
			unit.getUserKeyPair(path.dirname(__filename)+"/test.private.key", function (key_pair) {
				if (!(
					(key_pair instanceof Object) &&
					(typeof key_pair.private_pem == "string") &&
					(key_pair.public_jwk instanceof Object))
				) {
					throw new Error("Invalid key pair.");
				}
				done();
			});
		}, true);
	});
	// AcmeHelper.makeAcmePath
	describe('#makeAcmePath', function () {
		it('creates proper path', function (done) {
			fs.mkdir("test.unit-helper.root", function () {
				unit.makeAcmePath("test.unit-helper.root", function (result) {
					assert.equal(result, true);
					fs.rmdir("test.unit-helper.root/.well-known/acme-challenge", function () {
						fs.rmdir("test.unit-helper.root/.well-known", function () {
							fs.rmdir("test.unit-helper.root", function () {
								done();
							});
						});
					});
				});
			});
		});
	});
});
