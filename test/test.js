var should = require('should');
var crypto = require('crypto');
var constants = require('constants');
var aesKeygen = require('../build/Release/rsa_keygen.node');

describe("rsa-keygen", function() {
	describe("when generating keys", function() {
		var keys;

		before(function() {
			keys = aesKeygen.generate();
		});

		it("should generate valid keys", function() {
			!!keys.should.be.ok;
		});

		it("should have a public key", function() {
			keys.should.have.property("public_key");
			keys.public_key.should.be.an.instanceOf(Buffer);
		});

		it("should have a private key", function() {
			keys.should.have.property("private_key");
			keys.private_key.should.be.an.instanceOf(Buffer);
		});

		if (crypto.publicEncrypt && crypto.privateDecrypt) {
			describe("when using the private key", function() {
				var plaintext = new Buffer("LOLWTFBBQ");
				var ciphered = null, deciphered = null;

				before(function() {
					ciphered = crypto.publicEncrypt({
						key: keys.public_key,
						padding: constants.RSA_PKCS1_OAEP_PADDING
					}, plaintext);

					deciphered = crypto.privateDecrypt({
						key: keys.private_key,
						padding: constants.RSA_PKCS1_OAEP_PADDING
					}, ciphered);
				});

				it("should be able to encrypt", function() {
					!!ciphered.should.be.ok;
					ciphered.length.should.be.above(0);
				});

				it("should be able to decrypt", function() {
					!!deciphered.should.be.ok;
					deciphered.length.should.be.above(0);
				});

				it("should decrypt correctly", function() {
					deciphered.should.eql(plaintext);
				});
			});
		}
	});
});

