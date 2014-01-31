var crypto = require('crypto');

var onecrypt = require('../lib/onecrypt');

var key;
var mackey;

var password = 'this is my password. there are many like it, but this one is mine';
var message = "this is my message. it's so dumb";

exports.keygen = {
	"default": function (test) {
		test.expect(2);
		// we initialize these keys for later use
		key = new Buffer(onecrypt.gen_key(), 'base64');
		mackey = onecrypt.gen_key();
		
		test.equal(key.length, 32, 'generate a key of proper byte length');
		test.notEqual(key.toString('base64'), mackey, 'test that subsequent keys are not equal');
		
		test.done();
	},
	password: function (test) {
		test.expect(2);
		// default iterations times out
		var key1 = new Buffer(onecrypt.gen_key({ password: password, iterations: 10000 }), 'base64');
		var key2 = onecrypt.gen_key({ password: password, iterations: 10000 });
		
		test.equal(key1.length, 32, 'generate a key from a password of proper byte length');
		test.notEqual(key1.toString('base64'), key2, 'test that subsequent keys with the same password use a different salt');
		
		test.done();
	}
};
exports.symmetric = {
	encrypt_decrypt: function (test) {
		test.expect(5);

		var result1 = onecrypt.encipher(message, key, mackey);
		var result2 = onecrypt.encipher(message, key, mackey);

		test.notEqual(result1[0].toString('base64'), result2[0].toString('base64'), 'The mac should be different');
		test.notEqual(result1[1].toString('base64'), result2[1].toString('base64'), 'the iv should be different');
		test.notEqual(result1[2].toString('base64'), result2[2].toString('base64'), 'the ciphertext should be different');

		var plain1 = onecrypt.decipher(result1[2], key, mackey, result1[0], result1[1]);
		var plain2 = onecrypt.decipher(result2[2], key, mackey, result2[0], result2[1]);

		test.equal(message, plain1.toString());
		test.equal(message, plain2.toString());

		test.done();
	}
};

exports.kdfs = {
	default_kdf: function (test) {
		test.expect(7);

		var passSync = onecrypt.encrypt(password);
		var resultSync = onecrypt.verify(password, passSync);
		test.ok(resultSync, 'we successfully verified our password against the hash. simple');

		var ctr = 0;

		onecrypt.encrypt(password, function(err, pass) {
			// ignore any error
			test.notEqual(password, pass.toString(), 'confirm that these are actually different');
			test.equal(++ctr, 2, 'async2');
			onecrypt.verify(password, pass, function(err, result) {
				// ignore any error
				test.ok(result);
				test.equal(++ctr, 4, 'async4');
				test.done();
			});
			test.equal(++ctr, 3, 'async3');
		});
		test.equal(++ctr, 1, 'async1');
	},
	stable_verify: function (test) {
		test.expect(1);

		onecrypt.encrypt(password, function(err, pass) {
			onecrypt.verify_stable(password, pass, function(err, result) {
				// no matter how we change the default kdf, even switching to a different algorithm, this function will match anything
				// we've encrypted with the default `encrypt()`
				// scrypt automatically supports this functionality, out of the box.
				test.ok(result, 'this should always be true');
				test.done();
			});
		});
	},
	stable_upgrade: function (test) {
		var v1defaults = { params: { N: 262144, r: 8, p: 1 } };
		onecrypt.encrypt(password, v1defaults, function(err, pass) {
			onecrypt.verify_stable(password, pass, { upgrade: true }, function(err, result) {
				if (onecrypt.verify_stable.version > 1) {
					test.expect(2);
					test.notStrictEqual(result, true, 'the result should never be boolean true');
					test.ok(Buffer.isBuffer(result), 'this should be the upgraded hash');
				}
				else {
					test.expect(1);
					test.ok(result, 'this should match exactly');
				}
				test.done();
			});
		});
	},
	// these are simple checks to make sure we've properly set up the encrypt/verify pairs in the case of each kdf
	bcrypt_kdf: function (test) {
		test.expect(1);

		var kdf = new onecrypt.kdf(null, 'bcrypt');

		kdf.encrypt(password, function(err, pass) {
			kdf.verify(password, pass, function(err, result) {
				test.ok(result);
				test.done();
			});
		});
	},
	pbkdf2_kdf: function (test) {
		test.expect(1);

		var kdf = new onecrypt.kdf(null, 'pbkdf2');

		kdf.encrypt(password, function(err, pass) {
			kdf.verify(password, pass, function(err, result) {
				test.ok(result);
				test.done();
			});
		});
	},
	scrypt_kdf: function (test) {
		// this should be the default, so we'll test not just against the generated method, but the default as well
		test.expect(3);

		var kdf = new onecrypt.kdf(null, 'scrypt');

		var pass1 = kdf.encrypt(password);
		var result1 = kdf.verify(password, pass1);
		test.ok(result1);
		var result2 = onecrypt.verify(password, pass1);
		test.ok(result2);
		var pass2 = onecrypt.encrypt(password);
		var result3 = kdf.verify(password, pass2);
		test.ok(result3);

		test.done();
	},
	/*
	tests for the kdfs using the module to encrypt and onecrypt to verify, and vice versa
	*/
	/*
	tests for the kdfs with different options
	*/
	// just verify that our function produces the same output as the built in
	internal_pbkdf2: function (test) {
		test.expect(1);

		var salt = crypto.randomBytes(16);
		var iterations = 10000; // use 10000 iterations, because our slow algorithm chokes on much more than that unless used in specific scenarios
		var byte_length = 32;
		var pass1 = onecrypt._pbkdf2Slow('sha1-onecrypt', password, salt, iterations, byte_length);
		var pass2 = crypto.pbkdf2Sync(password, salt, iterations, byte_length);

		test.equal(pass1.toString('base64'), pass2.toString('base64'), 'our algorithm should produce the same output as the built-in provided the same input');

		test.done();
	}
};

exports.hashes = {
	default_hash_message: function (test) {
		test.expect(1);

		var digestSync = onecrypt.digest(message);
		var resultSync = onecrypt.match(message, digestSync);
		test.ok(resultSync, 'we successfully verified our password against the hash. simple');

		test.done();
	},
	// these are simple checks to make sure we've properly set up the digest/match pairs
	buncha_hashes_message: function (test) {
		var hashes = ['md5', 'sha1', 'sha256', 'whirlpool'];
		test.expect(hashes.length*2-1);

		var hash, digest, result;
		var last_digest;

		for (var i=0; i<hashes.length; i++) {
			hash = new onecrypt.hash(null, hashes[i]);

			// there's no reason to do this asynchronously because we haven't requested to generate a salt
			digest = hash.digest(message);
			if (last_digest) test.notEqual(last_digest, digest, 'the different algorithm should produce a different output');
			last_digest = digest;

			result = hash.match(message, digest);

			test.ok(result, 'our digest/match pair successfully worked together');
		}

		test.done();
	},
	magento_style_password: function (test) {
		test.expect(2);

		// magento hashes the password with md5 with a two character hash, which is appended to the password with a colon delimiter
		// we need to specify both a byte length for the salt, so we can generate it, and a character length, in case the bytes resolve
		// to more than 2 characters
		// the default encoding is already hex, but make it explicit lest our default should change
		// technically, with salt generation, we could/should be doing this asynchronously, but I can't be bothered to make an md5 hash
		// all that efficient
		var mag = new onecrypt.hash({ salt: true, salt_byte_length: 2, salt_char_length: 2, salt_after: true, delim: ':', encoding: 'hex' }, 'md5');
		var pass = mag.digest(password);
		test.ok(pass.match(/^[a-fA-F0-9]{32}:[a-fA-F0-9]{2}$/), 'hexadecimal with two character salt appended');
		var result = mag.match(password, pass);
		test.ok(result, 'we matched with our matched matcher');

		test.done();
	},
	sha1_w_6char_salt_password: function (test) {
		test.expect(4);

		var sha1 = new onecrypt.hash({ salt: true, salt_byte_length: 6, salt_char_length: 6, delim: '$' }, 'sha1');

		var pass = sha1.digest(password);
		test.ok(pass.match(/^[a-fA-F0-9]{6}\$[a-fA-F0-9]{40}$/), 'hexadecimal with 6 character salt prepended');
		var result = sha1.match(password, pass);
		test.ok(result, 'we matched with our matched matcher');

		sha1 = new onecrypt.hash({ salt: true, salt_byte_length: 6, salt_char_length: 6, concat: true }, 'sha1');
		pass = sha1.digest(password);
		test.ok(pass.match(/^[a-fA-F0-9]{46}$/), 'hexadecimal with 6 character salt prepended, no delimiter');
		result = sha1.match(password, pass);
		test.ok(result, 'we matched, with our matched matcher knowing how to pull off the salted bits');

		test.done();
	},
	upgrade_digest_to_encrypt_password: function (test) {
		test.expect(3);

		// we've provided a convenience definition for certain common hashes
		var mag = new onecrypt.hash(onecrypt.upgrade_magento.opts, onecrypt.upgrade_magento.algorithm);
		var pass = mag.digest(password);

		var result = onecrypt.upgrade_hash(password, pass, [mag]);
		test.notStrictEqual(result, false, 'we should not get boolean false');
		test.notStrictEqual(result, true, 'we should not get boolean true');

		var result1 = onecrypt.verify(password, result, function(err, result2) {
			test.strictEqual(result2, true);
			test.done();
		});
	}
};