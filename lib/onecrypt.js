// TO DO:
// 1) allow bcrypt and/or scrypt in the gen_key() function
// 2) allow using pbkdf2 with stronger algorithms than sha1

var crypto = require('crypto');

var bcrypt = require('bcrypt'),
	scrypt = require('scrypt');

// gen_key() is intended for manual use to generate a properly secure encryption key on
// the command line.  It's entirely synchronous and not built for high volume use
var gen_key = exports.gen_key = function(params) {
	params = params || {};
	if (params.safe) {
		// we don't want to throw an error under any circumstance.
		try { return _gen_key(params); }
		catch (err) { return null; }
	}
	else return _gen_key(params);
};

// extract the functional elements of key generation so we can optionally try/catch without a bunch of code duplication
var _gen_key = function(params) {
	// defaults
	// the resulting keylength, in bits
	var keylen = 256; // 256 bits
	// the following are only relevant to deriving a key from a password
	var saltlen = 128; // 128 bits
	var iterations = 1048576; // default to 2^20 iterations

	var byte_length = params.byte_length?parseInt(params.byte_length):(params.bit_length?(parseInt(params.bit_length)/8):(keylen/8)); // divide the bit length by 8 to get the byte length we need to feed into randomBytes

	if (params.password) {
		var salt = params.salt?params.salt:crypto.randomBytes(saltlen/8); // divide bit length by 8 to get byte length
		if (params.iterations) iterations = params.iterations;

		var key = crypto.pbkdf2Sync(params.password, salt, iterations, byte_length);
		// since this is for key generation, this could be thought of as a one time action if we store the resulting key and never need to re-generate it
		// however, since we're using a password, we may want to discard the key and re-generate it each time with a password, we need to know the parameters we used to create it
		// this _gen_key() function is not ideal for this purpose given its synchronous nature, but you could generate the key here and use it elsewhere
		return params.return_params?[(params.raw?key:key.toString('base64')), { salt: (params.raw?salt:salt.toString('base64')), iterations: iterations, keylen: byte_length, algo: 'pbkdf2', hash: 'hmac-sha1' }]:(params.raw?key:key.toString('base64'));
	}
	else {
		var key = crypto.randomBytes(byte_length);
		return params.raw?key:key.toString('base64');
	}
};

// the purpose of digest() is to create a simple hash for message verification
// for this purpose, hash security is still important, but the difficulty
// of the computation is irrelevant, because the payload isn't intended to be secret
/*var digest = exports.digest = function(payload) {
};*/

// match() is a simple function to match a cleartext payload with a digest()-ed secret,
// taking into account any salts
/*var match = exports.match = function(payload, secret, salt) {
};*/

// the purpose of encrypt() is to create a secure one way hash to protect secret data,
// like a password. It must both be cryptographically secure and computationally difficult
/*var encrypt = exports.encrypt = function(payload) {
};*/

// verify() is a simple function to match a cleartext payload with an encrypt()-ed
// secret, taking into account any salts
/*var verify = exports.verify = function(payload, secret, salt) {
};*/

// upgrade_hash() will accept old hashing algorithms, attempt to match against an old one, and
// if successful, re-encrypt with the currently accepted hashing algorithm
// DANGER: maintain tight control over `hashes`, you don't want to open yourself up to:
// function() { return true; }
/*var upgrade_hash = exports.upgrade_hash = function(payload, secret, salt, hashes) {
	for (var i=0; i<hashes.length; i++) {
		if (hashes[i](payload, secret, salt)) return encrypt(payload);
	}
	return false;
};*/

// a list of safe, configurable hash comparison functions usable by upgrade_hash() that can be passed in, rather than making the user write their own: md5, sha1
// our simple generic hash validator will take any available hashing algorithm, optionally with a salt, and run it for one iteration to check against a payload
var _generic_simple = function(opts, hash) {
	return function(payload, secret, salt) {
		var digest = crypto.createHash(hash);
		// defininig these as a properties of the function allows us to more easily pass in potential position variations
		this.salt = salt;
		this.hash = secret;
		var predelim = opts.predelim?opts.predelim:''; // internal delimiter used *before* hashing (typically none)
		var encoding = opts.encoding?opts.encoding:'hex'; // digest typically uses hex encoding

		if (this.salt == undefined && !opts.nosalt) {
			// if we were not explicitly passed salt information into our function, and we've not explicitly said to
			// ignore salt, then we'll need to attempt to retreive it from our hash

			if (opts.delim) { // the salt and hash are attached by a delimiter
				var parts = this.hash.split(opts.delim);
				// if we didn't actually find the delimiter, then we only have the hash and no salt
				if (parts.length == 1) this.salt = '';
 				// the full positions array allows us to define any number of informational elements that could be contained in the hash, but digest can use at most 2: salt & hash
				else if (opts.positions) {
					for (var i=0; i<opts.positions; i++) {
						// should we have passed in more positions than are relevant to digest, just ignore
						// this will mean that it's broken if salt or hash aren't the first two positions defined
						this[opts.positions[i]] = parts[i]?parts[i]:'';
					}
				}
				else if (opts.salt_after) {
					this.hash = parts[0];
					this.salt = parts[1];
				}
				// if we don't explicitly indicate all positions, or indicate salt after, default to before
				else {
					this.salt = parts[0];
					this.hash = parts[1];
				}
			}
			// if we weren't passed a delimiter
			else if (opts.positions) {
				var start = 0;
				for (var i=0; i<opts.positions.length; i++) {
					// it's slightly different when we're not using a delimiter, we need each position to have a field and a length so we can pull them out
					// we use the secret that was passed in, so that when we overwrite this.hash it won't mess us up
					this[opts.positions[i].field] = secret.substr(start, opts.positions[i].len);
					start += opts.positions[i].len;
				}
			}
			// otherwise, we have no way to find a salt, so don't worry about it
		}
		if (!this.salt) this.salt = ''; // make sure we're dealing with a string rather than undefined or null
		if (this.salt === true) this.salt = ''; // if we passed in boolean true, then we're explicitly saying there's no salt

		// does the salt come before or after the payload?  defaults to before
		if (opts.salt_after) payload += predelim + this.salt;
		else payload = this.salt + predelim + payload;

		digest.write(payload);
		digest.end();
		if (digest.read().toString(encoding) == this.hash) return true;

		// if we get here, it didn't match
		return false;
	};
}
/*var md5_upgrade = exports.md5_upgrade = function(opts) {
	return _generic_simple(opts, 'md5');
};

var sha1_upgrade = exports.sha1_upgrade = function(opts) {
	return _generic_simple(opts, 'sha1');
};
*/

// a one stop shop to do symmetric encryption using our "best-practices"
var encipher = exports.encipher = function(payload, key, mackey, opts, cb) {
	opts = opts || {};

	var iv_length = 128; // bit length

	// this operates async because we may need to build our own IV from a cryptographically secure source

	// we don't expect this, but if there's a reason to generate the IV outside the application we can allow it
	if (opts.iv) {
		// we should update this to also check to make sure it meets our iv_length
		var iv;
		if (!Buffer.isBuffer(opts.iv)) iv = opts.iv_encoding?new Buffer(opts.iv, opts.iv_encoding):new Buffer(opts.iv);
		else iv = opts.iv;

		setImmediate(function() { _encipher(payload, key, mackey, iv, opts, cb); });
	}
	else crypto.randomBytes(iv_length/8, function(err, iv) { if (err) cb(err); _encipher(payload, key, mackey, iv, opts, cb); });
};

// we have to do this assymmetrically with a callback so that we can properly handle creating a random IV at runtime
var _encipher = function(payload, key, mackey, iv, opts, cb) {
	// for now, force the cipher used and mode
	opts.algorithm = 'aes-256';
	opts.mode = 'ctr';
	opts.hmac_algo = 'sha512';

	if (!Buffer.isBuffer(payload)) payload = opts.payload_encoding?new Buffer(payload, opts.payload_encoding):new Buffer(payload);
	if (!Buffer.isBuffer(key)) key = opts.key_encoding?new Buffer(key, opts.key_encoding):new Buffer(key);
	if (!Buffer.isBuffer(mackey)) mackey = opts.mackey_encoding?new Buffer(mackey, opts.mackey_encoding):new Buffer(mackey);

	var cipher = crypto.createCipheriv(opts.algorithm+'-'+opts.mode, key, iv);
	cipher.write(payload);
	cipher.end();
	var ciphertext = cipher.read();

	var hmac = crypto.createHmac(opts.hmac_algo, mackey);
	hmac.write(iv);
	hmac.write(ciphertext);
	hmac.end();
	var mac = hmac.read();

	// send all of the public data needed to decrypt the message, the calling application can handle how they're packaged together
	cb(null, mac, iv, ciphertext);
};

// a one stop shop to do symmetric decryption using our "best-practices"
var decipher = exports.decipher = function(payload, key, mackey, mac, iv, opts) {
	opts = opts || {};

	// we pass in the pieces individually, the calling application manages how the iv and mac are packaged together
	// for now, force the cipher used and mode
	opts.algorithm = 'aes-256';
	opts.mode = 'ctr';
	opts.hmac_algo = 'sha512';

	if (!Buffer.isBuffer(payload)) payload = opts.payload_encoding?new Buffer(payload, opts.payload_encoding):new Buffer(payload);
	if (!Buffer.isBuffer(key)) key = opts.key_encoding?new Buffer(key, opts.key_encoding):new Buffer(key);
	if (!Buffer.isBuffer(mackey)) mackey = opts.mackey_encoding?new Buffer(mackey, opts.mackey_encoding):new Buffer(mackey);
	if (!Buffer.isBuffer(iv)) iv = opts.iv_encoding?new Buffer(iv, opts.iv_encoding):new Buffer(iv);
	if (!Buffer.isBuffer(mac)) mac = opts.mac_encoding?new Buffer(mac, opts.mac_encoding):new Buffer(mac);

	var hmac = crypto.createHmac(opts.hmac_algo, mackey);
	hmac.write(iv);
	hmac.write(payload);
	hmac.end();
	// if we haven't authenticated, then we've got a problem
	if (hmac.read().toString(opts.mac_encoding) !== mac.toString(opts.mac_encoding)) return new Error('Message failed to authenticate');

	var decipher = crypto.createDecipheriv(opts.algorithm+'-'+opts.mode, key, iv);
	decipher.write(payload);
	decipher.end();
	var plaintext = decipher.read();
	return plaintext; // return a raw buffer of our decrypted text
};

// a one stop shop to do assymmetric encryption with the private key using our "best-practices"
/*var sign = exports.sign = function(payload, key) {
};*/

// a one stop shop to do assymmetric decryption with the public key using our "best-practices"
/*var verify_signature = exports.verify_signature = function(payload, key) {
};*/

// a one stop shop to do assymmetric encryption with the public key using our "best-practices"
/*var your_eyes_only = exports.your_eyes_only = function(payload, key) {
};*/

// a one stop shop to do assymmetric decryption with the private key using our "best-practices"
/*var my_eyes_only = exports.my_eyes_only = function(payload, key) {
};*/

// this supersedes nodes pbkdf2 implementation, just so we can specify our chosen algorithm.
// if we do not specify, we should default to the built in method
// this code is non-functional at the moment, it should not be used
// in particular the key length appears to be wrong, and it's altogether producing the wrong output when using sha1 vs the built in method
function _pbkdf2(algo, payload, salt, iterations, keylen, callback) {
	//if (!algo || algo == 'sha1') return crypto.pbkdf2(payload, salt, iterations, keylen, callback);

	if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);
	if (!Buffer.isBuffer(salt)) salt = new Buffer(salt);

	var hash = crypto.createHash(algo);
	hash.write('');
	hash.end();
	var hashlen = hash.read().toString('binary').length; // get the byte length produced by this hash

	// figure out how many blocks we must compute to fill out the requested key length
	var key_blocks = Math.ceil(keylen/hashlen);
	var derived_key = new Buffer('');

	var interim_key, hash;

	// this really needs to be async, but for now just get it working synchronously
	for (var block=1; block<=key_blocks; block++) {
		var hmac = crypto.createHmac(algo, payload);
		// initial hash for current block iteration
		hmac.write(salt+String.fromCharCode(block));
		hmac.end();
		interim_key = hash = hmac.read();

		for (var i=1; i<=iterations; i++) {
			hmac = crypto.createHmac(algo, payload);
			hmac.write(hash);
			hmac.end();
			hash = hmac.read();

			for (var j=0; j<interim_key.length; j++) {
				interim_key[j] ^= hash[j];
			}
		}

		derived_key = Buffer.concat([derived_key, interim_key]);
	}

	// Return derived key of correct length
	if (callback) setImmediate(function() { callback(null, new Buffer(derived_key.toString('binary').substr(0, keylen))); });
	else return new Buffer(derived_key.toString('binary').substr(0, keylen));
}

// just for testing purposes
//exports._pbkdf2 = _pbkdf2;