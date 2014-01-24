// TO DO:
// 1) allow bcrypt and/or scrypt in the gen_key() function

var crypto = require('crypto'),
	util = require('util');

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
	var iterations = 262144; // default to 2^18 iterations.  With our slow algorithm, we run out of memory if we go over 1m

	var byte_length = params.byte_length?parseInt(params.byte_length):(params.bit_length?(parseInt(params.bit_length)/8):(keylen/8)); // divide the bit length by 8 to get the byte length we need to feed into randomBytes

	if (params.password) {
		var salt = params.salt?params.salt:crypto.randomBytes(saltlen/8); // divide bit length by 8 to get byte length
		if (params.iterations) iterations = params.iterations;

		// we can generate two complete keys with a single call with sha512, but for single key generation we'd be throwing half the bits away
		var key = _pbkdf2Slow('sha256', params.password, salt, iterations, byte_length);
		// since this is for key generation, this could be thought of as a one time action if we store the resulting key and never need to re-generate it
		// however, since we're using a password, we may want to discard the key and re-generate it each time with a password, we need to know the parameters we used to create it
		// this _gen_key() function is not ideal for this purpose given its synchronous nature, but you could generate the key here and use it elsewhere
		return params.return_params?[(params.raw?key:key.toString('base64')), { salt: (params.raw?salt:salt.toString('base64')), iterations: iterations, keylen: byte_length, algo: 'pbkdf2', hash: 'sha512' }]:(params.raw?key:key.toString('base64'));
	}
	else {
		var key = crypto.randomBytes(byte_length);
		return params.raw?key:key.toString('base64');
	}
};

// pre-format complimentary options for digest/match so that you don't have
// to define options every time you call
function hash(_opts, _hash) {
	var self = this;
	// supported options: [* - relevant to digest] [+ - relevant to match]
	// *+ encoding - the output encoding for the resulting digest, or the encoding expected for the digest we're testing against
	// *  salt - salt to use, or indicating that we want to use a salt
	// *  salt_byte_length - length of salt to generate, in bytes
	// *  salt_bit_length - length of salt to generate, in bits (superseded by byte length, above)
	// *+ salt_char_length - generally speaking, in hex, this number would be half the byte count if you don't want to truncate
	// *+ predelim - delimiter with which to concatenate the salt and the cleartext payload
	// *+ pre_salt_after - determine if the salt should be concatenated before or after the cleartext payload
	// *+ delim - delimiter with which to concatenate the salt and the hashed digest
	// *  concat - return the hash with the salt concatenated without a delimiter if we haven't specified one
	// *  salt_after - determine if the salt should be concatenated before or after the hashed digest

	this._opts = _opts || {};
	// default to sha512
	this._hash = _hash || 'sha512';

	// the purpose of digest() is to create a simple hash for message verification
	// for this purpose, hash security (avoiding collisions) is still important, but the
	// difficulty of the computation is irrelevant, because the payload isn't intended to
	// be secret
	// this is really just a wrapper to abstract away choice of algorithm
	// callback is only relevant if we're using a CSPRNG to salt, but we respect it
	// if it's there in any event
	// callback of the form function(err, hash)
	this.digest = function(payload, opts, callback) {
		if (typeof opts === 'function') callback = opts, opts = {};
		else opts = opts || {};

		for (var key in self._opts) {
			if (!self._opts.hasOwnProperty(key)) continue;
			if (opts[key] !== undefined) {
				var err = new Error("You've attempted to override a global option.");
				if (callback) return setImmediate(function() { callback(err); });
				else return err;
			}
			opts[key] = self._opts[key];
		}

		var digest = crypto.createHash(self._hash);

		// hash output is typically stored in hex format, so that's our default
		// we enforce an encoding because a digest lives to be recorded and passed around
		var encoding = opts.encoding?opts.encoding:'hex';

		if (opts.salt) {

			// by default, there's no internal delimiter before hashing the salt+payload
			var predelim = opts.predelim?opts.predelim:'';
			var saltlen = opts.salt_byte_length?parseInt(opts.salt_byte_length):(opts.salt_bit_length?parseInt(opts.salt_bit_length)/8:16); // default to 128 bits

			if (callback) {
				if (opts.salt === true) {
					crypto.randomBytes(saltlen, function(err, salt) {
						if (err) return callback(err);

						if (opts.salt_char_length) salt = salt.toString(encoding).substr(0, opts.salt_char_length);
						else salt = salt.toString(encoding);

						if (opts.pre_salt_after) digest.write(payload+predelim+salt);
						else digest.write(salt+predelim+payload);
						digest.end();
						
						if (typeof opts.delim === 'string' || (opts.concat && !(opts.delim = ''))) {
							if (opts.salt_after) callback(null, digest.read().toString(encoding)+opts.delim+salt);
							else callback(null, salt+opts.delim+digest.read().toString(encoding));
						}
						else callback(null, [salt, digest.read().toString(encoding)]);
					});
					return;
				}
			}
			else if (opts.salt === true) opts.salt = crypto.randomBytes(saltlen).toString(encoding);

			if (util.isError(opts.salt)) {
				if (callback) return setImmediate(function() { callback(opts.salt); });
				else return opts.salt;
			}

			if (opts.salt_char_length) opts.salt = opts.salt.substr(0, opts.salt_char_length);

			if (opts.pre_salt_after) digest.write(payload+predelim+opts.salt);
			else digest.write(opts.salt+predelim+payload);
			digest.end();

			if (typeof opts.delim === 'string' || (opts.concat && !(opts.delim = ''))) {
				if (opts.salt_after) {
					if (callback) setImmediate(function() { callback(null, digest.read().toString(encoding)+opts.delim+opts.salt); });
					else return digest.read().toString(encoding)+opts.delim+opts.salt;
				}
				else {
					if (callback) setImmediate(function() { callback(null, opts.salt+opts.delim+digest.read().toString(encoding)); });
					else return opts.salt+opts.delim+digest.read().toString(encoding);
				}
			}
			else {
				if (callback) setImmediate(function() { callback(null, [opts.salt, digest.read().toString(encoding)]); });
				else return [opts.salt, digest.read().toString(encoding)];
			}
		}
		else {
			digest.write(payload);
			digest.end();
			if (callback) setImmediate(function() { callback(null, digest.read().toString(encoding)) });
			else return digest.read().toString(encoding);
		}
	};

	// match() is a simple function to match a cleartext payload with a digest()-ed secret,
	// taking into account any salts
	// simple wrapper to verify, optionally with salt
	this.match = function(payload, secret, salt, opts) {
		if (salt !== null && typeof salt === 'object' && !Buffer.isBuffer(salt)) opts = salt, salt = undefined;
		else opts = opts || {};

		for (var key in self._opts) {
			if (!self._opts.hasOwnProperty(key)) continue;
			if (opts[key] !== undefined) {
				var err = new Error("You've attempted to override a global option.");
				if (callback) return setImmediate(function() { callback(err); });
				else return err;
			}
			opts[key] = self._opts[key];
		}

		var digest = crypto.createHash(self._hash);

		// hash output is typically stored in hex format, so that's our default
		// we enforce an encoding because a digest lives to be recorded and passed around
		var encoding = opts.encoding?opts.encoding:'hex';

		if (!salt && ((typeof opts.delim === 'string' && opts.delim) || opts.salt_char_length)) {
			// the salt should be concatenated to the payload, and we've defined some way to split it off:
			// 1) we have a delimiter we can split on
			// 2) we have a defined length to read off and remove

			// we have a delimiter
			if (opts.delim) {
				var parts = secret.split(opts.delim);
				// if we didn't actually find the delimiter, then we only have the hash and no salt
				if (parts.length == 1) salt = '';
				else if (opts.salt_after) {
					secret = parts[0];
					salt = parts[1];
				}
				// if we don't indicate salt after, default to before
				else {
					salt = parts[0];
					secret = parts[1];
				}
			}
			// if we weren't passed a delimiter
			else if (opts.salt_char_length) {
				if (opts.salt_after) {
					salt = secret.substr(-1*opts.salt_char_length);
					secret = secret.substr(0, -1*opts.salt_char_length);
				}
				else {
					salt = secret.substr(0, opts.salt_char_length);
					secret = secret.substr(opts.salt_char_length);
				}
			}
			// otherwise, we have no way to find a salt, so don't worry about it
		}

		salt = salt || '';
		var predelim = opts.predelim?opts.predelim:''; // internal delimiter used *before* hashing (typically none)

		// does the salt come before or after the payload? defaults to before
		if (opts.pre_salt_after) payload += predelim + salt;
		else payload = salt + predelim + payload;

		digest.write(payload);
		digest.end();
		if (opts.constant_time) return constant_time_str_cmp(digest.read().toString(encoding), secret);
		else return digest.read().toString(encoding) === secret;
	};	
};

exports.hash = hash;

// go ahead and export these functions as is, without pre-setting the options
var _hash = new hash();
exports.digest = _hash.digest;
exports.match = _hash.match;

// the purpose of encrypt() is to create a secure one way hash to protect secret data,
// like a password. It must both be cryptographically secure and computationally difficult
// this is really just a wrapper to abstract away the choice of algorithm, and provide some
// sane defaults
// callback of the form function(err, hash) {}
var encrypt = exports.encrypt = function(payload, opts, callback) {
	if (typeof opts === 'function') callback = opts, opts = {};
	else opts = opts || {};

	// we're using scrypt, because we like to sit with the cool kids

	var sparams = { N: null, r: null, p: null }; // the scrypt native parameters, N, r and p

	// 2^18 iterations, min recommended 2^14 (approx .1s), 2^20 for sensetive data (approx 5s), this should be tuned for
	// approximately 1s, which would be not too bad as a worst case user-experience, but a little more forward thinking
	// than the original recommendations, from a few years ago
	sparams.N = 262144; //131072;
	sparams.r = 8; // block size - dictates memory usage
	sparams.p = 1; // parallelization factor - dictates cpu usage

	if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);

	if (opts.params && opts.params.maxtime) {
		if (opts.params.maxmem === undefined) opts.params.maxmem = null;
		if (opts.params.maxmemfrac === undefined) opts.params.maxmemfrac = null;
		if (callback) {
			scrypt.params(opts.params.maxtime, opts.params.maxmem, opts.params.maxmemfrac, function(err, sparams) {
				scrypt.hash(payload, sparams, callback);
			});
		}
		else sparams = scrypt.params(opts.params.maxtime, opts.params.maxmem, opts.params.maxmemfrac);
	}
	else if (opts.params) {
		sparams.N = opts.params.N?opts.params.N:(opts.params.iterations?opts.params.iterations:sparams.N);
		sparams.r = opts.params.r?opts.params.r:(opts.params.block_size?opts.params.block_size:sparams.r);
		sparams.p = opts.params.p?opts.params.p:(opts.params.parallelization?opts.params.parallelization:sparams.p);
	}

	if (callback) scrypt.hash(payload, sparams, callback);
	// return the buffer directly, let the calling app decide what to do with it
	else return scrypt.hash(payload, sparams);
};

// verify() is a simple function to match a cleartext payload with an encrypt()-ed
// secret, taking into account any salts
// this is a fairly straight forward wrapper around the provided verify function
// we don't need to split out the salt or other details, because this is directly
// symmetric with the hash function
var verify = exports.verify = function(payload, secret, opts, callback) {
	if (typeof opts === 'function') callback = opts, opts = {};
	else opts = opts || {};

	if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);
	if (!Buffer.isBuffer(secret)) secret = opts.secret_encoding?new Buffer(secret, opts.secret_encoding):new Buffer(secret);

	if (callback) scrypt.verify(secret, payload, callback);
	else return scrypt.verify(secret, payload);
};

// upgrade_hash() will accept some permutation of the hashing algorithm, attempt to match against
// an old one
// if successful, re-encrypt with the currently accepted hashing algorithm
var upgrade_hash = exports.upgrade_hash = function(payload, secret, salt, hashes) {
	for (var i=0; i<hashes.length; i++) {
		var h = new hash(hashes[i].opts, hashes[i].algorithm);
		if (h.match(payload, secret, salt)) return encrypt(payload);
	}
	return false;
};

// we could lose these and export the generic function directly, and jsut allow the user to
// set the hash through the opts, but the point is to provide as much direction as possible
exports.upgrade_md5 = { algorithm: 'md5', opts: {} };
exports.upgrade_sha1 = { algorithm: 'sha1', opts: {} };
exports.upgrade_magento = { algorithm: 'md5', opts: { salt: true, salt_byte_length: 2, salt_char_length: 2, salt_after: true, delim: ':' } };

// a one stop shop to do symmetric encryption using our "best-practices"
var encipher = exports.encipher = function(payload, key, mackey, opts, cb) {
	if (typeof opts === 'function') cb = opts, opts = {};
	else opts = opts || {};

	var iv_length = 128; // bit length

	// this operates async because we may need to build our own IV from a cryptographically secure source

	// we don't expect this, but if there's a reason to generate the IV outside the application we can allow it
	if (opts.iv) {
		// we should update this to also check to make sure it meets our iv_length
		var iv;
		if (!Buffer.isBuffer(opts.iv)) iv = opts.iv_encoding?new Buffer(opts.iv, opts.iv_encoding):new Buffer(opts.iv);
		else iv = opts.iv;

		if (cb) setImmediate(function() { _encipher(payload, key, mackey, iv, opts, cb); });
		else return _encipher(payload, key, mackey, iv, opts);
	}
	else {
		if (cb) crypto.randomBytes(iv_length/8, function(err, iv) { if (err) return cb(err); _encipher(payload, key, mackey, iv, opts, cb); });
		else {
			var iv = crypto.randomBytes(iv_length/8);
			if (util.isError(iv)) return err;
			else return _encipher(payload, key, mackey, iv, opts);
		}
	}
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
	if (cb) cb(null, [mac, iv, ciphertext]);
	else return [mac, iv, ciphertext];
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
	if (!constant_time_str_cmp(hmac.read().toString(opts.mac_encoding), mac.toString(opts.mac_encoding))) return new Error('Message failed to authenticate');

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

// this is necessary to avoid leaking information about how many characters match in an HMAC
function constant_time_str_cmp(str1, str2) {
	if (str1.length !== str2.length) { return false; }
	var result = 0;
	for (var i = 0; i < str1.length; i++) {
		result |= (str1.charCodeAt(i) ^ str2.charCodeAt(i));
	}
	return result === 0;
}

// this is mostly an academic exercise
// any useful implementation should be accomplished in native C/C++ code as it should be as
// performant as possible so as to not unduely hinder legitimate code beyond the performance
// an attacker will acheive.
// the main use of this code would be for infrequent/manual one-time use to produce a hash
// using a more secure hashing algorithm than the default sha1 supported by node's built in pbkdf2 method
// when speed of producing the key is not important (as in the case of our gen_key function, above)
// for that reason, I've ommitted any asynchronous way of calling this code
// ported from a native PHP implementation
function _pbkdf2Slow(algo, payload, salt, iterations, keylen) {
	// if we're cool with the node default, offload to the crypto built-in
	if (!algo || algo == 'sha1') return crypto.pbkdf2Sync(payload, salt, iterations, keylen);

	if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);
	if (!Buffer.isBuffer(salt)) salt = new Buffer(salt);

	var hash = crypto.createHash(algo);
	hash.write('');
	hash.end();
	var hashlen = hash.read().toString('binary').length; // get the byte length produced by this hash

	// figure out how many blocks we must compute to fill out the requested key length
	var key_blocks = Math.ceil(keylen/hashlen);

	var interim_key, hash;

	for (var block=1; block<=key_blocks; block++) {
		var hmac = crypto.createHmac(algo, payload);
		// initial hash for current block iteration
		var blk = new Buffer(String.fromCharCode(block >> 24 & 0xF)+String.fromCharCode(block >> 16 & 0xF)+String.fromCharCode(block >> 8 & 0xF)+String.fromCharCode(block & 0xF));
		hmac.write(Buffer.concat([salt, blk]));
		hmac.end();
		interim_key = hash = hmac.read();

		// the first iteration is performed with the above initialization
		// this performs the rest of the loops
		for (var i=1; i<iterations; i++) {
			hmac = crypto.createHmac(algo, payload);
			hmac.write(hash);
			hmac.end();
			hash = hmac.read();

			for (var j=0; j<interim_key.length; j++) {
				interim_key[j] ^= hash[j];
			}
		}

		if (derived_key === undefined) var derived_key = new Buffer(interim_key);
		else derived_key = Buffer.concat([derived_key, interim_key]);
	}

	return new Buffer(derived_key.toString('binary').substr(0, keylen), 'binary');
}

// since this provides functionality not otherwise available in node, we'll export it, but
// its use is discouraged
exports._pbkdf2Slow = _pbkdf2Slow;
