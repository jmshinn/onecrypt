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

		var key = _pbkdf2Slow('sha512', params.password, salt, iterations, byte_length);
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

// the purpose of digest() is to create a simple hash for message verification
// for this purpose, hash security (avoiding collisions) is still important, but the
// difficulty of the computation is irrelevant, because the payload isn't intended to
// be secret
// this is really just a wrapper to abstract away choice of algorithm
// callback is only relevant if we're using a CSPRNG to salt, but we respect it
// if it's there in any event
// callback of the form function(err, hash)
var digest = exports.digest = function(payload, opts, callback) {
	if (typeof opts === 'function') callback = opts, opts = {};
	else opts = opts || {};

	var digest = crypto.createHash('sha512');

	// hash output is typically stored in hex format, so that's our default
	// we enforce an encoding because a digest lives to be recorded and passed around
	var encoding = opts.encoding?opts.encoding:'hex';

	if (opts.salt) {
		if (callback) {
			if (opts.salt === true) {
				var saltlen = opts.salt_byte_length?parseInt(opts.salt_byte_length):(opts.salt_bit_length?parseInt(opts.salt_bit_length)/8:16); // default to 128 bits
				crypto.randomBytes(saltlen, function(err, salt) {
					if (err) return callback(err);
					digest.write(salt.toString('base64')+payload);
					digest.end();
					if ((opts.delim !== null && opts.delim !== undefined) || (opts.concat && !(opts.delim = opts.delim || ''))) callback(null, salt+opts.delim+digest.read().toString(encoding));
					else callback(null, [salt, digest.read().toString(encoding)]);
				});
				return;
			}
		}
		else if (opts.salt === true) opts.salt = crypto.randomBytes(saltlen).toString('base64');

		if (util.isError(opts.salt)) {
			if (callback) return callback(opts.salt);
			else return opts.salt;
		}

		digest.write(opts.salt+payload);
		digest.end();
		if ((opts.delim !== null && opts.delim !== undefined) || (opts.concat && !(opts.delim = opts.delim || ''))) {
			if (callback) setImmediate(function() { callback(null, salt+opts.delim+digest.read().toString(encoding)); });
			else return salt+opts.delim+digest.read().toString(encoding);
		}
		else {
			if (callback) setImmediate(function() { callback(null, [salt, digest.read().toString(encoding)]); });
			else return [salt, digest.read().toString(encoding)];
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
var match = exports.match = function(payload, secret, salt, opts) {
	opts = opts || {};

	var digest = crypto.createHash('sha512');

	var encoding = opts.encoding?opts.encoding:'hex';
};

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

// upgrade_hash() will accept old hashing algorithms, attempt to match against an old one, and
// if successful, re-encrypt with the currently accepted hashing algorithm
// DANGER: maintain tight control over `hashes`, you don't want to open yourself up to:
// function() { return true; }
var upgrade_hash = exports.upgrade_hash = function(payload, secret, salt, hashes) {
	for (var i=0; i<hashes.length; i++) {
		if (hashes[i](payload, secret, salt)) return encrypt(payload);
	}
	return false;
};

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

		// does the salt come before or after the payload? defaults to before
		if (opts.salt_after) payload += predelim + this.salt;
		else payload = this.salt + predelim + payload;

		digest.write(payload);
		digest.end();
		if (digest.read().toString(encoding) == this.hash) return true;

		// if we get here, it didn't match
		return false;
	};
};
// we could lose these and export the generic function directly, and jsut allow the user to
// set the hash through the opts, but the point is to provide as much direction as possible
var md5_upgrade = exports.md5_upgrade = function(opts) {
	return _generic_simple(opts, 'md5');
};
var sha1_upgrade = exports.sha1_upgrade = function(opts) {
	return _generic_simple(opts, 'sha1');
};

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
// using a more secure algorithm than the default sha1 supported by node's built in pbkdf2 method
// when speed of producing the key is not important
// for that reason, I've ommitted any asynchronous way of calling this code
// ported from a native PHP implementation
function _pbkdf2Slow(algo, payload, salt, iterations, keylen) {
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

	// this really needs to be async, but for now just get it working synchronously
	for (var block=1; block<=key_blocks; block++) {
		var hmac = crypto.createHmac(algo, payload);
		// initial hash for current block iteration
		var blk = new Buffer(String.fromCharCode(block >> 24 & 0xF)+String.fromCharCode(block >> 16 & 0xF)+String.fromCharCode(block >> 8 & 0xF)+String.fromCharCode(block & 0xF));
		hmac.write(Buffer.concat([salt, blk]));
		hmac.end();
		interim_key = hash = hmac.read();

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

// just for testing purposes
// for the time being, we're not exporting this code for anyone else to use, since it has so many caveats
//exports._pbkdf2Slow = _pbkdf2Slow;
