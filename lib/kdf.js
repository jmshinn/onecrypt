var crypto = require('crypto'),
	util = require('util');

var bcrypt = require('bcrypt'),
	scrypt = require('scrypt');

var fn = require('./fn');

// pre-format complimentary options for encrypt/verify so that you don't have
// to define options every time you call
function kdf(_opts, _kdf) {
	var self = this;
	// supported options: [* - relevant to encrypt] [+ - relevant to verify]

	// default to options appropriate for key derivation
	this._opts = _opts || { delim: '$', constant_time: true }; // these defaults should only be relevant to pbkdf2, but they should mostly agree with the other functions
	// default to scrypt, because we like to sit with the cool kids
	this._kdf = _kdf || 'scrypt';

	// since each choice of key derivation function requires significantly different options and
	// functions significantly differnt, we'll just build them separately and include whichever pair
	// is requested

	// the purpose of encrypt() is to create a secure one way hash to protect secret data,
	// like a password. It must both be cryptographically secure and computationally difficult
	// this is really just a wrapper to abstract away the choice of algorithm, and provide some
	// sane defaults
	// callback of the form function(err, hash) {}

	// verify() is a simple function to match a cleartext payload with an encrypt()-ed
	// secret, taking into account any salts
	// this is a fairly straight forward wrapper around the provided verify function
	// we don't need to split out the salt or other details, because this is directly
	// symmetric with the hash function
	switch (this._kdf) {
		case 'scrypt':
			this.encrypt = function(payload, opts, callback) {
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

				if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);

				var params = { maxtime: .25, maxmem: null, maxmemfrac: null }; // the parameters scrypt tries to hit for resource usage
				var sparams = { N: null, r: null, p: null }; // this will be populated with N, r, and p that actually controls the technical elements of the algorithm

				if (opts.params) {
					params.maxtime = opts.params.maxtime?opts.params.maxtime:params.maxtime;
					params.maxmem = opts.params.maxmem?opts.params.maxmem:params.maxmem;
					params.maxmemfrac = opts.params.maxmemfrac?opts.params.maxmemfrac:params.maxmemfrac;
				}

				// if we've set all of N, r and p, then we don't need to generate these parameters
				if (!(opts.params && opts.params.N && opts.params.r && opts.params.p)) {
					if (callback) {
						scrypt.params(params.maxtime, params.maxmem, params.maxmemfrac, function(err, sparams) {
							scrypt.hash(payload, sparams, callback);
						});
						return;
					}
					else sparams = scrypt.params(params.maxtime, params.maxmem, params.maxmemfrac);
				}
				else {
					// we've set N, r and p, so pass them in
					sparams.N = opts.params.N;
					sparams.r = opts.params.r;
					sparams.p = opts.params.p;
				}

				if (callback) scrypt.hash(payload, sparams, callback);
				// return the buffer directly, let the calling app decide what to do with it
				else return scrypt.hash(payload, sparams);
			};
			this.verify = function(payload, secret, opts, callback) {
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

				if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);
				if (!Buffer.isBuffer(secret)) secret = opts.secret_encoding?new Buffer(secret, opts.secret_encoding):new Buffer(secret);

				if (callback) scrypt.verify(secret, payload, callback);
				else return scrypt.verify(secret, payload);
			};
			break;
		case 'bcrypt':
			this.encrypt = function(payload, opts, callback) {
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

				var work_factor = opts.work_factor?opts.work_factor:11; // default to a work factor of 11
				var seed_length = opts.seed_length?opts.seed_length:22; // default to a seed length of 22

				//if (!Buffer.isBuffer(payload)) payload = new Buffer(payload);

				// by default, hash only when necessary, but optionally hash always or never
				// bcrypt specification is ambiguous when it comes to the length of data it will support
				// it could be as low as 51 chars or as high as 72 (http://security.stackexchange.com/a/39851/34469)
				// according to testing, the bcrypt module we're using limits us to 72
				if (opts.always_prehash || payload.length > 72) {
					// sha256 will give us 32 bytes, which will definitely fit within the bcrypt length limit
					// even though we actually have 72 bytes to work with, sha512 won't necessarily be portable to other implementations
					var hash = crypto.createHash('sha256'); // this will give us 32 bytes, which will definitely fit within the bcrypt length limit even with salt
					hash.write(payload);
					hash.end();
					payload = hash.read().toString();
				}

				if (callback) {
					bcrypt.genSalt(work_factor, seed_length, function(err, salt) {
						if (err) return callback(err);
						bcrypt.hash(payload, salt, callback);
					});
					return;
				}
				// return the buffer directly, let the calling app decide what to do with it
				else {
					var salt = bcrypt.genSaltSync(work_factor, seed_length);
					if (util.isError(salt)) return err;
					// this can be used to test the maximum password length we can hash
					/*if (exports.TEST) {
						var p1 = bcrypt.hashSync(payload, salt);
						var p2 = bcrypt.hashSync(payload+'a', salt);
						if (p1.toString() == p2.toString()) throw new Error('password limit ['+payload.length+']; '+(payload.length+1)+' is too long');
					}*/
					return bcrypt.hashSync(payload, salt);
				}
			};
			this.verify = function(payload, secret, opts, callback) {
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

				// per the comments in the bcrypt encrypt, we may need to prehash due circumvent the bcrypt length limit
				if (opts.always_prehash || payload.length > 72) {
					// sha256 will give us 32 bytes, which will definitely fit within the bcrypt length limit
					// even though we actually have 72 bytes to work with, sha512 isn't guaranteed to work depending on how salt impacts length, nor if we change implementations
					var hash = crypto.createHash('sha256'); // this will give us 32 bytes, which will definitely fit within the bcrypt length limit even with salt
					hash.write(payload);
					hash.end();
					payload = hash.read().toString();
				}

				if (callback) bcrypt.compare(payload, secret, callback);
				else return bcrypt.compareSync(payload, secret);
			};
			break;
		case 'pbkdf2':
			this.encrypt = function(payload, opts, callback) {
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

				// default to sha1 since our pbkdf2Slow function will pass it off to the built-in, which
				// is much more efficient, and efficiency matters in this context
				var algo = opts.algo?opts.algo:'sha1';
				var saltlen = opts.salt_byte_length?parseInt(opts.salt_byte_length):(opts.salt_bit_length?parseInt(opts.salt_bit_length)/8:16); // default to 128 bits
				// default to 2^18, it's more than enough for 2014, and it'll still skirt by if we choose a tougher algorithm without running out of resources
				var iterations = opts.iterations?opts.iterations:262144;
				var keylen = opts.key_byte_length?parseInt(opts.key_byte_length):(opts.key_bit_length?parseInt(opts.key_bit_length)/8:32); // default to 256 bits

				// the rest of this is very similar to digest/match

				// hash output is typically stored in hex format, so that's our default
				// we enforce an encoding because we'll often be using this to verify passwords and thus we need a string format to store
				// if we need it to generate a key, we can turn it back into a buffer later
				var encoding = opts.encoding?opts.encoding:'hex';

				if (callback) {
					crypto.randomBytes(saltlen, function(err, salt) {
						if (err) return callback(err);

						salt = salt.toString(encoding);

						_pbkdf2Slow(algo, payload, salt, iterations, keylen, function(err, key) {
							if (!opts.delim) opts.delim = '';
							if (opts.salt_after) callback(null, key.toString(encoding)+opts.delim+salt);
							else callback(null, salt+opts.delim+key.toString(encoding));
						});
					});
					return;
				}
				
				var salt = crypto.randomBytes(saltlen);
				if (util.isError(salt)) return salt;

				if (!opts.delim) opts.delim = '';
				if (opts.salt_after) return _pbkdf2SlowSync(algo, payload, salt, iterations, keylen).toString(encoding)+opts.delim+salt;
				else return salt+opts.delim+_pbkdf2SlowSync(algo, payload, salt, iterations, keylen).toString(encoding);
			};
			this.verify = function(payload, secret, opts, callback) {
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

				// default to sha1 since our pbkdf2Slow function will pass it off to the built-in, which
				// is much more efficient, and efficiency matters in this context
				var algo = opts.algo?opts.algo:'sha1';

				var saltlen = opts.salt_byte_length?parseInt(opts.salt_byte_length):(opts.salt_bit_length?parseInt(opts.salt_bit_length)/8:16); // default to 128 bits
				// default to 2^18, it's more than enough for 2014, and it'll still skirt by if we choose a tougher algorithm without running out of resources
				var iterations = opts.iterations?opts.iterations:262144;
				var keylen = opts.key_byte_length?parseInt(opts.key_byte_length):(opts.key_bit_length?parseInt(opts.key_bit_length)/8:32); // default to 256 bits

				var encoding = opts.encoding?opts.encoding:'hex';

				var salt;
				// we have a delimiter
				if (opts.delim) {
					var parts = secret.split(opts.delim);
					if (opts.salt_after) {
						secret = parts[0];
						salt = parts[1];
					}
					// if we don't indicate salt after, default to before
					else {
						salt = parts[0];
						secret = parts[1];
					}
				}
				else {
					var inter = new Buffer(secret, encoding);
					if (opts.salt_after) {
						salt = inter.slice(-1*saltlen).toString(encoding);
						secret = inter.slice(0, -1*saltlen).toString(encoding);
					}
					else {
						salt = inter.slice(0, saltlen).toString(encoding);
						secret = inter.slice(saltlen).toString(encoding);
					}
					delete inter;
				}

				if (callback) {
					_pbkdf2Slow(algo, payload, salt, iterations, keylen, function(err, key) {
						if (opts.constant_time) callback(null, fn.constant_time_str_cmp(key.toString(encoding), secret));
						else callback(null, key.toString(encoding)===secret);
					});
				}
				else {
					if (opts.constant_time) return fn.constant_time_str_cmp(key.toString(encoding), secret);
					else return key.toString(encoding) === secret;
				}
			};
			break;
		default:
			throw new Error('Your requested key derivation function is not available');
			break;
	}
};

exports.kdf = kdf;

var _kdf = new kdf();
exports.encrypt = _kdf.encrypt;
exports.verify = _kdf.verify;

// this is mostly an academic exercise
// any useful implementation should be accomplished in native C/C++ code as it should be as
// performant as possible so as to not unduely hinder legitimate code beyond the performance
// an attacker will acheive.
// the main use of this code would be for infrequent/manual one-time use to produce a hash
// using a more secure hashing algorithm than the default sha1 supported by node's built in pbkdf2 method
// when speed of producing the key is not important (as in the case of our gen_key function, above)
// ported from a native PHP implementation
function _pbkdf2Slow(algo, payload, salt, iterations, keylen, callback) {
	// if we're cool with the node default, offload to the crypto built-in
	if (!algo || algo == 'sha1') {
		if (callback) return crypto.pbkdf2(payload, salt, iterations, keylen, callback);
		else return crypto.pbkdf2Sync(payload, salt, iterations, keylen);
	}

	//if (callback) throw new Error("_pbkdf2Slow does not support asynchronous processing without using the sha1 algorithm which gets passed off to the built-in function");

	// if we realy, really want to use our slow version of the algorithm, then we can force it
	// really would only need this to verify our algorithm as correct against the built in
	if (algo == 'sha1-onecrypt') algo = 'sha1';

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

	if (callback) setImmediate(function() { callback(null, new Buffer(derived_key.toString('binary').substr(0, keylen), 'binary')); });
	return new Buffer(derived_key.toString('binary').substr(0, keylen), 'binary');
}

function _pbkdf2SlowSync(algo, payload, salt, iterations, keylen) {
	return _pbkdf2Slow(algo, payload, salt, iterations, keylen);
}

// since this provides functionality not otherwise available in node, we'll export it, but
// its use is discouraged
// for that reason, I've ommitted any asynchronous way of calling this code from an external source
exports._pbkdf2Slow = _pbkdf2SlowSync;