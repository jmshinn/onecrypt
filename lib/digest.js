var crypto = require('crypto'),
	util = require('util');

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

	// default to options appropriate for message digest, i.e. no salt
	this._opts = _opts || { encoding: 'hex', salt: false };
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
			else if (opts.salt === true) opts.salt = crypto.randomBytes(saltlen);

			if (util.isError(opts.salt)) {
				if (callback) return setImmediate(function() { callback(opts.salt); });
				else return opts.salt;
			}

			opts.salt = opts.salt.toString(encoding);

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
	this.match = function(payload, secret, opts) {
		opts = opts || {};

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

		if (opts.salt !== false && typeof opts.salt !== 'string' && ((typeof opts.delim === 'string' && opts.delim) || opts.salt_char_length || opts.salt_byte_length || opts.salt_bit_length)) {
			// the salt should be concatenated to the payload, and we've defined some way to split it off:
			// 1) we have a delimiter we can split on
			// 2) we have a defined length to read off and remove

			var saltlen = opts.salt_byte_length?parseInt(opts.salt_byte_length):(opts.salt_bit_length?parseInt(opts.salt_bit_length)/8:16); // default to 128 bits

			// we have a delimiter
			if (opts.delim) {
				var parts = secret.split(opts.delim);
				// if we didn't actually find the delimiter, then we only have the hash and no salt
				if (parts.length == 1) salt = '';
				else if (opts.salt_after) {
					secret = parts[0];
					opts.salt = parts[1];
				}
				// if we don't indicate salt after, default to before
				else {
					opts.salt = parts[0];
					secret = parts[1];
				}
			}
			// if we weren't passed a delimiter
			else if (opts.salt_char_length) {
				if (opts.salt_after) {
					opts.salt = secret.substr(-1*opts.salt_char_length);
					secret = secret.substr(0, -1*opts.salt_char_length);
				}
				else {
					opts.salt = secret.substr(0, opts.salt_char_length);
					secret = secret.substr(opts.salt_char_length);
				}
			}
			else {
				var inter = new Buffer(secret, encoding);
				if (opts.salt_after) {
					opts.salt = inter.slice(-1*saltlen).toString(encoding);
					secret = inter.slice(0, -1*saltlen).toString(encoding);
				}
				else {
					opts.salt = inter.slice(0, saltlen).toString(encoding);
					secret = inter.slice(saltlen).toString(encoding);
				}
				delete inter;
			}
		}

		if (opts.salt === false) opts.salt = '';
		else opts.salt = opts.salt || '';
		var predelim = opts.salt&&opts.predelim?opts.predelim:''; // internal delimiter used *before* hashing (typically none)

		// does the salt come before or after the payload? defaults to before
		if (opts.pre_salt_after) payload += predelim + opts.salt;
		else payload = opts.salt + predelim + payload;

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