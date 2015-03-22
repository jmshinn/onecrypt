var crypto = require('crypto'),
	util = require('util');

var digest = require('./digest'),
	kdf = require('./kdf'),
	symmetric = require('./symmetric'),
	asymmetric = require('./asymmetric');

// certain options are only available in a testing context
exports.TEST = false;

// pass through anything that might be beneficial to have access to:
exports.hash = digest.hash;
exports.digest = digest.digest;
exports.match = digest.match;
exports.kdf = kdf.kdf;
exports.encrypt = kdf.encrypt;
exports.verify = kdf.verify;
exports.encipher = symmetric.encipher;
exports.decipher = symmetric.decipher;

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
	if (typeof params === 'string') params = { password: params };
	// defaults

	if (params.asymmetric) delete params.asymmetric;

	// the resulting keylength, in bits
	var keylen = params.asymmetric?2048:256; // 256 bits, if asymmetric it's actually a modulus, but the intent is the same so just reuse the variable
	// the following are only relevant to deriving a key from a password
	var saltlen = 128; // 128 bits
	var iterations = 262144; // default to 2^18 iterations.  With our slow algorithm, we run out of memory if we go over 1m

	// for asymmetric encryption, use a public exponent of 65537, recommended by NIST and used here mainly because it avoids
	// the unfounded concern about smaller exponents.  The concern about smaller exponents is unfounded because no vulnerabilities
	// have been found or proposed that actually relate to the exponent size, but are just easier to conceptualize with a small
	// exponent.  3, 5, 17, 257, and 65537 are Fermat Primes (2^k + 1), which provide better performance
	/*if (params.asymmetric) {
		var public_exponent = params.public_exponent?params.public_exponent:65537;
		// since ursa makes this failry easy, just go ahead and do it
		// the returned object is not just a key but an object that provides most of the cryptographic functionality available in ursa for RSA
		return ursa.generatePrivateKey(keylen, public_exponent);
	}*/

	var byte_length = params.byte_length?parseInt(params.byte_length):(params.bit_length?(parseInt(params.bit_length)/8):(keylen/8)); // divide the bit length by 8 to get the byte length we need to feed into randomBytes

	if (params.password) {
		var salt = params.salt?params.salt:crypto.randomBytes(saltlen/8); // divide bit length by 8 to get byte length
		if (params.iterations) iterations = params.iterations;

		// we use pbkdf2 because we can control the size of the resulting key, and it contains no predictable characters

		// we can generate two complete keys with a single call with sha512, but for single key generation we'd be throwing half the bits away
		var key = kdf._pbkdf2Slow('sha256', params.password, salt, iterations, byte_length);
		// since this is for key generation, this could be thought of as a one time action if we store the resulting key and never need to re-generate it
		// however, since we're using a password, we may want to discard the key and re-generate it each time with a password, we need to know the parameters we used to create it
		// this _gen_key() function is not ideal for this purpose given its synchronous nature, but you could generate the key here and use it elsewhere
		return params.return_params?[(params.raw?key:key.toString('base64')), { salt: (params.raw?salt:salt.toString('base64')), iterations: iterations, keylen: byte_length, algo: 'pbkdf2', hash: 'sha256' }]:(params.raw?key:key.toString('base64'));
	}
	else {
		var key = crypto.randomBytes(byte_length);
		return params.raw?key:key.toString('base64');
	}
};

// upgrade_hash() will accept some permutation of the hashing algorithm, attempt to match against
// an old one
// if successful, re-encrypt with the currently accepted key derivation algorithm
// this is specifically for taking a database that has passwords hashed in a weak format and
// allowing users to log in as normal, and upgrading their password hash to a strong format
var upgrade_hash = exports.upgrade_hash = function(payload, secret, hashes) {
	for (var i=0; i<hashes.length; i++) {
		if (hashes[i] instanceof digest.hash) {
			if (hashes[i].match(payload, secret)) return kdf.encrypt(payload);
		}
		else {
			var h = new digest.hash(hashes[i].opts, hashes[i].algorithm);
			if (h.match(payload, secret)) return kdf.encrypt(payload);
		}
	}
	return false;
};

// pre-define some password hash specifications used in the wild that we may want to upgrade
exports.upgrade_md5 = { algorithm: 'md5', opts: {} };
exports.upgrade_sha1 = { algorithm: 'sha1', opts: {} };
exports.upgrade_magento = { algorithm: 'md5', opts: { salt: true, salt_byte_length: 2, salt_char_length: 2, salt_after: true, delim: ':' } };

// this is a stable API that someone can use that will be updated any time our internal encrypt/verify pair
// is updated with new defaults so that it will automatically upgrade the password to the new algorithm, providing
// forwards compatibility
// any changes will be recorded here
exports.verify_stable = function(payload, secret, opts, callback) {
	opts = opts || {};

	var previous_params = [];

	if (opts.upgrade) {
		// for now, this is the same as below.  once we've actually made a change to the defaults, we'll
		// change this to return true if it passed with the current version, or the upgraded password if
		// it passed with an old version
		return kdf.verify(payload, secret, opts, callback);
	}
	else {
		// this being the first version of the API, this is a simple wrapper around our `verify()` method
		// further, since our scrypt library automatically embeds the defaults used, we'll have to introduce
		// more manual checking methods to make sure it breaks and upgrades with stronger defaults
		return kdf.verify(payload, secret, opts, callback);
	}
};
exports.verify_version = '1';
