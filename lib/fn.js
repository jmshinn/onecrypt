// this is necessary to avoid leaking information about how many characters match in an HMAC
exports.constant_time_str_cmp = function(str1, str2) {
	if (str1.length !== str2.length) { return false; }
	var result = 0;
	for (var i = 0; i < str1.length; i++) {
		result |= (str1.charCodeAt(i) ^ str2.charCodeAt(i));
	}
	return result === 0;
};

