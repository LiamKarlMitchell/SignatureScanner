var scan = function(buffer, query, callback) {
		if (typeof(query) == 'string') {
			var t = query;
			query = {
				string: t
			};
		}

		if (!callback) query.stream = false;

		query.encoding = query.encoding || 'utf8';
		if (query.encoding = 'unicode') query.encoding = 'utf16le';

		query.match = query.match || '';
		query.start = query.start || 0;
		query.end = query.end || buffer.length;
		query.debug = query.debug || 0;

		var result = {
			query: query,
			status: null,
			errors: [],
			warnings: [],
			found: []
		};

		if (query.string && query.match) {
			if (query.string.length != query.math.length / 2) {
				result.errors.push('match should be long enough to cover your query string');
				return result;
			}
		}

		var toSearch = new Buffer(query.string, query.encoding);
		// Temp fix to the issue of encoding not handling propperly
		// if (query.encoding == 'utf16le') {
		// 	toSearch = new Buffer(query.string.length * 2);
		// 	toSearch.write(query.string, 0, query.string.length * 2, query.encoding);
		// }

		if (toSearch.length > buffer.length - query.start) {
			result.warnings.push('Our search string is greater than buffer.length - query.start');
			//if (callback) { callback(result); };
			return result;
		}

		if (query.end > buffer.length - toSearch.length) {
			result.warnings.push('query.end is greater than buffer.length + search length setting it back');
			query.end = buffer.length - toSearch.length;
		}

		if (query.end - toSearch.length <= query.start) {
			result.errors.push('query.end is not far enough to find data we want to search for.');
			return result;
		}

		query.searchLength = toSearch.length;

		for (var pos = query.start; pos < query.end; pos++) {
			if (query.debug >= 2) {
				console.log('Next pos: ' + pos);
			}
			var found = null;

			for (var i = 0; i < toSearch.length; i++) {

				var currentPosition = pos + i;
				var matchFound = (query.match ? query.match[i] == '?' || ((toSearch[i] == buffer[currentPosition]) && query.match[i] == 'X') : toSearch[i] == buffer[currentPosition]);
				if (!matchFound) {
					break;
				}
				if (query.debug >= 1) {
					console.log('pos(' + (i + 1) + '/' + toSearch.length + '): ' + currentPosition + ': ' + toSearch[i] + ' == ' + buffer[currentPosition]);
				}

				if (i + 1 == toSearch.length) {
					//found = {
						//Address: pos + (query.offset || 0)
					//};
					found = pos+(query.offset||0);

					result.found.push(found);

					if (query.stream) {
						if (callback({
							query: query,
							status: null,
							errors: null,
							found: [found]
						})) break;
					}
				}
			}

			if (found) {
				if (!query.stream) {
					if (callback) {
						callback(result);
					}
				}

				if (query.limit != null && result.found.length >= query.limit) {
					return result;
				}
			}

		}
		return result;
	}

exports.scan = scan;

exports.version = function() {
	return '0.00';
}