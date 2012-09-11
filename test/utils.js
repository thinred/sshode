
var assert = require('assert');

exports.same = function(x, y) {
    x = JSON.stringify(x);
    y = JSON.stringify(y);
    return assert.equal(x, y);
}
