
var assert = require("assert")
var d = require('../src/data.js');

var hexeq = function() {
    var args = Array.prototype.slice.call(arguments);
    var hex = args[args.length - 1];
    args.pop();
    var repr = d.hexize.apply(this, args);
    return assert.equal(repr, hex);
}

describe('data.js', function() {
    it('dumping', function() {
        hexeq(d.byte(3), '03');
        hexeq(d.bytes([1, 2, 255]), '0102ff');
        hexeq(d.boolean(true), '01');
        hexeq(d.boolean(false), '00');
    });
    it('dumping 32-bit ints', function() {
        hexeq(d.uint32(0), '00000000');
        hexeq(d.uint32(3141592), '002fefd8');
        hexeq(d.uint32(0xffffffff), 'ffffffff');
    });
    it('dumping 64-bit ints', function() {
        hexeq(d.uint64(0), '0000000000000000');
        hexeq(d.uint64((1 << 30) * 4), '0000000100000000');
        hexeq(d.uint64('ff4ffffffffffff', 16), 
            '0ff4ffffffffffff');
    });
    it('dumping strings', function() {
        hexeq(d.string('ssh'), '00000003' + '737368');
        hexeq(d.string([1, 250]), '00000002' + '01fa');
    });
    it('dumping utf8', function() {
        var utf = 'jaźń';
        var repr = '00000006' + '6a61c5bac584';
        hexeq(d.utf8(utf), repr);
        hexeq(d.string(utf), repr);
    });
    it('dumping mpint', function() {
        hexeq(d.mpint(0), '00000000');
        hexeq(d.mpint('9a378f9b2e332a7', 16), '0000000809a378f9b2e332a7');
        hexeq(d.mpint(80, 16), '000000020080');
        hexeq(d.mpint(-1234, 16), '00000002edcc');
        hexeq(d.mpint('-deadbeef', 16), '00000005ff21524111');
    });
    it('dumping name-lists', function() {
        hexeq(d.namelist(['one', 'two']), '00000007' + '6f6e652c74776f');
        hexeq(d.namelist('a,b'), '00000003' + '612c62');
    });
});
