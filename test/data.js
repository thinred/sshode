
var assert = require("assert")
var d = require('../src/data.js');
var utils = require('./utils.js');

var same = utils.same;

var hexeq = function() {
    var args = Array.prototype.slice.call(arguments);
    var hex = args.pop();
    var repr = d.hexize.apply(this, args);
    return assert.equal(repr, hex);
}

var reparse = function() {
    var args = Array.prototype.slice.call(arguments);
    var repr = d.serialize.apply(this, args);
    return d.parse_array.call(this, repr, arguments);
}

exports.run = function() {

    hexeq(d.byte(3), '03');
    hexeq(d.bytes([1, 2, 255]), '0102ff');
    hexeq(d.boolean(true), '01');
    hexeq(d.boolean(false), '00');
    
    // dumping 32-bit ints
    
    hexeq(d.uint32(0), '00000000');
    hexeq(d.uint32(3141592), '002fefd8');
    hexeq(d.uint32(0xffffffff), 'ffffffff');
    
    // dumping 64-bit ints
    hexeq(d.uint64(0), '0000000000000000');
    hexeq(d.uint64((1 << 30) * 4), '0000000100000000');
    hexeq(d.uint64('ff4ffffffffffff', 16), '0ff4ffffffffffff');
    
    // dumping strings
    hexeq(d.string('ssh'), '00000003' + '737368');
    hexeq(d.string([1, 250]), '00000002' + '01fa');
    
    // dumping utf8
    var utf = 'jaźń';
    var repr = '00000006' + '6a61c5bac584';
    hexeq(d.utf8(utf), repr);
    hexeq(d.string(utf), repr);
    
    // dumping mpint
    hexeq(d.mpint(0), '00000000');
    hexeq(d.mpint('9a378f9b2e332a7', 16), '0000000809a378f9b2e332a7');
    hexeq(d.mpint(80, 16), '000000020080');
    hexeq(d.mpint(-1234, 16), '00000002edcc');
    hexeq(d.mpint('-deadbeef', 16), '00000005ff21524111');
    hexeq(d.mpint(-32768), '000000028000');
    
    // dumping name-lists
    hexeq(d.namelist(['one', 'two']), '00000007' + '6f6e652c74776f');
    hexeq(d.namelist('a,b'), '00000003' + '612c62');
    
    // parsing basics
    same(reparse(d.boolean(true)), [ true ]);
    same(reparse(d.boolean(false)), [ false ]);
    same(reparse(d.byte(1), d.byte(2)), [1, 2]);
    var buff = d.serialize(d.bytes([1,2,3]));
    var out = d.parse_array(buff, [ d.bytes(3) ])[0];
    assert.equal(out.length, 3);
    assert.equal([ out[0], out[1], out[2] ].toString(), '1,2,3');

    // parsing 32-bit ints
    same(reparse(d.uint32(42)), [ 42 ]);
    same(reparse(d.uint32(10), d.uint32(0xffffffff)), [10,4294967295]);

    // parsing 64-bit ints
    var out = reparse(d.uint64('1234567890', 16));
    assert.equal(d.is_array(out), true);
    assert.equal(d.is_bigint(out[0]), true);
    assert.equal(out[0].toString(), '78187493520');

    // parsing mpints
    var out = reparse(d.mpint(0), d.mpint(12345, 16), d.mpint(-7),
        d.mpint('111111111111111111111111111111', 7));
    assert.equal(out[0].toString(), '0');
    assert.equal(out[1].toString(), '74565');
    assert.equal(out[2].toString(), '-7');
    assert.equal(out[3].toString(), '3756556715115376347977208');

    // parsing str

    var x = reparse(d.string('cze'))[0];
    assert.equal(x.length, 3);
    assert.equal([ x[0], x[1], x[2] ].toString(), '99,122,101');

    // parsing utf
    same(reparse(d.utf8('cze'), d.utf8('żółw')), ['cze', 'żółw']);

    // various

    assert.equal(d.parse_array(new Buffer(0)).toString(), '');

    // parsing namelist

    same(reparse(d.namelist([ 'romek', 'tomek'])), [['romek', 'tomek']]);

    // parsing to object
    var b = new Buffer([1, 2, 3]);
    var o = d.parse_object(b, [ d.byte('b1'), d.bytes('b2', 2) ]);
    assert.equal(o.b1, 1)
    assert.equal(o.b2.toString('hex'), '0203');

    // flattening serializing

    var b = d.serialize(d.byte(9), [ [ d.byte(10) ], d.bytes([3, 14]) ]);
    assert.equal(b.toString('hex'), '090a030e');
};
