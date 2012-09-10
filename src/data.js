
'use strict';

var big = require('./bigdecimal.js');

var BIG255 = new big.BigInteger('255');
var ZERO = new big.BigInteger('0');
var ONE = new big.BigInteger('1');

// Data parser and serializer

function State(buffer) {
    // contains state of the buffer (i.e., buffer and offset)

    var offset = 0;

    this.readByte = function() {
        var c = buffer.readUInt8(offset);
        offset += 1;
        return c;
    }

    this.peekByte = function() {
        return buffer.readUInt8(offset);
    }

    this.writeByte = function(x) {
        buffer.writeUInt8(x, offset);
        offset += 1;
    }

    this.readInt = function() {
        var i = buffer.readUInt32BE(offset);
        offset += 4;
        return i;
    }

    this.writeInt = function(x) {
        buffer.writeUInt32BE(x, offset);
        offset += 4;
    }

    this.readBytes = function(n) {
        var bytes = buffer.slice(offset, offset + n);
        offset += n;
        return bytes;
    }

    this.writeBytes = function(x) {
        x.copy(buffer, offset);
        offset += x.length;
    }

    this.eof = function() {
        return (offset == buffer.length);
    }
}

function is_string(v) { return (typeof v === 'string'); }
function is_array(v) { return (v.constructor.name === 'Array'); }
function is_bigint(v) { return (!!v.divideAndRemainder); }

function raw_bytes(v) {
    var bytes = [];
    while(v.signum() != 0) {
        bytes.push(v.and(BIG255).intValue());
        v = v.shiftRight(8);
    }
    return bytes;
}

function mpint_to_bytes(sign, v) {
    if (sign == 0)
        return [];
    if (sign == 1) {
        var bytes = raw_bytes(v);
        if (bytes[bytes.length - 1] & 0x80)
            bytes.push(0x00);
        return bytes;
    } else {
        var bits = v.bitLength();
        var bytes = (bits >> 3) + (bits % 8 != 0);
        var mask = ONE.shiftLeft(bytes * 8).subtract(ONE);
        var repr = mask.xor(v).add(ONE);
        var bytes = raw_bytes(repr);
        if ((bytes[bytes.length - 1] & 0x80) == 0)
            bytes.push(0xff);
        return bytes;
    }
}

function to_mpint(v, base) {
    if (!is_bigint(v)) { // detect if v is already BigInteger
        if (!base) base = 10;
        v = new big.BigInteger(v.toString(), base);
    }
    return v;
}

function to_buffer(v) {
    if (is_string(v) || is_array(v))
        v = new Buffer(v);
    return v;
}


function type(klass) {
    var x = function(value, option) {
        return { 'klass': klass, 'value': value, 'option': option }
    }
    x.klass = klass;
    return x;
}

/*
    Serializing protocol is as follows:
        1. 'flatten' is called to optionally change the input to internal representation.
            Further on, this value is passed to 'size' or 'serialize'
        2. 'size' is called for every element and it should return a size in bytes
            of this object.
        3. Buffer is created to hold everything.
        4. 'serialize' is called for every object and it should serialize itself.
    Parsing is easier:
        1. 'parse' method is called for every object in turn.
            It should parse itself and return itself.
 */

var Byte = {
    flatten : null,
    size : function() { return 1; },
    serialize : function(v, state) { state.writeByte(v); },
    parse : function(state) { return state.readByte(); }
}

var Bytes = {
    flatten : to_buffer,
    size : function(v) { return v.length; },
    serialize : function(v, state) { state.writeBytes(v); },
    parse : function(state, n) { return state.readBytes(n); }
}

var Bool = {
    flatten : function(v) { return (!!v); },
    size : function() { return 1; },
    serialize : function(v, state) { state.writeByte(v ? 0x01 : 0x00); },
    parse : function(state) { return (state.readByte() != 0x00); }
}

var Uint32 = {
    flatten : null,
    size : function() { return 4; },
    serialize : function(v, state) {
        if (v < 0 || v > 0xffffffff)
            throw 'Invalid uint32';
        state.writeInt(v);
    },
    parse : function(state) { return state.readInt(); }
}

var Uint64 = {
    flatten : to_mpint,
    size : function() { return 8; },
    serialize : function(v, state) {
        if (v.signum() == -1 || v.bitLength() > 64)
            throw 'Invalid uint64';
        var bytes = raw_bytes(v);
        while (bytes.length != 8) bytes.push(0x00);
        bytes.reverse();
        return state.writeBytes(new Buffer(bytes));
    },
    parse : function(state) {
        var h = big.BigInteger.valueOf(state.readInt());
        var l = big.BigInteger.valueOf(state.readInt());
        return h.shiftLeft(32).or(l);
    }
}

var Str = {
    flatten : to_buffer,
    size : function(v) { return 4 + v.length; },
    serialize : function(v, state) {
        state.writeInt(v.length);
        state.writeBytes(v);
    },
    parse : function(state) {
        var n = state.readInt();
        return state.readBytes(n); // TODO
    }
}

var Utf8 = {
    flatten : function(v) { return new Buffer(v, 'utf8'); },
    size : Str.size,
    serialize : Str.serialize,
    parse : function(state) {
        var s = Str.parse(state);
        return s.toString('utf8');
    }
}

var Mpint = {
    flatten : function(v, base) {
        v = to_mpint(v, base);
        var sign = v.signum();
        if (sign == -1)
            v = v.negate();
        return [ sign, v ];
    },
    size : function(v) {
        var sign = v[0];
        v = v[1];
        if (sign == 0)
            return 4;
        var bits = v.bitLength();
        if (sign == 1)
            return (bits >> 3) + 1 + 4;
        // sign == -1
        if (bits % 8 != 0) {
            return (bits >> 3) + 1 + 4;
        } else {
            if (v.bitCount() == 1) // power of 2
                return (bits >> 3) + 4;
            else
                return (bits >> 3) + 1 + 4;
        }
    },
    serialize : function(v, state) {
        var bytes = mpint_to_bytes(v[0], v[1]);
        bytes.reverse(); // LSB => MSB
        return Str.serialize(Str.flatten(bytes), state);
    },
    parse : function(state) {
        var n = state.readInt();
        if (n == 0)
            return ZERO;
        var sign = (state.peekByte() & 0x80) != 0;
        var x = ZERO;
        // take integers
        for (var i = 0; i < (n >> 2); i++) {
            var u = state.readInt();
            x = x.shiftLeft(32).or(big.BigInteger.valueOf(u));
        }
        // take remaining bytes
        for (var i = 0; i < (n % 4); i++) {
            var b = state.readByte();
            x = x.shiftLeft(8).or(big.BigInteger.valueOf(b))
        }
        if (sign) {
            // we have to flip it and add 1
            var mask = ONE.shiftLeft(n * 8).subtract(ONE);
            x = x.xor(mask).add(ONE).negate();
        }
        return x;
    }
}

var Namelist = {
    flatten : function(v) {
        if (is_array(v))
            v = v.join(',');
        return Utf8.flatten(v);
    },
    size : Utf8.size,
    serialize : Utf8.serialize,
    parse : function(state) {
        var s = Utf8.parse(state);
        return s.split(',');
    }
}

/* Public interface */

function serialize() {
    // used to write SSH data to a buffer
    // 1. Compute length.
    var size = 0;
    var args = [];
    for (var x in arguments) {
        var it = arguments[x];
        if (it.klass.flatten !== null)
            it.value = it.klass.flatten(it.value, it.option);
        size += it.klass.size(it.value);
    }
    var buffer = new Buffer(size);
    var state = new State(buffer);
    // 2. Serialize.
    for (var x in arguments) {
        var it = arguments[x];
        it.klass.serialize(it.value, state);
    }
    if (!state.eof())
        throw 'Fatal error (eof not reached)';
    return buffer;
}

function parse_array(buffer, spec) {
    var state = new State(buffer);
    var values = [];
    for (var i in spec) {
        var el = spec[i];
        var v = el.klass.parse(state, el.value);
        values.push(v);
    }
    return values;
}

function parse() {
    var buffer = arguments[0];
    var args = Array.prototype.slice.call(arguments, 1);
    if (args.length == 0)
        return [];
    var first = args[0];
    if (args.length > 1 || (args.length == 1 && !is_array(first)))
        return parse_array(buffer, args);
    return parse_array(buffer, first);
}

function hexize() {
    return serialize.apply(this, arguments).toString('hex');
}

/* Exports */

exports.byte = type(Byte);
exports.bytes = type(Bytes);
exports.boolean = type(Bool);
exports.uint32 = type(Uint32);
exports.uint64 = type(Uint64);
exports.string = type(Str);
exports.utf8 = type(Utf8); /* like string, but works with UTF-8 */
exports.mpint = type(Mpint);
exports.namelist = type(Namelist);

exports.bigint = big.BigInteger;
exports.is_bigint = is_bigint;
exports.is_array = is_array;

exports.serialize = serialize;
exports.hexize = hexize;
exports.parse_array = parse_array;
exports.parse = parse;