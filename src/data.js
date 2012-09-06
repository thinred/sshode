
var big = require('./bigdecimal.js');

var BIG255 = new big.BigInteger('255');
var ONE = new big.BigInteger("1");
var MASK32 = ONE.shiftLeft(32).subtract(ONE);

// Data parser and serializer

function State(buffer) {
    // contains state of the buffer (i.e., buffer and offset)

    var offset = 0;

    this.readByte = function() {
        var c = buffer.readUInt8(offset);
        offset += 1;
        return c;
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
function is_array(v) { return (v.constructor === Array); }

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
    if (!v.divideAndRemainder) { // detect if v is already BigInteger
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


var Byte = {
    flatten : null,
    size : function() { return 1; },
    serialize : function(v, state) { state.writeByte(v); },
}

var Bytes = {
    flatten : to_buffer,
    size : function(v) { return v.length; },
    serialize : function(v, state) {
        state.writeBytes(v);
    }
}

var Bool = {
    flatten : function(v) { return (!!v); },
    size : function() { return 1; },
    serialize : function(v, state) { state.writeByte(v ? 1 : 0); }
}

var Uint32 = {
    flatten : null,
    size : function() { return 4; },
    serialize : function(v, state) {
        if (v < 0 || v > 0xffffffff)
            throw 'Invalid uint32';
        state.writeInt(v);
    }
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
    }
}

var Str = {
    flatten : to_buffer,
    size : function(v) { return 4 + v.length; },
    serialize : function(v, state) {
        state.writeInt(v.length);
        state.writeBytes(v);
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
    }
}

var Namelist = {
    flatten : function(v) {
        if (is_array(v))
            v = v.join(',');
        return v;
    },
    size : Str.size,
    serialize : Str.serialize
}

exports.byte = type(Byte);
exports.bytes = type(Bytes);
exports.boolean = type(Bool);
exports.uint32 = type(Uint32);
exports.uint64 = type(Uint64);
exports.string = type(Str);
exports.mpint = type(Mpint);
exports.namelist = type(Namelist);

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
