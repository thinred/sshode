
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

function type(reader, writer, sizer) {
    var f = function(n) {
        var args = arguments;
        return {
            'reader' : function(st) { 
                var array = [];
                for(var i = 0; i < n; i++)
                    array.push(reader(st));
                return array;
            },
            'writer' : function(st) {
                for(var i = 0; i < args.length; i++)
                    writer(st, args[i]);
            },
            'sizer' : function() {
                var sum = 0;
                for(var i = 0; i < args.length; i++)
                    sum += sizer(args[i]);
                return sum;
            }
        };
    }
    f.reader = reader;
    f.writer = writer;
    f.sizer = sizer;
    return f;
}

function byte(n) {
    var args = arguments;
    return {
        'reader' : function(st) {
            return st.readBytes(n);
        },
        'writer' : function(st, x) {
            for (var i = 0; i < args.length; i++)
                st.writeBytes(args[i]);
        },
        'sizer' : function() {
            var sum = 0;
            for (var i = 0; i < args.length; i++)
                sum += args[i].length;
            return sum;
        }
    };
}
byte.reader = function(st) { return st.readByte(); };
byte.writer = function(st, x) { st.writeByte(x); };
byte.sizer = function(x) { return 1; };

uint8 = type(
    function(st) { return st,readByte(); },
    function(st, x) { st.writeByte(x); },
    function(x) { return 1; }
);

uint32 = type(
    function(st) { return st.readInt(); },
    function(st, x) { st.writeInt(x); },
    function(x) { return 4; }
);

uint64 = type(
    function(st) {
        var high = st.readInt();
        var low = st.readInt();
        return (high * 4294967296) + low; // TODO: floating point!
    },
    function(st, x) { throw 'not implemented'; },
    function(x) { return 8; }
);

string = type(
    function(st) {
        var len = st.readInt();
        return st.readBytes(len);
    },
    function(st, x) {
        st.writeInt(x.length);
        st.writeBytes(x);
    },
    function(x) { return x.length + 4; }
);

utf8 = type(
    function(st) {
        return string.reader(st).toString('utf8'); 
    },
    function(st, x) {
        string.writer(st, new Buffer(x, 'utf8'));
    },
    function(x) {
        return new Buffer(x, 'utf8').length + 4;
    }
);

ascii = type(
    function(st) {
        return string.reader(st).toString('ascii');
    },
    function(st, x) {
        string.writer(st, new Buffer(x, 'ascii'));
    },
    function(x) {
        return x.length + 4;
    }
);

// TODO: more robust
namelist = type(
    function(st) { return ascii.reader(st).split(','); },
    function(st, x) { ascii.writer(st, x.join(',')); },
    function(x) {
        var sum = x.length - 1; // commas
        for (var i = 0; i < x.length; i++)
            sum += x[i].length;
        return sum + 4;
    }
);

// TODO
mpint = type(
    string.reader,
    null, 
    null
);

eof = type(
    function(st) { 
        if (!st.eof()) 
            throw 'end of message missing'; 
        return null; 
    },
    null,
    null
);

function parse_(buffer, args) {
    // this parses buffer, throws exception on error
    var state = new State(buffer);
    var fields = [];
    for (var i = 0; i < args.length; i++) {
        var v = args[i].reader(state);
        if (v !== null)
            fields.push(v);
    } 
    return fields;
}

function parse(buff, args, names) {
    var fields = args.length;
    args.push(eof);
    var results = parse_(buff, args);
    if (!names)
        return results;

    var result = {};
    for (var i=0; i < fields; i++) {
        result[names[i]] = results[i];
    }
    return result;
}

function record(buff, fields) {
    var args = [];
    var names = [];
    for (var i = 0; i < fields.length; i+= 2) {
        names.push(fields[i]);
        args.push(fields[i+1]);
    }
    // console.log(names, args);
    return parse(buff, args, names);
}

function size(args) {
    var s = 0;
    for (var i = 0; i < args.length; i++)
        s += args[i].sizer();
    return s;
}

/* Writing */

function build(args) {
    var buffer = new Buffer(size(args));
    var state = new State(buffer);
    for (var i = 0; i < args.length; i++)
        args[i].writer(state);
    if (!state.eof())
        throw 'eof assertion error';
    return buffer;
}

function PacketWriter() {
    // TODO: handle mac and padding length

    var self = this;
    var minimal = 4;
    var block = 8;

    self.write = function(payload) {
        var total = 4 + 1 + payload.length;
        var padlen = block - (total % block);
        if (padlen < minimal)
            padlen += block;
        total += padlen;
        var padding = new Buffer(padlen); // TODO: make it truly random
        var packet = [ uint32(total - 4), uint8(padlen), byte(payload), byte(padding) ];
        console.log(padlen);
        var x = build(packet);
        console.log(999);
        return x;
    }

    self.write_data = function(args) {
        var payload = build(args);
        return self.write(payload);
    }
}


exports.PacketWriter = PacketWriter;
exports.size = size;
exports.build = build;
exports.parse = parse;

exports.byte = byte;
exports.uint32 = uint32;
exports.namelist = namelist;
exports.record = record;

if (false) {
    buff = new Buffer([ 0, 0, 1, 0, 0x29, 0xb7, 0xf4, 0xaa ]);
    testing = new Buffer([ 0, 0, 0, 7, 116, 101, 115, 116, 105, 110, 103 ]);
    names = new Buffer([ 0x0, 0x0, 0x0, 0x09, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65,
            0x0, 0x0, 0x0, 0x09, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65, 17 ]);

    console.log(parse(buff, [ byte(5), byte(3) ]));
    console.log(parse(buff, [ uint32(2) ]));
    console.log(parse(buff, [ uint64 ]));

    console.log(parse(testing, [ string ]));
    console.log(parse(testing, [ utf8 ] ));

    console.log(parse(names, [ namelist(2), byte ]));


    console.log(build([ uint32(17), uint32(4), utf8('gęś') ]));
    console.log(build([ namelist([ 'A', 'B', 'C' ], [ 'D', 'E', 'F' ]) ]));
}

