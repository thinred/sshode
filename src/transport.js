
// Transport layer
// RFC 4253

var utils = require('./utils.js'),
    data = require('./data.js'),
    numbers = require('./numbers.js'),
    crypto = require('crypto');

function BasicBuffer() {
    var self = new Object();
    var buffer = new Buffer(0);
    var wait_predicate = null;
    var wait_callback = null;

    self.feed = function(data) {
        buffer = utils.concat(buffer, data);
        self.trigger(); 
    }

    self.trigger = function() {
        if (wait_predicate === null)
            return;
        var size = wait_predicate(buffer);
        if (size !== null) { 
            var buf = buffer.slice(0, size);
            buffer = buffer.slice(size);
            var cb = wait_callback;
            wait_callback = null;
            cb(buf, self); // calls callback
        }
    }

    self.wait_for = function(cb, predicate) {
        wait_predicate = predicate;
        wait_callback = cb;
        self.trigger();
    }

    self.wait_for_line = function(cb) {
        // waits for a line to show up
        self.wait_for(cb, function(buf) {
            var pos = utils.index_of(buf, '\r\n');
            return (pos >= 0) ? (pos + 2) : null;
        });
    }

    self.wait_for_size = function(size, cb) { 
        // waits for 'size' bytes to show up
        self.wait_for(cb, function(buf) { 
            return (buf.length >= size) ? size : null;
        });
    }

    self.wait_for_array = function(spec, cb) {
        var size = data.size(spec);
        self.wait_for_size(size, function(buf) {
            cb(data.parse_array(buf, spec));
        });
    }

    self.wait_for_object = function(spec, cb) {
        var size = data.size(spec);
        self.wait_for_size(size, function(buf) {
            cb(data.parse_object(buf, spec));
        });
    }

    self.wait_for_raw_packet = function(cb) {
        // gives packet payload to the callback
        var header = [ data.uint32('size'), data.byte('padlen') ];
        self.wait_for_object(header, function(o) {
            var content = [ data.bytes(o.size - o.padlen - 1), data.bytes(o.padlen) ];
            self.wait_for_array(content, function(arr) {
                cb(arr[0]);
            });
        });
    }

    self.wait_for_packet = function(cb) {
        self.wait_for_raw_packet(function(payload) {
            var n = payload.length;
            var o = data.parse_object(payload,
                [ data.byte('type'), data.bytes('rest', n - 1) ]
            );
            cb(o.type, o.rest);
        });
    }

    return self;
}

var KEX_INIT_THIS = [
    data.byte(numbers.SSH_MSG_KEXINIT),
    data.random(16),
    data.namelist([
        'diffie-hellman-group1-sha1',
        'diffie-hellman-group14-sha1' 
    ]),
    data.namelist([ 'ssh-dss' ]),
    data.namelist([ '3des-cbc' ]),
    data.namelist([ '3des-cbc' ]),
    data.namelist([ 'hmac-sha1' ]),
    data.namelist([ 'hmac-sha1' ]),
    data.namelist([ 'none' ]),
    data.namelist([ 'none' ]),
    data.namelist([ '' ]),
    data.namelist([ '' ]),
    data.boolean(false),
    data.uint32(0)
];

var KEX_INIT = [
    data.byte('type'),
    data.bytes('random', 16),
    data.namelist('kex_algos'),
    data.namelist('server_host_key_algos'),
    data.namelist('enc_client'),
    data.namelist('enc_server'),
    data.namelist('mac_client'),
    data.namelist('mac_server'),
    data.namelist('com_client'),
    data.namelist('com_server'),
    data.namelist('lan_client'),
    data.namelist('lan_server'),
    data.boolean('packet_follows'),
    data.uint32('reserved')
];

var KEXDH_REPLY = [
    data.byte('type'),
    data.string('server_certs'),
    data.mpint('f'),
    data.string('signature')
];


function DHAlgorithm(name) {
    // small wrapper around node.js DH (which has weird interface)
    var self = {};
    var dh = crypto.getDiffieHellman(name);
    dh.generateKeys();

    self.get_pubkey = function() {
        return data.mpint(dh.getPublicKey('hex'), 16);
    }

    self.exchange = function(other) {
        var other_key = other.toString(16); // to hex
        var secret = dh.computeSecret(other_key, 'hex', 'hex');
        return data.mpint(secret, 16);
    }

    return self;
}


function TransportBuffer(socket) {
    
    var self = BasicBuffer();

    var IDENT = 'SSH-2.0-NodeJS TB2011';
    var params = {};

    self.write = function(bytes) {
        return socket.write(bytes);
    }

    self.write_raw_packet = (function() {
        var minimal = 4;
        var block = 8;

        // TODO: handle mac and other paddings

        var dump = function(payload) {
            var total = 4 + 1 + data.size(payload);
            var padlen = block - (total % block);
            if (padlen < minimal)
                padlen += block;
            total += padlen;
            var packet = [ 
                data.uint32(total - 4), // size
                data.byte(padlen),      // padding length
                payload,                // payload
                data.random(padlen)     // random padding
            ];
            return data.serialize(packet);
        }

        return function(payload) {
            return socket.write(dump(payload));
        }
    })();

    self.write_packet = function(type, spec) {
        return self.write_raw_packet([ data.byte(type), spec ]);
    }

    self.wait_for_preamble = function(cb) {
        // RFC says to ignore every line till it starts with 'SSH-'
        self.wait_for_line(function(buf) {
            var found = (utils.index_of(buf, 'SSH-') != -1);
            return (found ? cb(buf.slice(0, buf.length - 2)) : self.wait_for_preamble(cb));
        });
    }

    self.wait_for_kexinit = function(cb) {
        self.wait_for_raw_packet(function(payload) {
            var o = data.parse_object(payload, KEX_INIT);
            if (o.type != numbers.SSH_MSG_KEXINIT)
                throw 'Wrong KEXINIT!';
            cb(o);
        });
    }

    self.wait_for_kexdh_reply = function(cb) {
        self.wait_for_raw_packet(function(payload) {
            var o = data.parse_object(payload, KEXDH_REPLY);
            if (o.type != numbers.SSH_MSG_KEXDH_REPLY)
                throw 'Wrong KEXDH_REPLY!';
            cb(o);
        });
    }   

    self.send_preamble = function() {
        socket.on('connect', function() {
            self.write(IDENT + '\r\n');
            self.write_raw_packet(KEX_INIT_THIS);
        });
    }

    self.establish = function() {
        self.send_preamble();
        self.wait_for_preamble(self.on_preamble);
    }

    // logic

    self.on_preamble = function(preamble) {
        params.preamble = preamble;
        self.wait_for_kexinit(self.on_kexinit);
    }

    self.on_kexinit = function(kex) {
        // sending kexdh
        params.kex = DHAlgorithm('modp2');
        self.write_packet(numbers.SSH_MSG_KEXDH_INIT, [ params.kex.get_pubkey() ]);
        self.wait_for_kexdh_reply(self.on_kexdh_reply)
    }

    self.on_kexdh_reply = function(reply) {
        params.shared_secret = params.kex.exchange(reply.f);
    }

    return self;
}

exports.TransportBuffer = TransportBuffer;
