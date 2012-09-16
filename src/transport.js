
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
    data.string('host_key'),
    data.mpint('f'),
    data.string('signature')
];

function parseDSAKey(key) {
    var o = data.parse_object(key, [
        data.utf8('name'),
        data.mpint('p'), data.mpint('q'),
        data.mpint('g'), data.mpint('y')
    ]);
    if (o.name != 'ssh-dss')
        throw "Wrong key type?";
    return DSAKey(o);
}

function DSAKey(self) {

    self.verify = function(msg, signature) {
        var o = data.parse_object(signature,
            [ data.utf8('name'), data.string('blob') ]
        );
        if (o.name != 'ssh-dss' || o.blob.length != 40)
            throw "Wrong signature?";
        var parts = data.parse_object(o.blob, [ data.bytes('r', 20), data.bytes('s', 20) ]);
        var r = data.to_mpint(parts.r),
            s = data.to_mpint(parts.s);

        if (r.compareTo(self.q) != -1)
            return false;
        if (s.compareTo(self.q) != -1)
            return false;

        var digest_bytes = utils.sha1(msg),
            digest = data.to_mpint(digest_bytes);

        var w = s.modInverse(self.q),
            u1 = digest.multiply(w).mod(self.q),
            u2 = r.multiply(w).mod(self.q),
            v1 = self.g.modPow(u1, self.p),
            v2 = self.y.modPow(u2, self.p),
            v = v1.multiply(v2).mod(self.p).mod(self.q);

        return v.compareTo(r) == 0;
    }

    return self;
}

function DHAlgorithm(name) {
    // small wrapper around node.js DH
    var self = { e : null, f : null, secret : null, h : null };
    var dh = crypto.getDiffieHellman(name);
    dh.generateKeys();
    self.e = data.mpint(dh.getPublicKey('hex'), 16);

    self.exchange = function(f) {
        if (self.secret)
            throw "Key exchanged many times?";
        var other_key = f.toString(16);
        var secret = dh.computeSecret(other_key, 'hex', 'hex');
        self.secret = data.mpint(secret, 16);
        self.f = data.mpint(other_key, 16);
        return self.secret;
    }

    var get_attr = function(name, err) {
        return function() {
            var value = self[name];
            if (!value) throw err;
            return value;
        }
    }

    self.get_e = get_attr('e', 'Fatal error');
    self.get_f = get_attr('f', 'Keys not exchanged');
    self.get_secret = get_attr('secret', 'Keys not exchanged');
    self.get_h = get_attr('h', 'Hash not computed');

    self.compute_h = function(params) {
        var content = data.serialize([
            data.string(params.client_preamble), // client identification string
            data.string(params.server_preamble), // server identification string
            data.string(params.client_kex_payload), // payload of client's KEXINIT
            data.string(params.server_kex_payload), // payload of server's KEXINIT
            data.string(params.host_key_payload), // the host key of the server
            params.kex.get_e(),
            params.kex.get_f(),
            params.kex.get_secret()
        ]);

        self.h = utils.sha1(content);
        return self.h;
    }

    self.hash = utils.sha1;

    return self;
}

function derive_keys(algo, session_id) {
    // derives keys (section 7.2)
    var derive_key = function(ch, size) {
        var tail = [ data.bytes(ch), data.bytes(session_id) ];
        var key = new Buffer(0);
        while (key.length < size) {
            var bytes = data.serialize([
                algo.get_secret(),
                data.bytes(algo.get_h()),
                tail ]);
            bytes = algo.hash(bytes);
            key = data.serialize([ data.bytes(key), data.bytes(bytes) ]);
            tail = data.bytes(key);
        }
        return key.slice(0, size);
    }
    var keys = {};
    keys.iv_client = derive_key('A', 24);
    keys.iv_server = derive_key('B', 24);
    keys.enc_client = derive_key('C', 24);
    keys.enc_server = derive_key('D', 24);
    keys.int_client = derive_key('E', 24);
    keys.int_server = derive_key('F', 24);
    return keys;
}


function TransportBuffer(socket) {
    
    var self = BasicBuffer();

    var params = {
        client_preamble : 'SSH-2.0-SSHode :)'
    };

    self.write = function(bytes) {
        socket.write(bytes);
        return bytes;
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
            var bytes = data.serialize(packet);
            return {
                'bytes': bytes,
                'payload' : bytes.slice(4 + 1, bytes.length - padlen)
            }
        }

        return function(payload) {
            var packet = dump(payload);
            self.write(packet.bytes);
            return packet;
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
            cb(o, payload);
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
            self.write(params.client_preamble + '\r\n');
            var kexinit = self.write_raw_packet(KEX_INIT_THIS);
            params.client_kex_payload = kexinit.payload; // used in hash computation
        });
    }

    self.establish = function() {
        self.send_preamble();
        self.wait_for_preamble(self.on_preamble);
    }

    // Business logic of the protocol

    self.on_preamble = function(preamble) {
        params.server_preamble = preamble;
        self.wait_for_kexinit(self.on_kexinit);
    }

    self.on_kexinit = function(kex, payload) {
        // sending kexdh
        params.server_kex_payload = payload; // used in hash computation
        params.kex = DHAlgorithm('modp2');
        self.write_packet(numbers.SSH_MSG_KEXDH_INIT, [ params.kex.get_e() ]);
        self.wait_for_kexdh_reply(self.on_kexdh_reply);
    }

    self.on_kexdh_reply = function(reply) {
        params.host_key_payload = reply.host_key;
        params.host_key = parseDSAKey(reply.host_key);
        params.kex.exchange(reply.f);
        params.kex.compute_h(params);

        var result = params.host_key.verify(params.kex.get_h(), reply.signature);

        console.log('Hash verification: ' + result);
        console.log('Hash: ' + params.kex.get_h().toString('hex'));

        params.session_id = params.kex.get_h(); // "hash H from the 1st exchange is used as the session id"

        console.log(derive_keys(params.kex, params.session_id));
    }

    return self;
}

exports.TransportBuffer = TransportBuffer;
exports.DSAKey = DSAKey;
