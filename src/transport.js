
// Transport layer
// RFC 4253

var utils = require('./utils.js'),
    data = require('./data.js'),
    numbers = require('./numbers.js'),
    crypto = require('crypto'),
    log = require('./log.js'),
    algos = require('./algos.js'),
    fs = require('fs');

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
            wait_predicate = null;
            cb(buf, self); // calls callback
        }
    }

    self.get_buffer = function() {
        return buffer;
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

    self.peek_size = function(size, cb) {
        // waits for 'size' bytes but does not consume
        self.wait_for(cb, function(buf) {
            return (buf.length >= size) ? 0 : null;
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
    data.namelist([ 'aes128-cbc', '3des-cbc' ]),
    data.namelist([ 'aes128-cbc', '3des-cbc' ]),
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

function HmacOpenSSL(name, key) {
    var self = {};

    self.digest = function(bytes) {
        var hmac = crypto.createHmac(name, key);
        hmac.update(bytes);
        return new Buffer(hmac.digest('hex'), 'hex');
    }

    self.size = 20;

    return self;
}

function HmacSha1(key) {
    return HmacOpenSSL('sha1', key);
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
    var keys = {
        // pick key lengths for negotiated algos
        iv_client : derive_key('A', 16),
        iv_server : derive_key('B', 16),
        enc_client : derive_key('C', 16),
        enc_server : derive_key('D', 16),
        int_client : derive_key('E', 20),
        int_server : derive_key('F', 20)
    }
    return keys;
}

function peek_type(msg) {
    return data.parse_array(msg.slice(0, 1), [ data.byte(1) ])[0];
}

function TransportBuffer(socket) {
    
    var self = BasicBuffer();
    var seq = 0;  // sequence number

    var params = {
        client_preamble : 'SSH-2.0-SSHode :)',
        block_size : 8,
        hmac_client : null,
        cipher_client : null
    };

    self.write = function(bytes) {
        socket.write(bytes);
        return bytes;
    }

    self.write_raw_packet = (function() {
        var minimal_padding = 4;

        var dump = function(payload) {
            var block = params.block_size;
            var total = 4 + 1 + data.size(payload);
            var padlen = block - (total % block);
            if (padlen < minimal_padding)
                padlen += block;
            total += padlen;
            var packet = [ 
                data.uint32(total - 4), // size
                data.byte(padlen),      // padding length
                payload,                // payload
                data.random(padlen)     // random padding
            ];
            var bytes = data.serialize(packet);
            var original = bytes;
            if (params.cipher_client) {
                bytes = params.cipher_client.encrypt_msg(bytes);
            }
            if (params.hmac_client) { // if HMAC is in use
                var m = data.serialize([
                    data.uint32(seq),
                    data.bytes(original)
                ]);
                var mac = params.hmac_client.digest(m);
                bytes = data.join([bytes, mac]);
            }
            seq += 1; // increment sequence number
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

    self.send_ignore = function() {
        return self.write_packet(numbers.SSH_MSG_IGNORE, data.string('ignore me'));
    }

    self.send_debug = function(msg) {
        return self.write_packet(numbers.SSH_MSG_DEBUG, [
            data.boolean(true),
            data.utf8('!!!!! ' + msg + ' !!!!!'),
            data.string('*')
        ]);
    }

    self.send_disconnect = function(msg) {
        if (!msg)
            msg = '';
        return self.write_packet(numbers.SSH_MSG_DISCONNECT, [
            data.uint32(4),
            data.utf8(msg),
            data.string('*')
        ]);
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

    self.wait_for_new_keys = function(cb) {
        self.wait_for_raw_packet(function(payload) {
            if (payload.length != 1)
                throw 'Wrong NEW_KEYS!';
            var o = data.parse_object(payload, [ data.byte('type') ]);
            if (o.type != numbers.SSH_MSG_NEWKEYS)
                throw 'Wrong NEW_KEYS (2)!'
            cb();
        });
    }

    self.establish = function(cb) {
        self.on_established = cb;
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
        // TODO: actually negotiate
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

        log.show('Hash verification: ' + result);
        log.show('Hash: ' + params.kex.get_h().toString('hex'));

        if (!result)
            throw 'Hash does not compute!';

        self.write_packet(numbers.SSH_MSG_NEWKEYS, []);

        params.session_id = params.kex.get_h(); // "hash H from the 1st exchange is used as the session id"
        params.keys = derive_keys(params.kex, params.session_id);

        // TODO: use negotiated algos

        params.cipher_client = new algos.AesCbc(params.keys.enc_client, 
            params.keys.iv_client);
        params.cipher_server = new algos.AesCbc(params.keys.enc_server,
            params.keys.iv_server);

        params.hmac_client = HmacSha1(params.keys.int_client);
        params.hmac_server = HmacSha1(params.keys.int_server);

        params.block_size = 16; // set packet block_size

        self.wait_for_new_keys(self.on_new_keys);
    }

    self.wait_for_pkt = function(cb) {
        self.peek_size(16, function(_, buffer) {
            var bytes = buffer.get_buffer().slice(0, 16);
            var o = params.cipher_server.peek(bytes);
            var lens = data.parse_array(o.slice(0, 5), [ data.uint32, data.byte ]);
            var len = lens[0];
            var padlen = lens[1];
            var maclen = params.hmac_server.size;
            self.wait_for_size(4 + len, function(rest) {
                rest = params.cipher_server.decrypt_msg(rest);
                var pkt = data.parse_object(rest, [
                    data.uint32('len'),
                    data.byte('padlen'),
                    data.bytes('payload', len - padlen - 1),
                    data.bytes('padding', padlen)
                ]);
                self.wait_for_size(maclen, function(hmac) {
                    params.hmac_server.digest(rest);
                    // TODO: dont ignore
                    cb(pkt.payload);
                });
            });
        });
    }

    self.wait_for_pkt_type = function(type, cb) {
        self.wait_for_pkt(function(payload) {
            var t = peek_type(payload);
            if (t != type)
                throw 'wrong packet';
            cb(payload);
        });
    }

    self.wait_for_service_accept = function(cb) {
        self.wait_for_pkt_type(numbers.SSH_MSG_SERVICE_ACCEPT, function(payload) {
            var o = data.parse_object(payload, [
                data.byte('type'),
                data.utf8('service_name')
            ]);
            // check service
            cb();
        });
    }

    self.request_auth = function() {
        return self.write_packet(numbers.SSH_MSG_SERVICE_REQUEST, [
            data.string('ssh-userauth')
        ]);
    }

    self.on_new_keys = function() {
        self.request_auth();
        self.wait_for_service_accept(function() {
            self.perform_auth();
        });
    }

    self.perform_auth = function() {
        var creds = fs.readFileSync('./creds.json', 'utf8');
        creds = JSON.parse(creds);
        self.write_packet(numbers.SSH_MSG_USERAUTH_REQUEST, [
            data.utf8(creds.user),
            data.utf8('ssh-connection'),
            data.utf8('password'),
            data.boolean(false),
            data.utf8(creds.pass)
        ]);
        self.wait_for_pkt(function(payload) {
            var t = peek_type(payload);
            if (t != numbers.SSH_MSG_USERAUTH_SUCCESS)
                throw 'error';
            // TODO
            self.on_established(self);
        });
    }


    self.request_session = function(cb) {
        self.write_packet(numbers.SSH_MSG_CHANNEL_OPEN, [
            data.utf8('session'),
            data.uint32(42), // TODO
            data.uint32(1000),
            data.uint32(512)
        ]);
        self.wait_for_pkt(function(payload) {
            var type = peek_type(payload);
            if (type != numbers.SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
                throw 'error';
            var o = data.parse_object(payload, [
                data.byte('type'),
                data.uint32('recipient_channel'),
                data.uint32('sender_channel'),
                data.uint32('window_size'),
                data.uint32('max_packet_size')
            ]);
            console.log(o);
            cb();
        });
    }

    self.exec = function(cmd, cb) {
        // executes a command
        self.request_session(function(session) {
            self.write_packet(numbers.SSH_MSG_CHANNEL_REQUEST, [
                data.uint32(0),
                data.utf8('exec'),
                data.boolean('true'),
                data.utf8(cmd)
            ]);
            self.wait_for_pkt(function(payload) {
                if (peek_type(payload) != 
                    numbers.SSH_MSG_CHANNEL_WINDOW_ADJUST)
                    throw 'window error';
                var o = data.parse_object(payload, [
                    data.byte('type'),
                    data.uint32('recipient_channel'),
                    data.uint32('bytes')
                ]);
                self.handle_data(cb);
            });
        });
    }

    self.handle_data = function(cb) {
        self.wait_for_pkt(function(payload) {
            // SSH_MSG_CHANNEL_SUCCESS
            self.wait_for_pkt(function(p) {
                // SSH_MSG_CHANNEL_DATA
                var o = data.parse_object(p, [
                    data.byte('type'),
                    data.uint32('recipient_channel'),
                    data.string('data')
                ]);
                cb(o.data);
            });
        });
    }


    return self;
}

exports.TransportBuffer = TransportBuffer;
exports.DSAKey = DSAKey;
