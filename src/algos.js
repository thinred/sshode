
var c = require('crypto');

function xor(m1, m2) {
    if (m1.length != m2.length)
        throw m1.length + ' != ' + m2.length;
    var b = new Buffer(m1.length);
    for (var i=0; i < b.length; i++) {
        b[i] = m1[i] ^ m2[i];
    }
    return b;
}

function assert_block(block) {
    if (!Buffer.isBuffer(block))
        throw 'not buffer';
    if (block.length != 16)
        throw 'wrong size (' + block.length + ')';
}

function assert_block_size(block) {
    if (!Buffer.isBuffer(block))
        throw 'not buffer';
    if (block.length % 16 != 0)
        throw 'wrong size (' + block.length + ')';
}

function AesCbc(key, iv) {
    var self = this;
    var name = 'AES-ERROR';
    if (key.length == 16)
        name = 'AES-128-ECB';
    else if (key.length == 24)
        name = 'AES-192-ECB';
    else if (key.length == 32)
        name = 'AES-256-ECB';
    self.name = name;

    var _encryptor = null;
    var _decryptor = null;
    
    var current = iv;

    function encryptor() {
        if (_encryptor == null) {
            _encryptor = c.createCipheriv(name, key, '');
            _encryptor.setAutoPadding(false);
        }
        return _encryptor;
    }

    function decryptor() {
        if (_decryptor == null) {
            _decryptor = c.createDecipheriv(name, key, '');
            _decryptor.setAutoPadding(false);
        }
        return _decryptor;
    }

    function mangle_block(mangler, msg) {
        // console.log('msg =', msg);
        var bytes = mangler.update(msg, null, 'binary');
        // console.log("len =", bytes.length);
        var buffer = new Buffer(bytes, 'binary');
        return buffer;
    }

    self.encrypt = function encrypt(msg) {
        // must be 16 bytes
        assert_block(msg);
        var b = xor(msg, current);
        current = mangle_block(encryptor(), b);
        return current;
    }

    self.encrypt_msg = function(msg) {
        assert_block_size(msg);
        var buff = new Buffer(msg.length);
        for (var i = 0; i < msg.length; i += 16) {
            var part = self.encrypt(msg.slice(i, i + 16));
            part.copy(buff, i);
        }
        return buff;
    }

    self.peek = function peek(msg) {
        // like decrypt, but does not move the pointer
        assert_block(msg);
        var b = mangle_block(decryptor(), msg);
        return xor(b, current);
    }

    self.peek_msg = function peek_msg(msg) {
        // peeks from message
        if (msg.length < 16)
            throw 'message to short';
        return self.peek(msg.slice(0, 16));
    }

    self.decrypt = function decrypt(msg) {
        var pt = self.peek(msg);
        current = msg;
        return pt;
    }

    self.decrypt_msg = function(msg) {
        assert_block_size(msg);
        var buff = new Buffer(msg.length);
        for (var i = 0; i < msg.length; i += 16) {
            var part = self.decrypt(msg.slice(i, i + 16));
            part.copy(buff, i);
        }
        return buff;
    }

    self.block_size = 16;
}

if (false) {
    var key = new Buffer('123456789abcdef;');
    var x =   new Buffer('tomekbuchertyoyo');

    var enc = new AesCbc(key, key);
    var dec = new AesCbc(key, key);

    var e = enc.encrypt(x);

    var u = dec.peek(e);
    var o = dec.decrypt(e);
}

exports.AesCbc = AesCbc;
