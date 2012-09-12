
// Building/parsing packets

var data = require('./data.js');
var numbers = require('./numbers.js');

function PacketManager() {
    // TODO: handle mac and padding length

    var self = new Object();
    var minimal = 4;
    var block = 8;

    self.write = function(payload) {
        var total = 4 + 1 + data.size(payload);
        var padlen = block - (total % block);
        if (padlen < minimal)
            padlen += block;
        total += padlen;
        var packet = [ 
            data.uint32(total - 4), 
            data.byte(padlen),
            payload,
            data.random(padlen) 
        ];
        return data.serialize(packet);
    }

    self.preamble = function() {
        return self.write(ThisPreamble);
    }

    return self;
}

ThisPreamble = [
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

exports.PacketManager = PacketManager;
