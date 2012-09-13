
var net = require('net'),
    t = require('./transport.js'),
    p = require('./packet.js');

function SSHSocket(self) {
    var buffer = t.TransportBuffer(self);

    self.on('data', buffer.feed);

    buffer.establish();

    return self;
}

function ssh_connect(host) {
    var client = net.connect(22, host);
    return SSHSocket(client);
}

(function() {
    var client = ssh_connect('localhost');
    client.setTimeout(2000);

    client.on('timeout', function() {
        client.end();
    });
})();

