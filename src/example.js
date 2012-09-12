
var net = require('net'),
    t = require('./transport.js'),
    p = require('./packet.js');

function SSHSocket(self) {
    var buffer = t.TransportBuffer();
    var writer = p.PacketManager();

    self.on('data', buffer.feed);

    buffer.wait_for_preamble(function(buf) {
        console.log('Preamble: ' + buf.toString());
    });

    self.on('connect', function() {
        self.write('SSH-2.0-NodeJS TB2011\r\n');
        self.write(writer.preamble());
    });

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

