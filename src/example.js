
var net = require('net'),
    t = require('./transport.js');

function SSHSocket(self, cb) {
    var buffer = t.TransportBuffer(self);

    self.on('data', buffer.feed);

    buffer.establish(cb);

    return buffer;
}

function ssh_connect(host, cb) {
    var client = net.connect(22, host);
    return SSHSocket(client, cb);
}

(function() {
    ssh_connect('localhost', function(c) {
        c.exec('uname', function(out) {
            console.log(out.toString('utf8'));
        });
    });
    // client.setTimeout(2000);

    // client.on('timeout', function() {
    //    client.end();
    // });

})();

