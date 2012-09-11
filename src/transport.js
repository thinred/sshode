
// Transport layer
// RFC 4253

var utils = require('./utils.js');

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

    return self;
}

function TransportBuffer() {
    var self = BasicBuffer();

    self.wait_for_preamble = function(cb) {
        // RFC says to ignore every line till it starts with 'SSH-'
        self.wait_for_line(function(buf) {
            var found = (utils.index_of(buf, 'SSH-') != -1);
            return (found ? cb(buf) : self.wait_for_preamble(cb));
        });
    }

    return self;
}


exports.TransportBuffer = TransportBuffer;
