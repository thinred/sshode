
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
