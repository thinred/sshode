
function concat(buf1, buf2) {
    var newbuf = new Buffer(buf1.length + buf2.length);
    buf1.copy(newbuf);
    buf2.copy(newbuf, buf1.length);
    return newbuf;
}

function index_of(buf, patt) {
    patt = new Buffer(patt); // convert to buffer
    for(var i = 0; i < buf.length - patt.length + 1; i++) { 
        var j = 0;
        while(j < patt.length && buf[i+j] == patt[j])
            j++;
        if (j == patt.length)
            return i;
    }
    return -1;
}

exports.concat = concat;
exports.index_of = index_of;
