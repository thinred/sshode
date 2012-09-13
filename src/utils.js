
/* Various utils */

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

function is_array(v) {
    return (v.constructor.name === 'Array');
}

function is_string(v) {
    return (typeof v === 'string');
}

function is_number(v) {
    return (typeof v === 'number');
}

function is_bigint(v) {
    return (!!v.divideAndRemainder);
}

function flatten_iter(array, f) {
    var stack = [ [array, 0] ];

    while(stack.length != 0) {
        var n = stack.length;
        var el = stack[n-1], arr = el[0], idx = el[1], it = arr[idx];
        if (idx == arr.length) {
            stack.pop();
        } else {
            stack[n-1] = [ arr, idx + 1 ];
            if (is_array(it)) {
                stack.push([ it, 0 ]);
            } else {
                f(it);
            }
        } // if
    } // while
}

function flatten(array) {
    var arr = [];
    flatten_iter(array, function(x) {
        arr.push(x);
    });
    return arr;
}

exports.is_array = is_array;
exports.is_string = is_string;
exports.is_bigint = is_bigint;
exports.is_number = is_number;
exports.concat = concat;
exports.index_of = index_of;
exports.flatten_iter = flatten_iter;
exports.flatten = flatten;
