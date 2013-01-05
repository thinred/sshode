
var config = {};

config.verbose = false;

function show() {
    if (config.verbose)
        console.log(arguments);
}

function verbose() {
    config.verbose = true;
}

exports.show = show;
exports.verbose = verbose;
