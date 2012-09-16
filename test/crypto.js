
var d = require('../src/data.js'),
    t = require('../src/transport.js'),
    assert = require('assert');

// this was generated using PyCrypto

exampleDSAKey = {
    p : d.to_mpint('800000000000000174cb82eb9e14a69f505c873087e0b5ebddc745c5eea93d6c092f12bebd8f9316b52168b9d7672209e206659f105c54d5a6575277780beec4b824601ee0b5d598d03d06f321eacec47b601ff51ac863a4b6e0228b6e998c2811596da202448daa0cf346668947e415f66a8f674bb517b8060c0c5f68e95be5', 16),
    q : d.to_mpint('934b0cfdbaa5c6d2356705ce0c6b87b829802a41', 16),
    g : d.to_mpint('ce9235d3c5d737041fea18ecf981b1cdd54dc90d7805af5093619b0e3f177b6f025450de672bdb3f31697f906b53edf5aef5441c97e11f496a02df3f2bf5f820efe9eb34fcc2687b5466f1c9286fc51cf945ff6bc389cd841ad2c83b53f254018c257a1e3a04e37f229b837fa9adec41aa72726146d4bb8b9d9677b8b5df94', 16),
    x : d.to_mpint('841bdf331ccd9d702f94f0573c8a9b5f452eee66', 16),
    y : d.to_mpint('44269d1a9e5e3c9912ce76c442f8d69268cf68f8781a7df9b07f94b89c6565329264912dceeb40e0ec07d0866da166a08c992931e044735585f3acaa5b89ed2a519c66ce2a7b19181e92abffadbaf4d1475bac1a8308d92747a5bde70910b6f728427d5e4fc72297995f268c5c8b4f02fe02d9ede7b462c49a2bed8996ca566d', 16)
}

goodSignature = d.serialize([
    d.string('ssh-dss'),
    d.uint32(40),
    d.bytes(new Buffer('7eb786042d656a2406c91abc48d80c541864313b', 'hex')),
    d.bytes(new Buffer('85a476658b6e9e53a5d94e99e5c13fcfc72b4a28', 'hex'))
]);                                             //   |
                                                //   |
badSignature = d.serialize([                    //   |
    d.string('ssh-dss'),                        //   |
    d.uint32(40),                               //   |
    d.bytes(new Buffer('7eb786042d656a2406c91abc48d80f541864313b', 'hex')),
    d.bytes(new Buffer('85a476658b6e9e53a5d94e99e5c13fcfc72b4a28', 'hex'))
]);

exports.run = function() {
    var key = t.DSAKey(exampleDSAKey);
    assert.equal(key.verify('Hello', goodSignature), true);
    assert.equal(key.verify('Hell', goodSignature), false);
    assert.equal(key.verify('Hello', badSignature), false);
    assert.equal(key.verify('Hell', badSignature), false);
}


