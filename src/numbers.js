
/*
 *  RFC 4250
 */

// SSH-TRANS
exports.SSH_MSG_DISCONNECT      = 1;
exports.SSH_MSG_IGNORE          = 2;
exports.SSH_MSG_UNIMPLEMENTED   = 3;
exports.SSH_MSG_DEBUG           = 4;
exports.SSH_MSG_SERVICE_REQUEST = 5;
exports.SSH_MSG_SERVICE_ACCEPT  = 6;

exports.SSH_MSG_KEXINIT         = 20;
exports.SSH_MSG_NEWKEYS         = 21;

exports.SSH_MSG_KEXDH_INIT      = 30;
exports.SSH_MSG_KEXDH_REPLY     = 31;

// SSH-USERAUTH
exports.SSH_MSG_USERAUTH_REQUEST = 50;
exports.SSH_MSG_USERAUTH_FAILURE = 51;
exports.SSH_MSG_USERAUTH_SUCCESS = 52;
exports.SSH_MSG_USERAUTH_BANNER  = 53;

// SSH-CONNECT
exports.SSH_MSG_GLOBAL_REQUEST            = 80;
exports.SSH_MSG_REQUEST_SUCCESS           = 81;
exports.SSH_MSG_REQUEST_FAILURE           = 82;
exports.SSH_MSG_CHANNEL_OPEN              = 90;
exports.SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
exports.SSH_MSG_CHANNEL_OPEN_FAILURE      = 92;
exports.SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93;
exports.SSH_MSG_CHANNEL_DATA              = 94;
exports.SSH_MSG_CHANNEL_EXTENDED_DATA     = 95;
exports.SSH_MSG_CHANNEL_EOF               = 96;
exports.SSH_MSG_CHANNEL_CLOSE             = 97;
exports.SSH_MSG_CHANNEL_REQUEST           = 98;
exports.SSH_MSG_CHANNEL_SUCCESS           = 99;
exports.SSH_MSG_CHANNEL_FAILURE           = 100;

// SSH-MSG-DISCONNECT reasons

exports.SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1;
exports.SSH_DISCONNECT_PROTOCOL_ERROR                 = 2;
exports.SSH_DISCONNECT_KEY_EXCHANGE_FAILED            = 3;
exports.SSH_DISCONNECT_RESERVED                       = 4;
exports.SSH_DISCONNECT_MAC_ERROR                      = 5;
exports.SSH_DISCONNECT_COMPRESSION_ERROR              = 6;
exports.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          = 7;
exports.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
exports.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9;
exports.SSH_DISCONNECT_CONNECTION_LOST                = 10;
exports.SSH_DISCONNECT_BY_APPLICATION                 = 11;
exports.SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12;
exports.SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13;
exports.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
exports.SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15;

// Channel connection failure reasons

exports.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
exports.SSH_OPEN_CONNECT_FAILED              = 2;
exports.SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3;
exports.SSH_OPEN_RESOURCE_SHORTAGE           = 4;

