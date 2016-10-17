// Derives a password from a scret + uri.
// The derived password string will be passed to the callback function as the
// only argument.
function zpass2(secret, uri, callback) {
    var password = secret+'@'+uri;
    password = new buffer.Buffer(password.normalize('NFKD'), 'utf8');
    var salt = new buffer.Buffer("6dYX3t1X402Q3b72T1eYa1D2520".normalize('NFKD'), 'utf8');

    // scrypt configuration
    var N = 1 << 12;
    var r = 1 << 3;
    var p = 1;
    var dkLen = 32;

    scrypt(password, salt, N, r, p, dkLen, function(error, progress, key) {
        if (key) {
            key = new buffer.SlowBuffer(key);
            postProcess(key, callback);
        }
    });
}

// Ensures that the derived password complies to the requirements of diversity
// and length.
function postProcess(key, callback) {
    key = bytesToBase62(key);
    key = key.slice(0,32);
    key = ensureComplexity(key);
    callback(key);
}

// Naive Base62 one way encoding.
// byteArray should be an array of UInt8.
function bytesToBase62(byteArray) {
    var b62str = '';
    for (i=0; i < byteArray.length; i++) {
        b62str = b62str + b62encode(byteArray[i]);
    }
    return b62str;
}

function b62encode(byteVal) {
    var chars='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var str = '';
    do {
        var i = byteVal % 62;
        str = chars.charAt(i) + str;
        byteVal = (byteVal - i) / 62;
    } while(byteVal > 0);
    return str;
}

// Make sure the string contains a digit, a lower case letter and a upper case letter
// To achive this the first 3 chars of the text will be converted.
function ensureComplexity(text) {
    var digits = '0123456789';
    var loAlpha = 'abcdefghijklmnopqrstuvwxyz';
    var upAlpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var c0 = text.charCodeAt(0) % 10;
    var c1 = text.charCodeAt(1) % 26;
    var c2 = text.charCodeAt(2) % 26;
    return digits.charAt(c0) + loAlpha.charAt(c1) + upAlpha.charAt(c2) + text.slice(3);
}
