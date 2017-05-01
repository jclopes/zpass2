// Derives a password from a scret + uri.
// The derived password string will be passed to the callback function as the
// only argument.
function zpass2(secret, uri, callback) {
    var res = secret+'@'+uri;
    var salt = new buffer.Buffer("6dYX3t1X402Q3b72T1eYa1D2520".normalize('NFKD'), 'utf8');

    // scrypt configuration
    var N = 1 << 12;
    var r = 1 << 3;
    var p = 1;
    var dkLen = 32;

    do {
        var password = new buffer.Buffer(res.normalize('NFKD'), 'utf8');
        var key = scrypt(password, salt, N, r, p, dkLen);
        key = new buffer.SlowBuffer(key);
        res = postProcess(key);
    } while(!checkComplexity(res));
    callback(res)
}

// Ensures that the derived password complies to the requirements of diversity
// and length.
function postProcess(key) {
    key = bytesToBase62(key);
    key = key.slice(0,16);
    return key;
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

function checkComplexity(text) {
    var hasNumber = /\d/;
    var hasUpper = /[A-Z]/;
    var hasLower = /[a-z]/;
    var res = (hasNumber.test(text) && hasUpper.test(text) && hasLower.test(text));
    return res;
}
