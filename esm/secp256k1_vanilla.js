const CURVE = {
    P: 2n ** 256n - 2n ** 32n - 977n,
    n: 2n ** 256n - 432420386565659656852420866394968145599n,
    magicExp: (2n ** 256n - 2n ** 32n - 977n + 1n) / 4n,
    A: 0n,
    B: 7n
};

class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    // Adds point to itself. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    double() {
        const X1 = this.x;
        const Y1 = this.y;
        const lam = mod(3n * X1 ** 2n * invert(2n * Y1, CURVE.P));
        const X3 = mod(lam * lam - 2n * X1);
        const Y3 = mod(lam * (X1 - X3) - Y1);
        return new Point(X3, Y3);
    }
    // Adds point to other point. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    add(other) {
        const [a, b] = [this, other];
        const [X1, Y1, X2, Y2] = [a.x, a.y, b.x, b.y];
        if (X1 === 0n || Y1 === 0n)
            return b;
        if (X2 === 0n || Y2 === 0n)
            return a;
        if (X1 === X2 && Y1 === Y2)
            return this.double();
        if (X1 === X2 && Y1 === -Y2)
            return Point.ZERO;
        const lam = mod((Y2 - Y1) * invert(X2 - X1, CURVE.P));
        const X3 = mod(lam * lam - X1 - X2);
        const Y3 = mod(lam * (X1 - X3) - Y1);
        return new Point(X3, Y3);
    }
    // Elliptic curve point multiplication with double-and-add algo.
    multiplyDA(n) {
        let p = Point.ZERO;
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }

    isInfinity(){
        return this.x == null || this.y == null;
    }

    equals(other) {
        if (null == other) {
            return false;
        }

        let i1 = this.isInfinity();
        let i2 = other.isInfinity();

        if (i1 || i2) {
            return (i1 && i2);
        }

        let p1 = this;
        let p2 = other;
        return (p1.x === p2.x) && (p1.y === p2.y);
    }

    // Generate a private key
    async generateKey() {
        // using subtlecrypto to generate a key. note that we are using an AES key
        // as an secp256k1 key here, since browsers don't support the latter;
        // that means all the keys must be created exportable to work with.
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt']
        );
        let hex = ['0x'];
        const exported = await crypto.subtle.exportKey('raw', keyPair);
        (new Uint8Array(exported)).forEach(i => {
            var h = i.toString(16);
            if (h.length % 2) { h = '0' + h; }
            hex.push(h);
        });
        // the next line works if AES key is always positive
        return BigInt(hex.join('')) % CURVE.n;
    }
    // Generate a private key
    static async generateKey() {
        // using subtlecrypto to generate a key. note that we are using an AES key
        // as an secp256k1 key here, since browsers don't support the latter;
        // that means all the keys must be created exportable to work with.
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt']
        );
        let hex = ['0x'];
        const exported = await crypto.subtle.exportKey('raw', keyPair);
        (new Uint8Array(exported)).forEach(i => {
            var h = i.toString(16);
            if (h.length % 2) { h = '0' + h; }
            hex.push(h);
        });
        // the next line works if AES key is always positive
        return BigInt(hex.join('')) % CURVE.n;
    }
}
Point.ZERO = new Point(0n, 0n); // Point at infinity aka identity point aka zero

function mod(a, b = CURVE.P) {
    const result = a % b;
    return result >= 0 ? result : b + result;
}

function BnPowMod(base, n, mod) {
    let res = 1n, cur = base;
    while (n > 0n) {
        if (n & 1n)
            res = (res * cur) % mod;
        cur = (cur * cur) % mod ;
        n >>= 1n;
    }
    return res;
}

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
function egcd(a, b) {
    let [x, y, u, v] = [0n, 1n, 1n, 0n];
    while (a !== 0n) {
        let [q, r] = [b / a, b % a];
        let [m, n] = [x - u * q, y - v * q];
        [b, a] = [a, r];
        [x, y] = [u, v];
        [u, v] = [m, n];
    }
    return [b, x, y];
}

function invert(number, modulo = CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('invert: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('invert: does not exist');
    }
    return mod(x, modulo);
}

// G x, y values taken from official secp256k1 document
const G = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n, 32670510020758816978083085130507043184471273380659243275938904335757337482424n);

function getPublicKey(privKey) {
    return G.multiplyDA(privKey);
}

function zero2(word) {
    if (word.length === 1)
        return '0' + word;
    else
        return word;
}

function toHex(msg) {
    var res = '';
    for (var i = 0; i < msg.length; i++)
        res += zero2(msg[i].toString(16));
    return res;
}

function stringToHex(str) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}

function stringToArray(str) {
    var arr = [];
    for(var i=0;i<str.length;i++) {
        arr.push(str.charCodeAt(i));
    }
    return arr;
}

function AttestationCrypto(){
    this.rand = randomBigInt(32);
}

AttestationCrypto.prototype.makeRiddle = function(identity, type, secret){
    // hash email
    let hashedIdentity = this.hashIdentifier(type, identity);
    console.log(hashedIdentity);
    let makeRiddle = hashedIdentity.multiplyDA(secret);
    console.log("secret = " , secret);
    // console.log(makeRiddle);
    console.log(makeRiddle.x.toString(16));
    console.log(makeRiddle.y.toString(16));
    // return hashedIdentity.multiplyDA(secret).getEncoded(false);
}
AttestationCrypto.prototype.hashIdentifier = function(type, identity) {
    // console.log("identifier = "+identity);
    idenNum = this.mapToInteger(type, stringToArray(identity.trim().toLowerCase()));
    console.log("idenNum = "+idenNum);
    return this.computePoint(idenNum);
}
AttestationCrypto.prototype.mapToInteger = function(type, arr ) {
    // add prefix [0,0,0,1] for email type
    let prefix = type === "mail" ? [0,0,0,1] : [0,0,0,0];
    return mod(BigInt('0x' + keccak256(prefix.concat(arr))) );
}
AttestationCrypto.prototype.computePoint = function( x ) {
    x = mod ( x );
    let y = 0n, expected = 0n, ySquare = 0n;
    let resPoint;
    let p = CURVE.P;
    let a = CURVE.A;
    let b = CURVE.B;
    // do {
        do {
            x = mod(x + 1n);
            // console.log("x+1 = "+x);
            ySquare = mod(BnPowMod (x, 3n, p) + a * x + b );
            console.log("ySquare = "+ySquare);
            y = BnPowMod(ySquare, CURVE.magicExp, p);
            expected = mod(y * y);
            console.log("y*y = "+expected);
        } while (expected !== ySquare);
        resPoint = new Point(x, y);
        referencePoint = resPoint.multiplyDA( CURVE.n - 1n);
    // } while (!resPoint.equals(referencePoint) )
    // negateRefPoint = referencePoint.negate();
    console.log("resPoint = ",resPoint);
    console.log("resPointY = ",resPoint.y.toString(16));
    console.log("referencePoint = ",referencePoint);
    console.log("referencePointY = ",referencePoint.y.toString(16));
    return resPoint;
}


function randomBigInt(bytes) {
    var cryptoObj = window.crypto || window.msCrypto; // IE 11
    let u8 = cryptoObj.getRandomValues(new Uint8Array(bytes));
    let hex = [];
    u8.forEach(function (i) {
        var h = i.toString(16);
        if (h.length % 2) { h = '0' + h; }
        hex.push(h);
    });

    return BigInt('0x' + hex.join(''));
}

function privateToPublicKey(privateKey) {
    points = getPublicKey(BigInt('0x' + test_priv));
    return points.x.toString(16) + points.y.toString(16);
}

function hexStrToTypedArray(str) {
    return new Uint8Array(publ.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
    }))
}

function publicKeyToEthereumAddress(publicKey) {
    var hashed = keccak256(hexStrToTypedArray(publicKey));
    return '0x' + hashed.slice(-40);
}

function createCheque(identifier, type, amount, validity, keys, secret){
    let crypto = new AttestationCrypto();
    let riddle = crypto.makeRiddle(identifier, type, secret);

    // let publicKeys = DERUtility.restoreBase64Keys(readFile(inputKeyDir));
}

async function recoverPubKey(){
    await window.ethereum.enable();
    let u = ethers.utils;
    let provider = new ethers.providers.Web3Provider(web3.currentProvider);
    let signer = provider.getSigner();
    let ethAddress = await signer.getAddress();
    console.log("ethAddress = "+ ethAddress);
    let hash = await u.keccak256(ethAddress);
    console.log("hash = "+ hash);
    // First the message must be binary
    let hashBytes = u.arrayify(hash);
    let sig = await signer.signMessage(hashBytes);
    console.log("sig = "+ sig);
    // Then you must compute the prefixed-message hash
    let messageHash = u.hashMessage(hashBytes);
    console.log("messageHash = "+ messageHash);

    // Then you must make this binary
    let messageHashBytes = u.arrayify(messageHash);

    // Now you have the digest,
    let publicKey = u.recoverPublicKey(messageHashBytes, sig);
    console.log("publicKey  =" + publicKey);
}



