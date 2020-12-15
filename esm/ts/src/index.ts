let EC = require("elliptic");
let sha3 = require("js-sha3");

let ec = new EC.ec('secp256k1');

const CURVE = {
    P: 2n ** 256n - 2n ** 32n - 977n,
    n: 2n ** 256n - 432420386565659656852420866394968145599n,
    magicExp: (2n ** 256n - 2n ** 32n - 977n + 1n) / 4n,
    A: 0n,
    B: 7n
};

interface keyPair {
    priv: bigint,
    pub: Point,
}

class Point {
    static ZERO = new Point(0n, 0n); // Point at infinity aka identity point aka zero
    constructor(public x: bigint, public y: bigint) {}

    // Adds point to itself. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    double(): Point {
        const X1 = this.x;
        const Y1 = this.y;
        const lam = mod(3n * X1 ** 2n * invert(2n * Y1, CURVE.P));
        const X3 = mod(lam * lam - 2n * X1);
        const Y3 = mod(lam * (X1 - X3) - Y1);
        return new Point(X3, Y3);
    }

    // Adds point to other point. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    add(other: Point): Point {
        const [a, b] = [this, other];
        const [X1, Y1, X2, Y2] = [a.x, a.y, b.x, b.y];
        if (X1 === 0n || Y1 === 0n) return b;
        if (X2 === 0n || Y2 === 0n) return a;
        if (X1 === X2 && Y1 === Y2) return this.double();
        if (X1 === X2 && Y1 === -Y2) return Point.ZERO;
        const lam = mod((Y2 - Y1) * invert(X2 - X1, CURVE.P));
        const X3 = mod(lam * lam - X1 - X2);
        const Y3 = mod(lam * (X1 - X3) - Y1);
        return new Point(X3, Y3);
    }

    // Elliptic curve point multiplication with double-and-add algo.
    multiplyDA(n: bigint) {
        let p = Point.ZERO;
        let d: Point = this;
        while (n > 0n) {
            if (n & 1n) p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }

    isInfinity(): boolean{
        return this.x == null || this.y == null;
    }

    getEncoded(compressed = false): Uint8Array{
        if (this.isInfinity())
        {
            return new Uint8Array(0);
        }

        let X = bnToBuf(this.x);
        if (compressed) {
            return uint8merge([Uint8Array.from([2]),X]);
        }

        return uint8merge([Uint8Array.from([4]), X , bnToBuf(this.y)]);
    }

    equals(other: Point): boolean {
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
    static async generateKey(): Promise<bigint> {
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
        const exported = await crypto.subtle.exportKey("raw", keyPair);

        (new Uint8Array(exported)).forEach(i => {
            var h = i.toString(16);
            if (h.length % 2) { h = '0' + h; }
            hex.push(h);
        });
        // the next line works if AES key is always positive
        return BigInt(hex.join('')) % CURVE.n;
    }
}

function uint8merge(list : Uint8Array[]): Uint8Array{
    if (list.length === 1) return list[0];

    let out = Uint8Array.from([]);
    if (list.length === 0) return out;

    for (let i = 0; i< list.length; i++){
        let temp = new Uint8Array(out.length + list[i].length);
        temp.set(out);
        temp.set(list[i], out.length);
        out = temp;
    }
    return out;
}

function mod(a: bigint, b: bigint = CURVE.P): bigint {
    const result = a % b;
    return result >= 0 ? result : b + result;
}

function bnToBuf(bn: bigint): Uint8Array {
    var hex = BigInt(bn).toString(16);
    if (hex.length % 2) { hex = '0' + hex; }

    var len = hex.length / 2;
    var u8 = new Uint8Array(len);

    var i = 0;
    var j = 0;
    while (i < len) {
        u8[i] = parseInt(hex.slice(j, j+2), 16);
        i += 1;
        j += 2;
    }

    return u8;
}

function bufToBn(buf: Uint8Array) {
    let hex: string[] = [];
    let u8 = Uint8Array.from(buf);

    u8.forEach(function (i) {
        var h = i.toString(16);
        if (h.length % 2) { h = '0' + h; }
        hex.push(h);
    });

    return BigInt('0x' + hex.join(''));
}

function BnPowMod(base: bigint, n: bigint, mod: bigint) {
    let res = 1n, cur = base;
    while (n > 0n) {
        if (n & 1n)
            res = (res * cur) % mod;
        cur = (cur * cur) % mod ;
        n >>= 1n;
    }
    return res;
}

function stringToHex(str: string) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}

function stringToArray(str: string) {
    var arr = [];
    for(var i=0;i<str.length;i++) {
        arr.push(str.charCodeAt(i));
    }
    return arr;
}

function getPublicKey(privKey: bigint): Point {
    return G.multiplyDA(privKey);
}

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
function egcd(a: bigint, b: bigint) {
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

function invert(number: bigint, modulo: bigint = CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('invert: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('invert: does not exist');
    }
    return mod(x, modulo);
}


// TODO add timezone
function formatGeneralizedDateTime(date: any):string {
    var d = new Date(date),
        month = '' + (d.getUTCMonth() + 1),
        day = '' + d.getUTCDate(),
        year = d.getUTCFullYear();
    let hour = '' + d.getUTCHours(),
        min = '' + d.getUTCMinutes(),
        sec = '' + d.getUTCSeconds()

    if (month.length < 2)
        month = '0' + month;
    if (day.length < 2)
        day = '0' + day;
    if (hour.length < 2)
        hour = '0' + hour;
    if (min.length < 2)
        min = '0' + min;
    if (day.length < 2)
        sec = '0' + sec;

    return [year, month, day, hour, min, sec].join('') + 'Z';
}

function uint8tohex(uint8: Uint8Array): string {
    // function i2hex(i) {
    //     return ('0' + i.toString(16)).slice(-2);
    // }
    return Array.from(uint8).map(i => ('0' + i.toString(16)).slice(-2)).join('');
}

// G x, y values taken from official secp256k1 document
const G = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n);

const ATTESTATION_TYPE: {[index: string]:number} = {
    phone: 0,
    mail: 1
}

const Asn1DerTagByType: {[index: string]:number} = {
    END_OF_CONTENT: 0,
    BOOLEAN: 1,
    INTEGER: 2,
    BIT_STRING: 3,
    OCTET_STRING: 4,
    NULL_VALUE: 5,
    OBJECT_ID: 6,
    OBJECT_DESCRIPTOR: 7,
    EXTERNAL: 8,
    REAL: 9,
    ENUMERATED: 10,
    EMBEDDED_PDV: 11,
    UTF8STRING: 12,
    RELATIVE_OID: 13,
    //reserved: 14,
    //reserved: 15,
    SEQUENCE_10: 16, // SEQUENCE и SEQUENCE OF
    SET_OF: 17, // SET и SET OF
    NUMERABLE_STRING: 18,
    PRINTABLE_STRING: 19,
    T61STRING: 20,
    VIDEO_TEX_STRING: 21,
    IA5STRING: 22,
    UTC_TIME: 23,
    GENERALIZED_TIME: 24,
    // SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", DateUtil.EN_Locale);
    // dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
    // time = Strings.toByteArray(dateF.format(time));
    GRAPHIC_STRING: 25,
    VISIBLE_STRING: 26,
    GENERAL_STRING: 27,
    UNIVERSAL_STRING: 28,
    CHARACTER_STRING: 29,
    BMP_STRING: 30,
    //long_form: 31,
    SEQUENCE_30: 48,
    SET: 49
}
const Asn1DerTagById = {
    0: "END_OF_CONTENT",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT_STRING",
    4: "OCTET_STRING",
    5: "NULL_VALUE",
    6: "OBJECT_ID",
    7: "OBJECT_DESCRIPTOR",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED_PDV",
    12: "UTF8STRING",
    13: "RELATIVE_OID",
    16: "SEQUENCE_10",
    19: "PRINTABLE_STRING",
    22: "IA5STRING",
    24: "GENERALIZED_TIME",
    48: "SEQUENCE_30",
    49: "SET",
}

class Asn1Der {
    static encode(type: string, value: any) {
        let encType: number = Asn1DerTagByType[type];
        let encValue = '';
        switch (type) {
            case 'GENERALIZED_TIME':
            case "VISIBLE_STRING":
                encValue = stringToHex(value);
                break;
            case 'INTEGER':
                encValue = parseInt(value).toString(16);
                encValue = (encValue.length % 2 ? '0' : '') + encValue;
                break;
            case "SEQUENCE_30":
            case "OCTET_STRING":
                encValue = value;
                break;
        }

        // TODO maybe worth it to code indefinite form
        // 8.1.3.6	For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5), and shall consist of a single octet.
        // 8.1.3.6.1	The single octet shall have bit 8 set to one, and bits 7 to 1 set to zero.
        // 8.1.3.6.2	If this form of length is used, then end-of-contents octets (see 8.1.5) shall be present in the encoding following the contents octets.

        let encLength = '';
        let dataLength: number = Math.ceil(encValue.length / 2);

        let dataLengthHex = dataLength.toString(16);
        dataLengthHex = (dataLengthHex.length % 2 ? '0' : '') + dataLengthHex;

        if (dataLength < 128) {
            encLength = dataLengthHex;
        } else {
            encLength = (128 + Math.round(dataLengthHex.length / 2)).toString(16) + dataLengthHex;
        }
        encValue = (encValue.length % 2 ? '0' : '') + encValue;

        return encType.toString(16).padStart(2, '0') + encLength + encValue;
    }

    // function Asn1Der(byteArray, _parent, _root) {
    // decode(byteArray) {
    //     this._io = byteArray;
    //     // this._parent = _parent;
    //     // this._root = _root || this;
    //     this._read();
    // }
    // _read() {
    //     // this.typeTag = this._io.readU1();
    //     this.typeTag = this._io.shift();
    //     this.len = new LenEncoded(this._io, this, this._root);
    //     switch (this.typeTag) {
    //         /*
    //         case Asn1Der.TypeTag.PRINTABLE_STRING:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodyPrintableString(_io__raw_body, this, this._root);
    //             break;
    //         case Asn1Der.TypeTag.SEQUENCE_10:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodySequence(_io__raw_body, this, this._root);
    //             break;
    //         case Asn1Der.TypeTag.SET:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodySequence(_io__raw_body, this, this._root);
    //             break;
    //
    //          */
    //         case Asn1Der.TypeTag.SEQUENCE_30:
    //             this._raw_body = this._io.splice(0,this.len.result);
    //             // var _io__raw_body = new KaitaiStream(this._raw_body);
    //             // this.body = new BodySequence(_io__raw_body, this, this._root);
    //             this.body = (new BodySequence(this._raw_body)).entries;
    //             break;
    //         /*
    //     case Asn1Der.TypeTag.UTF8STRING:
    //         this._raw_body = this._io.readBytes(this.len.result);
    //         var _io__raw_body = new KaitaiStream(this._raw_body);
    //         this.body = new BodyUtf8string(_io__raw_body, this, this._root);
    //         break;
    //     case Asn1Der.TypeTag.OBJECT_ID:
    //         this._raw_body = this._io.readBytes(this.len.result);
    //         var _io__raw_body = new KaitaiStream(this._raw_body);
    //         this.body = new BodyObjectId(_io__raw_body, this, this._root);
    //         break;
    //
    //          */
    //         default:
    //             this.body = this._io.splice(0,this.len.result);
    //             break;
    //     }
    //     console.log(this.body);
    // }

    // var BodySequence = Asn1Der.BodySequence = (function() {
    //     // function BodySequence(_io, _parent, _root) {
    //     function BodySequence(_io) {
    //         this._io = _io;
    //         // this._parent = _parent;
    //         // this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodySequence.prototype._read = function() {
    //         this.entries = [];
    //         var i = 0;
    //         while (this._io.length) {
    //             this.entries.push( (new Asn1Der(this._io)).body );
    //             i++;
    //         }
    //     }
    //
    //     return BodySequence;
    // })();

    // var BodyUtf8string = Asn1Der.BodyUtf8string = (function() {
    //     function BodyUtf8string(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodyUtf8string.prototype._read = function() {
    //         this.str = KaitaiStream.bytesToStr(this._io.readBytesFull(), "UTF-8");
    //     }
    //
    //     return BodyUtf8string;
    // })();

    /**
     * @see {@link https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-object-identifier|Source}
     */

    // var BodyObjectId = Asn1Der.BodyObjectId = (function() {
    //     function BodyObjectId(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodyObjectId.prototype._read = function() {
    //         this.firstAndSecond = this._io.readU1();
    //         this.rest = this._io.readBytesFull();
    //     }
    //     Object.defineProperty(BodyObjectId.prototype, 'first', {
    //         get: function() {
    //             if (this._m_first !== undefined)
    //                 return this._m_first;
    //             this._m_first = Math.floor(this.firstAndSecond / 40);
    //             return this._m_first;
    //         }
    //     });
    //     Object.defineProperty(BodyObjectId.prototype, 'second', {
    //         get: function() {
    //             if (this._m_second !== undefined)
    //                 return this._m_second;
    //             this._m_second = KaitaiStream.mod(this.firstAndSecond, 40);
    //             return this._m_second;
    //         }
    //     });
    //
    //     return BodyObjectId;
    // })();

    // var LenEncoded = Asn1Der.LenEncoded = (function() {
    //     function LenEncoded(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     LenEncoded.prototype._read = function() {
    //         this.b1 = this._io.shift();
    //         if (this.b1 == 130) {
    //             let bite1 = this._io.shift();
    //             let bite2 = this._io.shift();
    //             this.int2 = bite1 << 8 + bite2;
    //         }
    //         if (this.b1 == 129) {
    //             this.int1 = this._io.shift();
    //         }
    //     }
    //     Object.defineProperty(LenEncoded.prototype, 'result', {
    //         get: function() {
    //             if (this._m_result !== undefined)
    //                 return this._m_result;
    //             this._m_result = (this.b1 == 129 ? this.int1 : (this.b1 == 130 ? this.int2 : this.b1));
    //             return this._m_result;
    //         }
    //     });
    //
    //     return LenEncoded;
    // })();

    // var BodyPrintableString = Asn1Der.BodyPrintableString = (function() {
    //     function BodyPrintableString(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodyPrintableString.prototype._read = function() {
    //         this.str = KaitaiStream.bytesToStr(this._io.readBytesFull(), "ASCII");
    //     }
    //
    //     return BodyPrintableString;
    // })();
}

class AttestationCrypto {
    rand: bigint;
    constructor() {
        this.rand = this.makeSecret();
    }
    getType(type: string): number {
        switch (type.toLowerCase()) {
            case "mail":
                return ATTESTATION_TYPE.mail;
            case "phone":
                return ATTESTATION_TYPE.phone;
            default:
                throw new Error("Wrong type of identifier");
        }
    }
    makeRiddle(identity: string, type: string, secret: bigint) {
        // hash email
        let hashedIdentity = this.hashIdentifier(type, identity);
        // console.log("identity = " + identity);
        // console.log("secret = " , secret);
        // console.log("hashedIdentity.x = " + hashedIdentity.x.toString(16));
        // console.log("hashedIdentity.y = " + hashedIdentity.y.toString(16));

        //console.log(hashedIdentity);
        let makeRiddle = hashedIdentity.multiplyDA(secret);

        // console.log(makeRiddle);
        // console.log("makeRiddle.x = " + makeRiddle.x.toString(16));
        // console.log("makeRiddle.y = " + makeRiddle.y.toString(16));
        // console.log("getEncoded = " + makeRiddle.getEncoded());
        return hashedIdentity.multiplyDA(secret).getEncoded(false);
    }
    // TODO use type
    hashIdentifier(type: string , identity: string): Point {
        // console.log("identifier = "+identity);

        let idenNum = this.mapToInteger(type, Uint8Array.from(stringToArray(identity.trim().toLowerCase())));
        // console.log("idenNum = " + idenNum);
        return this.computePoint(idenNum);
    }
    // TODO change arr type
    mapToInteger(type: string, arr: Uint8Array ):bigint {
        // add prefix [0,0,0,1] for email type
        let prefix = type === "mail" ? [0,0,0,1] : [0,0,0,0];
        return mod(BigInt('0x'+sha3.keccak256(uint8merge([Uint8Array.from(prefix),arr]))));
    }
    mapToIntegerFromUint8(arr: Uint8Array ):bigint {
        let idenNum = BigInt( '0x'+ sha3.keccak256(arr));
        return mod(idenNum);
    }
    computePoint( x: bigint ): Point {
        x = mod ( x );
        let y = 0n, expected = 0n, ySquare = 0n;
        let resPoint,referencePoint: Point;
        let p = CURVE.P;
        let a = CURVE.A;
        let b = CURVE.B;
        do {
            do {
                x = mod(x + 1n);
                // console.log("x+1 = "+x);
                ySquare = mod(BnPowMod(x, 3n, p) + a * x + b);
                // console.log("ySquare = "+ySquare);
                y = BnPowMod(ySquare, CURVE.magicExp, p);
                expected = mod(y * y);
                // console.log("y*y = "+expected);
            } while (expected !== ySquare);
            resPoint = new Point(x, y);
            // TODO add Point.negate() and use following logic
            // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
            if (resPoint.y > (p / 2n)) {
                resPoint = new Point(x, p - y);
            }
            referencePoint = resPoint.multiplyDA(CURVE.n - 1n);
            if (referencePoint.y > (p / 2n)) {
                referencePoint = new Point(referencePoint.x, p - referencePoint.y);
            }
        } while (!resPoint.equals(referencePoint))
        // console.log("resPoint = ",resPoint);
        // console.log("resPointY = ",resPoint.y.toString(16));
        // console.log("referencePoint = ",referencePoint);
        // console.log("referencePointY = ",referencePoint.y.toString(16));
        return resPoint;
    }
    async genaratePrivateKey(): Promise<bigint> {
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
        console.log(hex);
        return BigInt(hex.join('')) % CURVE.n;
    }
    async createKeys(): Promise<{priv: bigint, pub: any}> {
        let priv = await this.genaratePrivateKey();
        return {
            priv,
            pub: getPublicKey(priv)
        }
    }
    makeSecret(bytes = 48): bigint{
        var array = new Uint8Array(bytes);
        window.crypto.getRandomValues(array);

        let output = '0x';
        for (var i = 0; i < array.length; i++) {
            output += array[i].toString(16);
        }
        return BigInt(output);
    }
    constructProof(identity: string, type: string, secret: bigint){
        const hashedIdentity: Point = this.hashIdentifier(type, identity);
        const identifier = hashedIdentity.multiplyDA(secret);
        return this.computeProof(hashedIdentity, identifier, secret);
    }

    computeProof(base: Point, riddle: Point, exponent: bigint){
        let r: bigint = this.makeSecret();
        let t: Point = base.multiplyDA(r);
        // TODO ideally Bob's ethreum address should also be part of the challenge
        let c: bigint = mod(this.mapToIntegerFromUint8(this.makeArray([base, riddle, t])), CURVE.n);
        let d: bigint = mod(r + c * exponent);
        return  new ProofOfExponent(base, riddle, t, d);
    }
    makeArray(pointArray: Point[]): Uint8Array{
        let output: Uint8Array = new Uint8Array(0);
        pointArray.forEach( (item:Point) => {
            output = new Uint8Array([ ...output, ...item.getEncoded(false)]);
        })
        return output;
    }
}

class ProofOfExponent {
    encoding: string;
    constructor(private base: Point, private riddle: Point, private tPoint: Point, private challenge: bigint) {
        this.encoding = this.makeEncoding();
    }

    makeEncoding(): string{
        let res: string = Asn1Der.encode('OCTET_STRING', uint8tohex(this.base.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', this.challenge.toString(16)) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false)));
        return Asn1Der.encode('SEQUENCE_30', res);
    }
}

class Cheque {
    publicKey: bigint;
    riddle: Uint8Array;
    encoded: string;
    // TODO code it
    constructor(private identifier: string, private type: string, private amount: number, private validity: number, private keys: keyPair, private secret: bigint) {}

    createAndVerify(){
        let crypto = new AttestationCrypto();
        this.riddle = crypto.makeRiddle(this.identifier, this.type, this.secret);
        // this.publicKey = this.keys.pub;
        let current =  new Date().getTime() ;
        let notValidBefore = current - (current % 1000); // Round down to nearest second
        let notValidAfter = notValidBefore + this.validity * 1000;
        let cheque = this.makeCheque(notValidBefore, notValidAfter);

        // console.log('this.makeCheque done');
        // console.log('cheque = ' + cheque);
        // console.log('priv = ' + this.keys.priv.toString(16));

        let ecKey = ec.keyFromPrivate(this.keys.priv);
        var signature = ecKey.sign(cheque);
        var pubPoint = ecKey.getPublic().encode('hex');

        // console.log('pubPoint = ' + pubPoint);
        var derSign = signature.toDER();// array
        var derSignHex = signature.toDER('hex');// hex string

        this.encoded = this.encodeSignedCheque(cheque, derSignHex, pubPoint);
        // console.log('encoded = ' + this.encoded);

        let verify = ecKey.verify(cheque, signature);
        // console.log('verify = ' + verify);

        if (!verify) {
            throw new Error("Public and private keys are incorrect");
        }
        console.log(Asn1Der.encode('OCTET_STRING', this.secret.toString(16)));
        return {
            cheque,
            chequeEncoded: this.encoded,
            derSignature: derSignHex,
            derSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', this.secret.toString(16)))
        }
    }

    encodeSignedCheque(cheque: string, derSign: string, pubPoint: string){
        let fullSequence = cheque + derSign + Asn1Der.encode('OCTET_STRING', pubPoint);
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }

    makeCheque(notValidBefore: number, notValidAfter: number){
        let timeList =
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(notValidBefore)) +
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(notValidAfter));
        // console.log('timeList = ' + timeList);
        let fullSequence =
            Asn1Der.encode('INTEGER', this.amount) +
            Asn1Der.encode('SEQUENCE_30', timeList) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle));
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }


    // TODO code it
    getDerEncoding(): Uint8Array{
        return Uint8Array.from([]);
    }
}

class AttestationRequest {
    signature: string;
    private identity: string;
    private type: string;
    private pok: string;
    private keys: keyPair;
    constructor() {}
    static fromData(identity: string, type: string, pok: string, keys: keyPair): AttestationRequest {
        let me = new this();
        me.create(identity, type, pok, keys);
        return me;
    }
    create(identity: string, type: string, pok: string, keys: keyPair){
        this.identity = identity;
        this.type = type;
        this.pok = pok;
        this.keys = keys;

        let ecKey = ec.keyFromPrivate(this.keys.priv);
        let signature = ecKey.sign(this.getUnsignedEncoding());
        this.signature = signature.toDER('hex');
    }
    getUnsignedEncoding(){
        let res = Asn1Der.encode('VISIBLE_STRING',this.identity) +
            Asn1Der.encode('INTEGER',ATTESTATION_TYPE[this.type]) +
            this.pok;
        return Asn1Der.encode('SEQUENCE_30',res);
    }
    getDerEncoding(){
        let ecKey = ec.keyFromPrivate(this.keys.priv);
        var pubPoint = ecKey.getPublic().encode('hex');

        let res = this.getUnsignedEncoding() +
            Asn1Der.encode('OCTET_STRING', pubPoint) +
            Asn1Der.encode('OCTET_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', res);
    }
    static fromBytes(data: string): AttestationRequest {
        let me = new this();


        return me;
    }
}

class main {
    crypto: AttestationCrypto;
    constructor() {
        this.crypto = new AttestationCrypto();
    }
    createKeys() {
        return this.crypto.createKeys();
    }

    createCheque(amount: number, receiverId: string, type: string, validityInMilliseconds: number, keys: keyPair) {
        let secret: bigint = this.crypto.makeSecret();
        let cheque: Cheque = new Cheque(receiverId, type, amount, validityInMilliseconds, keys, secret);
        return cheque.createAndVerify();
    }

    requestAttest(receiverId: string, type: string, keys: keyPair) {
        let secret: bigint = this.crypto.makeSecret();
        let pok = this.crypto.constructProof(receiverId, type, secret);
        let request = AttestationRequest.fromData(receiverId, type, pok.encoding, keys);
        return {
            request: request.getDerEncoding(),
            requestSignature: request.signature,
            requestSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', secret.toString(16)))
        }
    }

    constructAttest( issuerName: string, validityInMilliseconds: number, requestBytes: string, keys: keyPair)  {
        let request = AttestationRequest.fromBytes(requestBytes);



        // if (!request.checkValidity()) {
        //     console.log("Could not validate attestation signing request");
        //     throw new Error("Validation failed");
        // }
        // if (!request.verify()) {
        //     System.err.println("Could not verify attestation signing request");
        //     throw new Error("Validation failed");
        // }
        // let att = new IdentifierAttestation(request.getIdentity(), request.getType(), request.getPok().getRiddle().getEncoded(false), request.getPublicKey());
        // att.setIssuer("CN=" + issuerName);
        // att.setSerialNumber(new Random().nextLong());
        // Date now = new Date();
        // att.setNotValidBefore(now);
        // att.setNotValidAfter(new Date(System.currentTimeMillis() + validityInMilliseconds));
        // SignedAttestation signed = new SignedAttestation(att, keys);
        // if (!writeFile(attestationDir, DERUtility.printDER(signed.getDerEncoding(), "ATTESTATION"))) {
        //     System.err.println("Could not write attestation to disc");
        //     throw new IOException("Could not write file");
        // }
    }
}
(window as any).CryptoTicket = main;
























/*
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
}*/

