import {base64ToUint8array, hexStringToArray, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {CURVE_SECP256k1, Point} from "./Point";

const ASN1 = require('@lapo/asn1js');

// G x, y values taken from official secp256k1 document
const G = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n);

export class KeyPair {
    private constructor() {}
    private privateInHex: string;
    private publicInHex: string;
    getPrivateAsHexString(): string{
        return this.privateInHex;
    }
    getPrivateAsBigInt(): bigint{
        return BigInt('0x' + this.privateInHex);
    }
    static privateFromBigInt(priv: bigint): KeyPair {
        let me = new this();
        me.privateInHex = priv.toString(16).padStart(64, '0');
        return me;
    }
    static privateFromHex(priv: string): KeyPair {
        let me = new this();
        me.privateInHex = priv.padStart(64, '0');
        return me;
    }
    // hex string 129-130 symbols with leading 04 (it means uncompressed)
    // TODO test if correct input string
    static fromPublicHex(publicHex: string){
        if (publicHex.length < 129 || publicHex.length > 130) {
            throw new Error('Wrong public hex length');
        }
        let me = new this();
        // console.log(publicHex);
        // console.log(typeof publicHex);
        // console.log(publicHex.padStart(130, '0'));
        // console.log("publicHex.padStart(130, '0')");
        me.publicInHex = publicHex.padStart(130, '0');
        return me;
    }
    static privateFromAsn1base64(base64: string): KeyPair {
        let me = new this();
        let base64StrArray = base64.split(/\r?\n/);
        if (base64.slice(0,3) === "---") {
            base64StrArray.shift();
            base64StrArray.pop();
        }
        let privateUint8 = base64ToUint8array(base64StrArray.join(''));
        let mainSequence = ASN1.decode(privateUint8);
        if (mainSequence.typeName() != "SEQUENCE" || mainSequence.sub.length != 3) {
            throw new Error('Wrong Private Key format(mainSequence)');
        }
        let octetsAsWrapper = mainSequence.sub[2];

        if (octetsAsWrapper.typeName() != "OCTET_STRING" || octetsAsWrapper.sub.length != 1) {
            throw new Error('Wrong Private Key format(octetsAsWrapper)');
        }

        let SequenseAsWrapper = octetsAsWrapper.sub[0];

        if (SequenseAsWrapper.typeName() != "SEQUENCE" || SequenseAsWrapper.sub.length != 4) {
            throw new Error('Wrong Private Key format(SequenseAsWrapper)');
        }

        let privateKeyOctetString = SequenseAsWrapper.sub[1].toHexString();

        let asn1 = new Asn1Der();
        me.privateInHex = asn1.decode(Uint8Array.from(hexStringToArray(privateKeyOctetString)));
        return me;
    }
    // Generate a private key
    static async generateKeyAsync(): Promise<KeyPair> {
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

        return this.privateFromBigInt(BigInt(hex.join('')) % CURVE_SECP256k1.n);
    }

    static createKeys(): KeyPair {
        return this.privateFromBigInt(BigInt('0x'+uint8tohex(crypto.getRandomValues(new Uint8Array(32))) ) % CURVE_SECP256k1.n);
    }

    getPublicKeyAsHexStr(): string {
        if (this.publicInHex) {
            return this.publicInHex;
        } else {
            let pubPoint = G.multiplyDA(this.getPrivateAsBigInt());
            // prefix 04 means it is uncompressed key
            return '04' + pubPoint.x.toString(16).padStart(64, '0') + pubPoint.y.toString(16).padStart(64, '0')
        }
    }


    getAsnDerPublic():string {
        var pubPoint = this.getPublicKeyAsHexStr();
        // TODO algorithm hardcoded
        let pubPointTypeDescrDER = "3081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101";
        return Asn1Der.encode('SEQUENCE_30',
            pubPointTypeDescrDER +
            Asn1Der.encode('BIT_STRING', pubPoint)
        );
    }
}
