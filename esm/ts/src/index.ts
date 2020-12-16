import { DERUtility, Asn1Der } from "./libs/DerUtility";
import { AttestationRequest } from "./libs/AttestationRequest";
import { ATTESTATION_TYPE, CURVE } from "./libs/interfaces";
import { Point } from "./libs/Point";
import { mod, invert, bnToBuf, uint8merge } from "./libs/utils";
import { keyPair } from "./libs/interfaces";

let sha3 = require("js-sha3");

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

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
        let hashedIdentity = this.hashIdentifier(type, identity);
        return hashedIdentity.multiplyDA(secret).getEncoded(false);
    }
    // TODO use type
    hashIdentifier(type: string , identity: string): Point {
        let idenNum = this.mapToInteger(type, Uint8Array.from(stringToArray(identity.trim().toLowerCase())));
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

        let ecKey = ec.keyFromPrivate(this.keys.priv);
        var signature = ecKey.sign(cheque);
        let pubPoint = ecKey.getPublic();
        var pubPointHEX = pubPoint.getX().toString(16) + pubPoint.getY().toString(16);

        let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', signature.r.toString(16) + signature.s.toString(16));

        this.encoded = this.encodeSignedCheque(
            cheque,
            signatureHexDerDitString,
            pubPointHEX);

        let verify = ecKey.verify(cheque, signature);
        // console.log('verify = ' + verify);

        if (!verify) {
            throw new Error("Public and private keys are incorrect");
        }
        console.log(Asn1Der.encode('OCTET_STRING', this.secret.toString(16)));
        return {
            cheque,
            chequeEncoded: this.encoded,
            derSignature: signatureHexDerDitString,
            derSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', this.secret.toString(16)))
        }
    }

    encodeSignedCheque(cheque: string, derSign: string, pubPoint: string){
        let fullSequence = cheque + Asn1Der.encode('BIT_STRING', pubPoint) + derSign;
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

class main {
    crypto: AttestationCrypto;
    constructor() {
        this.crypto = new AttestationCrypto();
    }
    createKeys() {
        return this.crypto.createKeys();
    }

    createCheque(amount: number, receiverId: string, type: string, validityInMilliseconds: number, keys: keyPair, secret: bigint) {
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

    // receiveCheque(userKeysDER: string, chequeSecret: string, attestationSecret: string, cheque: string, attestation: string, attestorKey: string){
    //     let userKeys = DERUtility.restoreBase64Keys(userKeysDER);
        // byte[] chequeSecretBytes = DERUtility.restoreBytes(readFile(chequeSecretDir));
        // BigInteger chequeSecret = DERUtility.decodeSecret(chequeSecretBytes);
        // byte[] attestationSecretBytes = DERUtility.restoreBytes(readFile(attestationSecretDir));
        // BigInteger attestationSecret = DERUtility.decodeSecret(attestationSecretBytes);
        // byte[] chequeBytes = DERUtility.restoreBytes(readFile(chequeDir));
        // Cheque cheque = new Cheque(chequeBytes);
        // byte[] attestationBytes = DERUtility.restoreBytes(readFile(attestationDir));
        // AsymmetricKeyParameter attestationProviderKey = PublicKeyFactory.createKey(
        //     DERUtility.restoreBytes(readFile(attestorKeyDir)));
        // SignedAttestation att = new SignedAttestation(attestationBytes, attestationProviderKey);
        //
        // if (!cheque.checkValidity()) {
        //     System.err.println("Could not validate cheque");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!cheque.verify()) {
        //     System.err.println("Could not verify cheque");
        //     throw new RuntimeException("Verification failed");
        // }
        // if (!att.checkValidity()) {
        //     System.err.println("Could not validate attestation");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!att.verify()) {
        //     System.err.println("Could not verify attestation");
        //     throw new RuntimeException("Verification failed");
        // }
        //
        // RedeemCheque redeem = new RedeemCheque(cheque, att, userKeys, attestationSecret, chequeSecret);
        // if (!redeem.checkValidity()) {
        //     System.err.println("Could not validate redeem request");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!redeem.verify()) {
        //     System.err.println("Could not verify redeem request");
        //     throw new RuntimeException("Verification failed");
        // }
        // // TODO how should this actually be?
        // SmartContract sc = new SmartContract();
        // if (!sc.testEncoding(redeem.getPok())) {
        //     System.err.println("Could not submit proof of knowledge to the chain");
        //     throw new RuntimeException("Chain submission failed");
        // }
    // }

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

