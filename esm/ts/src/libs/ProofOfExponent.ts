import { AttestationCrypto } from "./AttestationCrypto";
import { Point } from "./Point";
import { Asn1Der } from "./DerUtility";
import { uint8tohex } from "./utils";

export class ProofOfExponent {
    encoding: string;

    constructor(private base: Point, private riddle: Point, private tPoint: Point, private challenge: bigint) {
        this.encoding = this.makeEncoding();
    }

    static fromArray(inputArr: []){
        // try {
        let baseEnc = inputArr.shift();
        //     this.base = AttestationCrypto.decodePoint(baseEnc.getOctets());
        let riddleEnc = inputArr.shift();
        //     this.riddle = AttestationCrypto.decodePoint(riddleEnc.getOctets());
        let challengeEnc = inputArr.shift();
        //     this.challenge = new BigInteger(challengeEnc.getOctets());
        //     ASN1OctetString tPointEnc = ASN1OctetString.getInstance(asn1.getObjectAt(3));
        let tPointEnc = inputArr.shift();
        //     this.tPoint = AttestationCrypto.decodePoint(tPointEnc.getOctets());
        // } catch (IOException e) {
        //     throw new RuntimeException(e);
        // }
        // let me = new this();
        // if (!me.verify()) {
        //     throw new Error("The proof is not valid");
        // }
    }
    // verify(): boolean{
    //     let crypto = new AttestationCrypto();
    //     // TODO refactor into the POK class
    //     //return crypto.verifyProof(this);
    // }
    getBase(){

    }
    getRiddle(){

    }
    getPoint(){

    }

    makeEncoding(): string{
        let res: string = Asn1Der.encode('OCTET_STRING', uint8tohex(this.base.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', this.challenge.toString(16)) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false)));
        return Asn1Der.encode('SEQUENCE_30', res);
    }
}
