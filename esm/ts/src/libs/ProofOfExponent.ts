import { AttestationCrypto } from "./AttestationCrypto";
import {CURVE_BN256, Point} from "./Point";
import { Asn1Der } from "./DerUtility";
import { uint8tohex } from "./utils";

export class ProofOfExponent {
    encoding: string;

    constructor(private base: Point, private riddle: Point, private tPoint: Point, private challenge: bigint) {
        this.encoding = this.makeEncoding();
    }

    static fromArray(baseEnc: string, riddleEnc: string, challengeEnc: string, tPointEnc: string){
        // console.log('POK points and challange received= ', baseEnc, riddleEnc, tPointEnc, challengeEnc);
        let base = Point.decodeFromHex(baseEnc, CURVE_BN256);
        let riddle = Point.decodeFromHex(riddleEnc, CURVE_BN256);
        let tPoint = Point.decodeFromHex(tPointEnc, CURVE_BN256);
        let me = new this(base, riddle, tPoint, BigInt('0x'+challengeEnc) );
        me.encoding = me.makeEncoding();
        // if (!me.verify()) {
        //     throw new Error("The proof is not valid");
        // }
        return me;
    }
    verify(): boolean{
        let crypto = new AttestationCrypto();
        let verify = crypto.verifyProof(this);
        console.log(`verify POK = ${verify}`);
        // TODO refactor into the POK class

        return crypto.verifyProof(this);
    }
    getBase(): Point{
        return this.base;
    }
    getRiddle(): Point{
        return this.riddle;
    }
    getPoint(): Point{
        return this.tPoint;
    }
    getChallenge(): bigint{
        return this.challenge;
    }

    makeEncoding(): string{
        // console.log('POK points and challange encoded= ', uint8tohex(this.base.getEncoded(false)), uint8tohex(this.riddle.getEncoded(false)), uint8tohex(this.tPoint.getEncoded(false)), this.challenge.toString(16));
        let res: string = Asn1Der.encode('OCTET_STRING', uint8tohex(this.base.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', this.challenge.toString(16)) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.tPoint.getEncoded(false)));
        return Asn1Der.encode('SEQUENCE_30', res);
    }
}
