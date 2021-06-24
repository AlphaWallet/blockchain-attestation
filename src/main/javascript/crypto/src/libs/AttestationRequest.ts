import {CURVE_BN256, Point} from "./Point";
import { Asn1Der } from "./DerUtility";
import { uint8ToBn, uint8toBuffer, uint8tohex} from "./utils";
import {AttestationCrypto} from "./AttestationCrypto";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {AsnParser} from "@peculiar/asn1-schema";
import {Identity} from "../asn1/shemas/AttestationRequest";

export class AttestationRequest {
    private type: number;
    public pok: FullProofOfExponent;
    private constructor() {}

    static fromData(type: number, pok: FullProofOfExponent): AttestationRequest {
        let me = new this();
        me.type = type;
        me.pok = pok;
        if (!me.verify()) {
            throw new Error("The proof is not valid");
        }
        return me;
    }

    getDerEncoding(){
        let res = Asn1Der.encode('INTEGER',this.type) +
            this.pok.getDerEncoding();
        return Asn1Der.encode('SEQUENCE_30',res);
    }

    static fromBytes(asn1: Uint8Array): AttestationRequest {
        let me = new this();
        let identity: Identity;

        try {
            identity = AsnParser.parse( uint8toBuffer(asn1), Identity);
            me.type = identity.type;
        } catch (e){
            throw new Error('Cant parse AttestationRequest Identity');
        }

        try {
            let riddleEnc = new Uint8Array(identity.proof.riddle);
            let challengeEnc = new Uint8Array(identity.proof.challengePoint);
            let tPointEnc = new Uint8Array(identity.proof.responseValue);
            let nonce = new Uint8Array(identity.proof.nonce);

            let riddle = Point.decodeFromHex(uint8tohex(riddleEnc), CURVE_BN256 );
            let challenge = uint8ToBn(challengeEnc);
            let tPoint = Point.decodeFromHex(uint8tohex(tPointEnc), CURVE_BN256 );
            me.pok = FullProofOfExponent.fromData(riddle, tPoint, challenge, nonce);
        } catch (e){
            throw new Error('Cant create FullProofOfExponent');
        }

        if (!me.verify()) {
            throw new Error("Could not verify the proof");
        }
        // console.log('proof OK');
        return me;
    }

    verify():boolean {

        let AttestationCryptoInstance = new AttestationCrypto();

        if (!AttestationCryptoInstance.verifyFullProof(this.pok)) {
            return false;
        }

        // console.log('VerifyAttestationRequestProof OK');

        return true;
    }

    getPok(): FullProofOfExponent{
        return this.pok;
    }

    getType(): number{
        return this.type;
    }
}

