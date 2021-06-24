import {KeyPair} from "./KeyPair";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {ASNEncodable} from "./ASNEncodable";
import {Verifiable} from "./Verifiable";
import {Identity} from "../asn1/shemas/AttestationRequestWithUsage";
import {AsnParser} from "@peculiar/asn1-schema";
import {uint8ToBn, uint8toBuffer, uint8tohex} from "./utils";
import {CURVE_BN256, Point} from "./Point";
import {AttestationCrypto} from "./AttestationCrypto";
import {Asn1Der} from "./DerUtility";

export class AttestationRequestWithUsage implements ASNEncodable, Verifiable {
    private sessionPublicKey: KeyPair;
    private type: number;
    public pok: FullProofOfExponent;

    private constructor() {
    }

    static fromData(type: number, pok: FullProofOfExponent, sessionPublicKey: KeyPair): AttestationRequestWithUsage {
        let me = new this();
        me.type = type;
        me.pok = pok;
        me.sessionPublicKey = sessionPublicKey;
        if (!me.verify()) {
            throw new Error("Could not verify the proof");
        }
        return me;
    }

    static fromBytes(asn1: Uint8Array): AttestationRequestWithUsage {
        let me = new this();
        let identity: Identity;

        try {
            identity = AsnParser.parse( uint8toBuffer(asn1), Identity);
            me.type = identity.type;
            me.sessionPublicKey = KeyPair.publicFromSubjectPublicKeyValue(identity.sessionKey);
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

    getDerEncoding(){
        let res = Asn1Der.encode('INTEGER',this.type) +
            this.pok.getDerEncoding() +
            this.sessionPublicKey.getAsnDerPublic();

        return Asn1Der.encode('SEQUENCE_30',res);
    }

    getPok(): FullProofOfExponent{
        return this.pok;
    }

    getType(): number{
        return this.type;
    }

    getSessionPublicKey():KeyPair {
        return this.sessionPublicKey;
    }
}
