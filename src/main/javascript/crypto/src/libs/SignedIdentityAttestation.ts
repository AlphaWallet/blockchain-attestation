import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {hexStringToArray, uint8toBuffer, uint8tohex} from "./utils";
import {Attestation} from "./Attestation";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {ASNEncodable} from "./ASNEncodable";
import {Asn1Der} from "./DerUtility";
import {IdentifierAttestation} from "./IdentifierAttestation";

export class SignedIdentityAttestation implements ASNEncodable, Verifiable, Validateable {
    private signature: string;
    private att: IdentifierAttestation;
    private commitment: Uint8Array;
    private uint8data: Uint8Array;
    private attestorKeys: KeyPair;
    static ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

    constructor() {}

    static fromBytes(uint8data: Uint8Array, attestorKeys: KeyPair): SignedIdentityAttestation {

        const myAttestation: MyAttestation = AsnParser.parse( uint8toBuffer( uint8data ), MyAttestation);
        return this.fromASNType(myAttestation, attestorKeys, uint8data);

    }

    static fromASNType(myAttestation: MyAttestation, attestorKeys: KeyPair, uint8data: Uint8Array = new Uint8Array(0)): SignedIdentityAttestation {
        let me = new this();
        me.uint8data = uint8data;
        me.attestorKeys = attestorKeys;
        let algorithmEncoded: string = myAttestation.signatureAlgorithm.algorithm;
        me.att = IdentifierAttestation.fromBytes(myAttestation.signedInfo) as IdentifierAttestation;

        // me.signature = myAttestation.signatureValue;
        me.signature = uint8tohex(new Uint8Array(myAttestation.signatureValue));
        if (algorithmEncoded !== me.att.getSigningAlgorithm()) {
            throw new Error("Algorithm specified is not consistent");
        }
        me.constructorCheck();
        return me;
    }

    static fromData(att: IdentifierAttestation, attestationSigningKey: KeyPair): SignedIdentityAttestation{
        let me = new this();
        me.attestorKeys = attestationSigningKey;
        me.att = att;
        // me.att.setSigningAlgorithm(SignedIdentityAttestation.ECDSA_WITH_SHA256);
        // me.signature = attestationSigningKey.signDeterministicSHA256( Array.from(me.att.getPrehash()));
        me.signature = me.attestorKeys.signRawBytesWithEthereum( Array.from(me.att.getPrehash()));
        me.constructorCheck();
        return me;
    }

    verify(){
        try {
            return this.attestorKeys.verifyBytesWithEthereum(hexStringToArray(this.att.getDerEncoding()), this.signature);

        } catch (e) {
            console.error(e);
            return false;
        }
    }

    checkValidity(){
        return this.getUnsignedAttestation().checkValidity();
    }

    getUnsignedAttestation(): IdentifierAttestation{
        return this.att;
    }

    getDerEncoding(): string{
        if (this.uint8data && this.uint8data.length){
            return uint8tohex(new Uint8Array(this.uint8data));
        } else {
            return this.constructSignedAttestation(this.getUnsignedAttestation(), this.signature);
        }
    }

    constructSignedAttestation(unsignedAtt: Attestation, signature: string){

        let rawAtt: Uint8Array = unsignedAtt.getPrehash();
        let alg = Asn1Der.encode('OBJECT_ID', unsignedAtt.getSigningAlgorithm());

        let res: string = uint8tohex(rawAtt) +
            Asn1Der.encode('SEQUENCE_30', alg) +
            Asn1Der.encode('BIT_STRING', '04' + uint8tohex(KeyPair.anySignatureToRawUint8(signature)));

        return Asn1Der.encode('SEQUENCE_30', res);
    }

    constructorCheck(){
        // TODO implement
        // if (!(verificationKey instanceof ECPublicKeyParameters)) {
        //     throw new UnsupportedOperationException("Attestations must be signed with ECDSA key");
        // }
        if (!this.verify()) {
            throw new Error("The signature is not valid");
        }
    }

}
