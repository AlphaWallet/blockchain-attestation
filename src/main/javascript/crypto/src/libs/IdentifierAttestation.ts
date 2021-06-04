import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {Asn1Der} from "./DerUtility";
import {uint8tohex} from "./utils";
import {Attestation} from "./Attestation";

export class IdentifierAttestation extends Attestation {
    private crypto: AttestationCrypto;
    static OID_OCTETSTRING = "1.3.6.1.4.1.1466.115.121.1.40";
    constructor(riddle: Uint8Array, private keys: KeyPair) {
        super();
        this.setVersion(18); // Our initial version
        this.setSubject("CN=" + this.keys.getAddress());
        this.setSignature(AttestationCrypto.OID_SIGNATURE_ALG);

        this.setSubjectPublicKeyInfo(keys);
        this.setRiddle(riddle);
    }

    static fromData(identifier: string, type: number, keys: KeyPair, secret: bigint){
        let crypto = new AttestationCrypto();
        let riddle = crypto.makeCommitment(identifier, type, secret);
        return new this(riddle, keys);
    }

    setSignature(signature: string) {
        // TODO create algorithm parser and change variable type
        // let alg = new AlgorithmIdentifierASN();
        // alg.algorithm = signature;
        // hadrcoded ASN1 sequence
        this.signature = "300906072A8648CE3D0201";
    }
    setSubjectPublicKeyInfo(keys: KeyPair){
        // TODO generate algorithm object
        // hardcoded algorithm
        // let hardcodedAlg = "3081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101";

        // let res = hardcodedAlg + Asn1Der.encode('BIT_STRING', keys.getPublicKeyAsHexStr());
        // this.subjectPublicKeyInfo = Asn1Der.encode('SEQUENCE_30', res);
        this.subjectPublicKey = keys;
    }


    setRiddle(riddle: Uint8Array) {
        // TODO hardcoded OID
        // extensions.add(new ASN1ObjectIdentifier(Attestation.OID_OCTETSTRING));
        let attestOIDencoded = "060B2B060104018B3A73790128";
        let extensions: string = attestOIDencoded
            + Asn1Der.encode('BOOLEAN', 1)
        + Asn1Der.encode('OCTET_STRING', uint8tohex(riddle));

        let extensionsEncoded = Asn1Der.encode('SEQUENCE', extensions);
        extensionsEncoded = Asn1Der.encode('SEQUENCE', extensionsEncoded);

        this.riddle = riddle;
        // Double Sequence is needed to be compatible with X509V3
        // TODO create extensions as correct type "Extensions"
        // this.extensions = extensionsEncoded;
    }

    checkValidity(): boolean {
        if (!super.checkValidity()) {
            return false;
        }
        if (this.getVersion() != 18) {
            console.error("The version number is " + this.getVersion() + ", it must be 18");
            return false;
        }
        if (this.getSubject() == null || this.getSubject().length != 45 || !this.getSubject().startsWith("CN=0x")) { // The address is 2*20+5 chars long because it starts with CN=0x
            console.error("The subject is supposed to only be an Ethereum address as the Common Name");
            return false;
        }
        if (this.getSignature() != AttestationCrypto.OID_SIGNATURE_ALG) {
            console.error("The signature algorithm is supposed to be " + AttestationCrypto.OID_SIGNATURE_ALG);
            return false;
        }
        // Verify that the subject public key matches the subject common name

        let parsedSubject: string = "CN=" + this.subjectPublicKey.getAddress();
        if (parsedSubject != this.getSubject()) {
            console.error("The subject public key does not match the Ethereum address attested to");
            return false;
        }

        return true;
    }
}
