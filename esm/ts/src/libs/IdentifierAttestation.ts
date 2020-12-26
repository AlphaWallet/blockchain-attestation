import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {Asn1Der} from "./DerUtility";

export class IdentifierAttestation {
    private crypto: AttestationCrypto;
    private version: string;
    static OID_OCTETSTRING = "1.3.6.1.4.1.1466.115.121.1.40";
    constructor(private riddle: Uint8Array, private keys: KeyPair) {
        this.crypto = new AttestationCrypto();
        this.setVersion(18); // Our initial version
        // this.setSubject("CN=" + this.crypto.addressFromKey(this.keys));
        // SEQUENCE (1 elem)
        // OBJECT IDENTIFIER
        // this.setSignature(AttestationCrypto.OID_SIGNATURE_ALG);
        // try {
        //     SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
        //     super.setSubjectPublicKeyInfo(spki);
        // } catch (IOException e) {
        //     throw new RuntimeException(e);
        // }
        this.setRiddle(riddle);
    }
    setVersion(version: number) {
        this.version = Asn1Der.encodeAsInteger( BigInt(version) );
    }
    // setSubject(subject: string) {
    //     this.version = Asn1Der.encode('INTEGER', subject);
    // }
    // setSignature(signature: string) {
    //     this.version = Asn1Der.encode('INTEGER', signature);
    // }
    setRiddle(riddle: Uint8Array) {

    }
}
