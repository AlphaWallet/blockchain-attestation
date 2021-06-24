import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {Attestation} from "./Attestation";
import {Validateable} from "./Validateable";

export class IdentifierAttestation extends Attestation implements Validateable{
    private crypto: AttestationCrypto;
    static OID_OCTETSTRING = "1.3.6.1.4.1.1466.115.121.1.40";
    private DEFAULT_SIGNING_ALGORITHM = "1.2.840.10045.4.2";

    constructor() {
        super();
    }

    fromCommitment(commitment: Uint8Array, keys: KeyPair){

        this.subjectKey = keys;
        this.setVersion(18); // Our initial version
        this.setSubject("CN=" + this.subjectKey.getAddress());
        this.setSigningAlgorithm(this.DEFAULT_SIGNING_ALGORITHM);

        this.setSubjectPublicKeyInfo(keys);
        this.setCommitment(commitment);
    }

    static fromData(identity: string, type: number, keys: KeyPair, secret: bigint){
        let crypto = new AttestationCrypto();
        let commitment = crypto.makeCommitment(identity, type, secret);
        return (new this()).fromCommitment(commitment, keys);
    }

    static fromBytes(bytes: Uint8Array){
        return super.fromBytes(bytes);
    }

    setSubjectPublicKeyInfo(keys: KeyPair){
        this.subjectKey = keys;
    }

    setCommitment(encodedRiddle: Uint8Array) {
        this.commitment = encodedRiddle;
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
        // TODO check if we really need to skip that check
        // if (this.getSigningAlgorithm() != AttestationCrypto.OID_SIGNATURE_ALG) {
        //     console.error("The signature algorithm is supposed to be " + AttestationCrypto.OID_SIGNATURE_ALG);
        //     return false;
        // }
        // Verify that the subject public key matches the subject common name

        let parsedSubject: string = "CN=" + this.subjectKey.getAddress();
        if (parsedSubject.toLowerCase() != this.getSubject().toLowerCase()) {
            console.error("The subject public key does not match the Ethereum address attested to");
            return false;
        }

        return true;
    }

    setIssuer(issuer: string){
        this.issuer = issuer;
    }

    public getSerialNumber(): number {
        return this.serialNumber;
    }

    public setSerialNumber(serialNumber: number) {
        this.serialNumber = serialNumber;
    }

    public getAddress(): string {
        // Remove the "CN=" prefix
        return this.subjectKey.getAddress();
    }
}
