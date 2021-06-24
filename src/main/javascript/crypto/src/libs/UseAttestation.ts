import {KeyPair} from "./KeyPair";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {AttestationCrypto} from "./AttestationCrypto";
import {SignedIdentityAttestation} from "./SignedIdentityAttestation";
import {ASNEncodable} from "./ASNEncodable";
import {UseAttestation as UseAttestationASN} from "../asn1/shemas/UseAttestation";
import {AsnParser} from "@peculiar/asn1-schema";
import {uint8toBuffer} from "./utils";
import {Asn1Der} from "./DerUtility";

export class UseAttestation implements ASNEncodable, Verifiable, Validateable {
    private attestation: SignedIdentityAttestation;
    public type: number;
    private pok: FullProofOfExponent;
    private sessionPublicKey: KeyPair;
    private encoding: string;

    static fromData(attestation: SignedIdentityAttestation, type: number, pok: FullProofOfExponent, sessionPublicKey: KeyPair): UseAttestation {
        let me = new this();
        me.attestation = attestation;
        me.type = type;
        me.pok = pok;
        me.sessionPublicKey = sessionPublicKey;
        me.encoding = me.makeEncoding(attestation, type, pok, sessionPublicKey);
        me.constructorCheck();
        return me;
    }

    static fromBytes(derEncoding: Uint8Array, attestationVerificationKey: KeyPair) {
        let me = new this();
        let useAttest: UseAttestationASN;

        try {
            useAttest = AsnParser.parse( uint8toBuffer(derEncoding), UseAttestationASN);
        } catch (e){
            throw new Error('Cant parse UseAttestationASN. ' + e);
        }

        try {

            me.attestation = SignedIdentityAttestation.fromASNType(useAttest.attestation, attestationVerificationKey);

            me.type = useAttest.type;
            me.pok = FullProofOfExponent.fromASNType(useAttest.proof);
            me.sessionPublicKey = KeyPair.publicFromSubjectPublicKeyValue(useAttest.sessionKey);

        } catch ( e) {
            throw new Error("Cant decode internal data. " + e);
        }
        me.constructorCheck();
        return me;
    }

    constructorCheck() {
        if (!this.verify()) {
            throw new Error("The use attestation object is not valid");
        }
    }

    makeEncoding( attestation: SignedIdentityAttestation, type: number, pok: FullProofOfExponent, sessionKey: KeyPair): string {
        let res: string = attestation.getDerEncoding()
        + Asn1Der.encode('INTEGER', type)
        + pok.getDerEncoding()
        + sessionKey.getAsnDerPublic();

        return Asn1Der.encode('SEQUENCE_30', res );
    }

     getAttestation(): SignedIdentityAttestation {
        return this.attestation;
    }

     getType(): number { return this.type; }

    public getPok(): FullProofOfExponent {
        return this.pok;
    }

    public getSessionPublicKey(): KeyPair {
        return this.sessionPublicKey;
    }

    public getDerEncoding():string {
        return this.encoding;
    }

    public verify(): boolean {
        return this.attestation.verify() && new AttestationCrypto().verifyFullProof(this.pok);
    }

    public checkValidity(): boolean {
        return this.attestation.checkValidity();
    }
}
