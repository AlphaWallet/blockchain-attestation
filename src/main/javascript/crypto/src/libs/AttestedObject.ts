import {AttestationCrypto} from "./AttestationCrypto";
import {SignedIdentityAttestation} from "./SignedIdentityAttestation";
import {hexStringToArray, uint8toBuffer, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";
import {KeyPair} from "./KeyPair";
import {AsnParser} from "@peculiar/asn1-schema";
import {UseToken} from "../asn1/shemas/UseToken";
import {UsageProofOfExponent} from "./UsageProofOfExponent";
import {IdentifierAttestation} from "./IdentifierAttestation";
import {Attestable} from "./Attestable";
import {SignatureUtility} from "./SignatureUtility";
import {Verifiable} from "./Verifiable";
import {ASNEncodable} from "./ASNEncodable";
import {AttestableObject} from "./AttestableObject";

declare global {
    interface Window {
        ethereum: any;
        web3: any;
    }
}

export class AttestedObject implements ASNEncodable, Verifiable {
    private crypto: AttestationCrypto;
    private pok: ProofOfExponentInterface;
    private unsignedEncoding: string;
    private derEncodedProof: string;
    private signature: string;
    private encoding: string;
    private attestableObject: any;
    private att: SignedIdentityAttestation;
    private attestationSecret: bigint ;
    private objectSecret: bigint;
    private userPublicKey: Uint8Array;
    private userKeyPair: KeyPair;

    private preSignEncoded: string;

    private webDomain: string;

    static Eip712UserData: {[index: string]:string|number}  = {
        payload: '',
        description: '',
        timestamp: 0
    }
    // static Eip712UserDataTypes: {[index: string]:string}[]  = [
    static Eip712UserDataTypes: {name: string, type: string}[]  = [
        {name: 'payload', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'timestamp', type: 'uint256'},
    ]
    static Eip712UserDataPrimaryName: string = "Authentication";
    static Eip712UserDataDescription: string = "Single-use authentication";

    constructor() {}

    create<T extends Attestable>(
        attestableObject: T ,
        att: SignedIdentityAttestation,
        attestationSecret: bigint ,
        objectSecret: bigint
    ){
        this.attestableObject = attestableObject;
        this.att = att;
        this.attestationSecret = attestationSecret;
        this.objectSecret = objectSecret;
        this.crypto = new AttestationCrypto();
        this.pok = this.makeProof(attestationSecret, objectSecret, this.crypto);
        this.derEncodedProof = this.pok.getDerEncoding();

        this.fillPresignData();

    }

    setWebDomain(domain: string){
        this.webDomain = domain;
    }

    fillPresignData(){

        this.preSignEncoded = this.attestableObject.getDerEncoding() +
            this.att.getDerEncoding() +
            this.pok.getDerEncoding();
        this.unsignedEncoding = Asn1Der.encode('SEQUENCE_30', this.preSignEncoded);
    }

    fromDecodedData<T extends Attestable>(
        attestableObject: T ,
        att: SignedIdentityAttestation,
        pok: ProofOfExponentInterface ,
        signature: string
    ){
        this.attestableObject = attestableObject;
        this.att = att;
        this.pok = pok;
        this.signature = signature;

        this.fillPresignData();

        let vec = this.preSignEncoded + Asn1Der.encode('BIT_STRING', this.signature)

        this.encoding = Asn1Der.encode('SEQUENCE_30', vec);
        this.userKeyPair = this.att.getUnsignedAttestation().getSubjectPublicKeyInfo();

        if (!this.verify()) {
            throw new Error("The redeem request is not valid");
        }
    }


    async sign(){
        let userData = {
            payload: this.unsignedEncoding,
            description: AttestedObject.Eip712UserDataDescription,
            timestamp: new Date().getTime()
        };

        return await SignatureUtility.signEIP712WithBrowserWallet(this.webDomain, userData, AttestedObject.Eip712UserDataTypes, AttestedObject.Eip712UserDataPrimaryName );
    }

    public checkValidity(): boolean {
        // CHECK: that it is an identity attestation otherwise not all the checks of validity needed gets carried out
        try {
            let attEncoded = this.att.getUnsignedAttestation().getDerEncoding();
            let std: IdentifierAttestation = IdentifierAttestation.fromBytes(new Uint8Array(hexStringToArray(attEncoded))) as IdentifierAttestation;

            // CHECK: perform the needed checks of an identity attestation
            if (!std.checkValidity()) {
                console.error("The attestation is not a valid standard attestation");
                return false;
            }
        } catch (e) {
            console.error("The attestation is invalid");
            return false;
        }

        // CHECK: that the cheque is still valid
        if (!this.getAttestableObject().checkValidity()) {
            console.error("Cheque is not valid");
            return false;
        }

        // CHECK: the Ethereum address on the attestation matches receivers signing key
        let attestationEthereumAddress: string = this.getAtt().getUnsignedAttestation().getSubject().substring(3);

        if (attestationEthereumAddress.toLowerCase() !== KeyPair.publicFromUint(this.getUserPublicKey()).getAddress().toLowerCase()) {
            console.error("The attestation is not to the same Ethereum user who is sending this request");
            return false;
        }

        // CHECK: verify signature on RedeemCheque is from the same party that holds the attestation
        if (this.signature != null) {
            let spki = this.getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
            try {
                if (!spki.verifyHexStringWithEthereum(this.unsignedEncoding, this.signature)) {
                    console.error("The signature on RedeemCheque is not valid");
                    return false;
                }
            } catch (e) {
                console.error("The attestation SubjectPublicKey cannot be parsed");
                return false;
            }
        }

        return true;
    }

    verify(): boolean{
        let result: boolean =
            this.attestableObject.verify()
            && this.att.verify()
            && this.crypto.verifyEqualityProof(
                this.att.getUnsignedAttestation().getCommitment(),
                this.attestableObject.getCommitment(),
                this.pok
            );
        if (this.signature != null) {
            let spki = this.getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
            return result && spki.verifyHexStringWithEthereum(this.unsignedEncoding, this.signature);
        } else {
            return result;
        }
    }

    static fromBytes<D extends UseToken, T extends AttestableObject>(asn1: Uint8Array, decoder: new () => D, attestorKey: KeyPair, attestable: new () => T, issuerKey: KeyPair): AttestedObject{
        let attested: D = AsnParser.parse( uint8toBuffer(asn1), decoder);

        // console.log('attested');
        // console.log(attested);

        let me = new this();

        // let attestableObj: T
        me.attestableObject = new attestable();
        me.attestableObject.fromBytes(attested.signedToken, issuerKey);

        me.att = SignedIdentityAttestation.fromBytes(new Uint8Array(attested.attestation), attestorKey);

        let pok = new UsageProofOfExponent();
        pok.fromBytes( new Uint8Array(attested.proof) ) ;
        me.pok = pok;

        let attCom: Uint8Array = me.att.getUnsignedAttestation().getCommitment();
        let objCom: Uint8Array = me.attestableObject.getCommitment();
        let crypto = new AttestationCrypto();

        if (!crypto.verifyEqualityProof(attCom, objCom, pok)) {
            throw new Error("The redeem proof did not verify");
        }

        return me;
    }

    private makeProof(attestationSecret: bigint, objectSecret: bigint, crypto: AttestationCrypto): ProofOfExponentInterface {
        // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
        // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
        // TODO we dont parse that value, because its already parsed to this.riddle
        // let extensions = this.att.getUnsignedAttestation().getExtensions();//.getObjectAt(0));

        // Index in the second DER sequence is 2 since the third object in an extension is the actual value

        // TODO we dont parse that value, because its already parsed to this.riddle
        // let attCom: Uint8Array = new Uint8Array(extensions.extension.extnValue);
        let attCom: Uint8Array = this.att.getUnsignedAttestation().getCommitment();
        let objCom: Uint8Array = this.attestableObject.getCommitment();
        let pok: ProofOfExponentInterface = crypto.computeEqualityProof(uint8tohex(attCom), uint8tohex(objCom), attestationSecret, objectSecret);

        if (!crypto.verifyEqualityProof(attCom, objCom, pok)) {
            throw new Error("The redeem proof did not verify");
        }
        return pok;
    }

    getAttestableObject(){
        return this.attestableObject;
    }

    getAtt(){
        return this.att;
    }

    getDerEncodeProof(){
        return this.derEncodedProof;
    }

    public getDerEncodingWithSignature() { return this.encoding; }

    public getDerEncoding():string {
        return this.unsignedEncoding;
    }

    public getUserPublicKey() {
        return this.userPublicKey;
    }
}
