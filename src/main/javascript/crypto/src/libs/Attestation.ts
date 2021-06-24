import {hexStringToUint8, uint8toBuffer, uint8tohex} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedInfo} from "../asn1/shemas/AttestationFramework";
import {Extensions} from "../asn1/shemas/AuthenticationFramework";
import {KeyPair} from "./KeyPair";
import {Asn1Der} from "./DerUtility";

export class Attestation {
    static OID_OCTETSTRING: string = "1.3.6.1.4.1.1466.115.121.1.40";
    protected version = 18; // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
    protected serialNumber: any;
    // private signingAlgorithm:AlgorithmIdentifierASN;
    // der encoded
    protected signingAlgorithm:string;
    protected issuer: string; // X500Name value Optional
    private notValidBefore: any;// Optional
    private notValidAfter: any;// Optional
    //private subject: Name;  //X500Name  CN=Ethereum address     // Optional
    // der encoded
    protected subject: string;  //X500Name  CN=Ethereum address     // Optional
    // protected subjectPublicKeyInfo: SubjectPublicKeyInfo;    // Optional
    // der encoded
    //protected subjectPublicKeyInfo: string;    // Optional
    protected subjectKey: KeyPair;    // Optional
    private smartcontracts: any; // ASN1integers  // Optional
    private dataObject: any;
    protected commitment: Uint8Array;
    // der encoded
    // protected extensions: string;
    protected extensions: Extensions;
    private signedInfo: Uint8Array;

    constructor(){}

    static fromBytes( uint8bytes: Uint8Array) {
        const me = new this();
        let decodedAttestationObj: SignedInfo = AsnParser.parse(uint8toBuffer(uint8bytes), SignedInfo);

        me.signedInfo = uint8bytes;
        me.version = decodedAttestationObj.version.version;
        me.serialNumber = decodedAttestationObj.serialNumber;

        me.signingAlgorithm = decodedAttestationObj.signature.algorithm.toString();

        if (decodedAttestationObj.validity){
            me.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            me.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
        }

        let rdn = decodedAttestationObj.subject.rdnSequence;
        if (rdn && rdn[0] && rdn[0][0]){
            let obj = rdn[0][0];
            me.subject = (obj.type.toString() == "2.5.4.3" ? "CN=" : "") + obj.value;
        }

        me.subjectKey = KeyPair.publicFromSubjectPublicKeyInfo(decodedAttestationObj.subjectPublicKeyInfo);

        let issuerSet = decodedAttestationObj.issuer.rdnSequence;
        let namesArray: string[] = [];
        if (issuerSet.length) {
            issuerSet.forEach(issuerSetItem => {
                let curVal = issuerSetItem[0].value;
                let type = issuerSetItem[0].type;
                let prefix = '';
                switch (type){
                    case '2.5.4.3':
                        prefix = "CN";
                        break;
                    case '2.5.4.6':
                        prefix = "C";
                        break;
                    case '2.5.4.10':
                        prefix = "O";
                        break;
                    case '2.5.4.11':
                        prefix = "OU";
                        break;
                    case '2.5.4.7':
                        prefix = "L";
                        break;
                    default:
                        throw new Error('Alg "' + type + '" Not implemented yet');
                }

                if (type && curVal) {
                    namesArray.push(type + '=' + curVal);
                }
            })
        }
        me.issuer = namesArray.join(',');

        if (decodedAttestationObj.contract){
            me.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo.extensions){
            me.extensions = decodedAttestationObj.attestsTo.extensions;
            me.commitment = new Uint8Array(me.extensions.extension.extnValue);
        } else if(decodedAttestationObj.attestsTo.dataObject) {
            // TODO parse dataObject
            //this.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
        return me;
    }

    public isValidX509(): boolean {
        // if (this.version.getValue().intValueExact() != 0 && version.getValue().intValueExact() != 1  && version.getValue().intValueExact() != 2) {
        if (this.version != 18) {
            return false;
        }
        if (!this.issuer) {
            return false;
        }
        if (this.notValidBefore == null || this.notValidAfter == null) {
            return false;
        }
        if (this.subject == null) {
            return false;
        }
        if (!this.subjectKey) {
            return false;
        }
        if (this.smartcontracts != null) {
            return false;
        }
        if (this.dataObject != null) {
            return false;
        }
        if (this.version == null || this.serialNumber == null || this.signingAlgorithm == null) {
            return false;
        }
        return true;
    }

    getDerEncoding(): string{
        if (!this.signedInfo) {
            this.signedInfo = this.getPrehash();
        }
        if (!this.signedInfo) {
            throw new Error('Empty Attestaion Der Encoding');
        }
        return uint8tohex(new Uint8Array(this.signedInfo));
    }

    getCommitment(): Uint8Array{
        return this.commitment;
    }

    getNotValidBefore(): number{
        return this.notValidBefore;
    }

    setNotValidBefore(d: number){
        this.notValidBefore = d;
    }

    getNotValidAfter(): number{
        return this.notValidAfter;
    }

    setNotValidAfter(d: number){
        this.notValidAfter = d;
    }

    getSubjectPublicKeyInfo(){
        return this.subjectKey;
    }

    checkValidity(){
        if (this.version == null
            || this.serialNumber == null
            || this.signingAlgorithm == null
            || (!this.extensions && !this.dataObject && !this.commitment)
        ) {
            console.log("Some attest data missed");
            return false;
        }
        let currentTime = Date.now();
        let attNotBefore = this.getNotValidBefore();
        let attNotAfter = this.getNotValidAfter();
        if ( attNotBefore && attNotAfter && !(currentTime >= attNotBefore && currentTime < attNotAfter)) {
            console.log("Attestation is no longer valid");
            return false;
        }
        return true;
    }

    getExtensions(){
        return this.extensions;
    }
    setVersion(version: number){
        this.version = version;
    }
    getVersion(): number{
        return this.version;
    }

    setSubject(subject: string){
        this.subject = subject;
    }

    getSubject(): string{
        return this.subject;
    }

    setSigningAlgorithm(alg: string) {
        this.signingAlgorithm = alg;
    }

    public getPrehash(): Uint8Array {
        if (!this.checkValidity()) {
            return null;
        }
        // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
        // new DERTaggedObject(true, 0, this.version);
        let res: string = Asn1Der.encode('TAG', Asn1Der.encode('INTEGER', this.version),0)
        + Asn1Der.encode('INTEGER', this.serialNumber)
            // TODO verify encoding!!!
        + Asn1Der.encodeObjectId(this.signingAlgorithm);
            // res.add(this.issuer == null ? new DERSequence() : this.issuer);
        res += this.issuer ? Asn1Der.encodeName(this.issuer) : Asn1Der.encode('NULL_VALUE','');

        if (this.notValidAfter != null && this.notValidBefore != null) {
            let date = Asn1Der.encode('GENERALIZED_TIME', this.notValidBefore)
            + Asn1Der.encode('GENERALIZED_TIME', this.notValidAfter);
            res += Asn1Der.encode('SEQUENCE_30', date);
        } else {
            res += Asn1Der.encode('NULL_VALUE','');
        }

        // res.add(this.subject == null ? new DERSequence() : this.subject);
        res += this.subject ? Asn1Der.encodeName(this.subject) : Asn1Der.encode('NULL_VALUE','');

        res += this.subjectKey ? this.subjectKey.getAsnDerPublic() : Asn1Der.encode('NULL_VALUE','');

        // if (this.smartcontracts != null) {
        //     res.add(this.smartcontracts);
        // }

        if (this.commitment && this.commitment.length){
            let extensions: string = Asn1Der.encode('OBJECT_ID', Attestation.OID_OCTETSTRING)
                + Asn1Der.encode('BOOLEAN', 1)
                + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
            // Double Sequence is needed to be compatible with X509V3
            res += Asn1Der.encode('TAG',Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('SEQUENCE_30', extensions)),3);
        } else {
            // if (this.extensions != null) {
            //     res.add(new DERTaggedObject(true, 3, this.extensions));
            // } else {
            //     res.add(new DERTaggedObject(true, 4, this.dataObject));
            // }
            throw new Error('dataObject not implemented. We didn\'t use it before.');
        }
        return hexStringToUint8(Asn1Der.encode('SEQUENCE_30',res));
    }

    public getSigningAlgorithm() {
        return this.signingAlgorithm;
    }
}
