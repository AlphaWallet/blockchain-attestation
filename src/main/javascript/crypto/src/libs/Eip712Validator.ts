import {AttestedObject} from "./AttestedObject";
import {UseToken} from "../asn1/shemas/UseToken";
import {XMLconfigData} from "../data/tokenData";
import {KeyPair} from "./KeyPair";
import {Ticket} from "../Ticket";
import {Eip712DomainInterface, SignatureUtility} from "./SignatureUtility";
import {hexStringToUint8} from "./utils";
const url = require('url');

export class Eip712Validator {
    private XMLConfig: any;
    protected domain: string;
    // protected acceptableTimeLimitMs: number;
    // public DEFAULT_TIME_LIMIT_MS = 1000 * 60 * 20; // 20 min

    constructor() {
        this.XMLConfig = XMLconfigData;
    }

    static stringIsAValidUrl(domain: string): boolean {
        let parsedUrl;

        try {
            parsedUrl = new URL(domain);
        } catch (e) {
            console.log('cant construct url. Error:' + e);
            return false;
        }

        return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
    };

    setDomainAndTimout(domain: string){
        if (!Eip712Validator.stringIsAValidUrl(domain)) throw new Error('wrong domain');
        this.domain = domain;
    }

    setDomain(domain: string){
        if (!Eip712Validator.stringIsAValidUrl(domain)) throw new Error('wrong domain');
        this.domain = domain;
    }

    getDomain(): string{
        return this.domain;
    }

    validateRequest(jsonInput: string) {
        try {
            let authenticationData = JSON.parse(jsonInput);

            let authenticationRootNode = JSON.parse(authenticationData.jsonSigned);

            // console.log(authenticationRootNode);

            let eip712Domain = authenticationRootNode.domain;
            let eip712Message = authenticationRootNode.message;

            console.log('eip712Domain');
            console.log(eip712Domain);
            console.log(eip712Message);

            let attestedObject = this.retrieveAttestedObject(eip712Message);

            // TODO implement
            return this.validateDomain(eip712Domain)
            // && this.validateAuthentication(auth);
            // accept &= verifySignature(authenticationData, attestedObject.getUserPublicKey());
            // accept &= validateAttestedObject(attestedObject);
            // return accept;
        } catch (e) {
            console.error('Validate error!');
            console.error(e);
            return false;
        }
    }

    // TODO
    // public boolean verifyTimeStamp(String timestamp) {

    validateDomain(domainToCheck: Eip712DomainInterface): boolean {
        return (domainToCheck.name.toLowerCase() === this.domain.toLowerCase())
        && (domainToCheck.version === SignatureUtility.Eip712Data['PROTOCOL_VERSION']);
    }

    retrieveAttestedObject(auth: any){
        let attestedObjectHex = auth.payload;

        let attestorKey = KeyPair.publicFromBase64(XMLconfigData.base64attestorPubKey);
        let issuerKey = KeyPair.publicFromBase64(XMLconfigData.base64senderPublicKey);

        let decodedAttestedObject = AttestedObject.fromBytes(hexStringToUint8(attestedObjectHex), UseToken, attestorKey, Ticket, issuerKey);
        return decodedAttestedObject;
    }

    public verifySignature(signedJsonInput: string, pkAddress: string): boolean {

        let tokenData = JSON.parse(signedJsonInput);
        let signatureInHex = tokenData.signatureInHex;
        let jsonSigned = JSON.parse(tokenData.jsonSigned);

        let publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
        let userKey = KeyPair.fromPublicHex(publicKey.substr(2));

        if (pkAddress.toLowerCase() !== jsonSigned.message.address.toLowerCase()){
            console.log('message.address is not equal pkAddress');
            return false;
        }
        if (pkAddress.toLowerCase() !== userKey.getAddress().toLowerCase()){
            console.log('Recovered address is not equal pkAddress');
            return false;
        }
        return true;

    }

    // TODO check all methods
    // Eip712Validator.java
}
