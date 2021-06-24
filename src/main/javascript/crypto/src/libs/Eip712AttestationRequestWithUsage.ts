import {Eip712Validator} from "./Eip712Validator";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {Eip712AttestationUsage} from "./Eip712AttestationUsage";
import {TokenValidateable} from "./TokenValidateable";
import {Eip712AttestationRequest} from "./Eip712AttestationRequest";
import { AttestationRequestWithUsage } from "./AttestationRequestWithUsage";
import {KeyPair} from "./KeyPair";
import {base64ToUint8array, hexStringToBase64Url} from "./utils";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {Nonce} from "./Nonce";
import {AttestationRequest} from "./AttestationRequest";
import {Eip712Token} from "./Eip712Token";
import {Timestamp} from "./Timestamp";

export class Eip712AttestationRequestWithUsage extends Eip712Token implements JsonEncodable,
    Verifiable, Validateable, TokenValidateable {
    // public static DEFAULT_TOKEN_TIME_LIMIT: number = Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    // public static DEFAULT_TIME_LIMIT_MS: number = Eip712AttestationRequest.DEFAULT_TIME_LIMIT_MS;

    private Eip712UserDataTypes: {name: string, type: string}[]  = [
        {name: 'payload', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'timestamp', type: 'string'},
        {name: 'expirationTime', type: 'string'},
    ]

    protected data: {
        payload: string,
        description: string,
        identifier: string,
        timestamp: string,
        expirationTime: string,
    }

    private Eip712UserDataPrimaryName: string = "AttestationRequestWUsage";
    private Eip712UserDataDescription: string = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\""
        + " and use this to authorize usage of local, temporary keys.";

    private maxTokenValidityInMs: number;
    private acceptableTimeLimit: number;
    private attestationRequestWithUsage:AttestationRequestWithUsage;

    private jsonEncoding: string;
    private userPublicKey: KeyPair;
    private userKey: KeyPair;

    constructor(userKey: KeyPair = null, acceptableTimeLimit:number = Timestamp.DEFAULT_TIME_LIMIT_MS, maxTokenValidityInMs:number = Timestamp.DEFAULT_TOKEN_TIME_LIMIT) {
        super();
        this.userKey = userKey;

        this.acceptableTimeLimit = acceptableTimeLimit;
        this.maxTokenValidityInMs = maxTokenValidityInMs;
    }


    public async fromData(attestorDomain:string, acceptableTimeLimit:number = Timestamp.DEFAULT_TIME_LIMIT_MS, maxTokenValidityInMs:number = Timestamp.DEFAULT_TOKEN_TIME_LIMIT  ,identifier:string,
    attestationRequestWithUsage: AttestationRequestWithUsage, signingKey: KeyPair = null) {

        this.setDomain(attestorDomain);
        if (signingKey) {
            this.userKey = signingKey;
        }
        try {
            this.acceptableTimeLimit = acceptableTimeLimit;
            this.maxTokenValidityInMs = maxTokenValidityInMs;
            this.attestationRequestWithUsage = attestationRequestWithUsage;
            this.jsonEncoding = await this.makeToken(identifier, attestationRequestWithUsage);
        } catch ( e ) {
            console.log(e);
            throw new Error("Could not encode object");
        }

        try {
            this.fillJsonData(this.jsonEncoding);
        } catch ( e ) {
            throw new Error("Could not decode object");
        }
    }

    public Eip712AttestationRequestWithUsage(attestorDomain:string,
        acceptableTimeLimit:number, maxTokenValidityInMs: number, jsonEncoding:string) {
            //TODO
            // super(attestorDomain);
        try {
            this.acceptableTimeLimit = acceptableTimeLimit;
            this.maxTokenValidityInMs = maxTokenValidityInMs;
            this.jsonEncoding = jsonEncoding;

            this.fillJsonData(this.jsonEncoding);

        } catch ( e ) {
            console.log(e);
            throw new Error("Could not decode object");
        }
    }

    fillJsonData(json: string){
        if (!json) throw new Error('Empty json');

        this.jsonEncoding = json;
        let tokenData = JSON.parse(json);
        let signatureInHex = tokenData.signatureInHex;

        let jsonSigned = JSON.parse(tokenData.jsonSigned);
        this.eip712DomainData = jsonSigned.domain;
        this.data = jsonSigned.message;

        try {
            let publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
            this.userPublicKey = KeyPair.fromPublicHex(publicKey.substr(2));
            // console.log('Eip712 withUsage restored address: ' + this.userPublicKey.getAddress());
        } catch (e){
            let m = "Recover Address failed with error:" + e;
            console.log(m)
            throw new Error(m);
        }

        if (!this.attestationRequestWithUsage){
            this.attestationRequestWithUsage = AttestationRequestWithUsage.fromBytes(base64ToUint8array( this.data.payload));
        }

        this.constructorCheck();
    }

    constructorCheck() {
        if (!this.verify()) {
            throw new Error("Could not verify Eip712 use attestation");
        }
    }

    async makeToken(identifier: string, attestationRequestWithUsage: AttestationRequestWithUsage) {

        if (!this.userKey) {
            await SignatureUtility.connectMetamaskAndGetAddress();
        }

        let ts = new Timestamp().getTimeAsString();
        let expirationTime = new Timestamp(Date.now() + this.maxTokenValidityInMs).getTimeAsString();

        let userData = {
            payload: hexStringToBase64Url(attestationRequestWithUsage.getDerEncoding()),
            description: this.Eip712UserDataDescription,
            timestamp: ts,
            identifier: identifier,
            expirationTime: expirationTime,
        };


        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712UserDataTypes, this.Eip712UserDataPrimaryName, this.userKey );
    }

    public getIdentifier(): string {
        return this.data.identifier;
    }

    public getUserPublicKey(): KeyPair {
        return this.userPublicKey;
    }

    public getPok(): FullProofOfExponent {
        return this.attestationRequestWithUsage.getPok();
    }

    public getType(): number {
        return this.attestationRequestWithUsage.getType();
    }

    public getSessionPublicKey(): KeyPair {
        return this.attestationRequestWithUsage.getSessionPublicKey();
    }

    public getJsonEncoding(): string {
        return this.jsonEncoding;
    }

    /**
     * Verify that an attestation can be issued. I.e. the nonce is not expired
     */
    public checkValidity(): boolean {
        if (!this.testNonceAndDescription(this.acceptableTimeLimit)) {
            return false;
        }
        return true;
    }

    /**
     * Verify that the object can be used as a usage token. I.e. the token timestamp has not expired.
     * Note that the object can still be used as a token after the nonce for issuance has expired.
     */
    public checkTokenValidity():boolean {
        let time:Timestamp = new Timestamp(this.data.timestamp);
        time.setValidity(this.maxTokenValidityInMs);
        if (!time.validateAgainstExpiration(Timestamp.stringTimestampToLong(this.data.expirationTime))) {
            console.log('time.validateAgainstExpiration filed');
            return false;
        }
        // Nonce validation must still happen since this also verifies user's address and receiver's domain
        if (!this.testNonceAndDescription(this.maxTokenValidityInMs)) {
            return false;
        }
        return true;
    }

    private testNonceAndDescription(timeLimit: number): boolean {
        if (!timeLimit) {
            throw new Error('timeLimit required');
        }
        let nonceMinTime: number  = Timestamp.stringTimestampToLong(this.data.timestamp) - timeLimit;
        let nonceMaxTime: number = Timestamp.stringTimestampToLong(this.data.timestamp) + timeLimit;
        if (!new Nonce().validateNonce(
            this.attestationRequestWithUsage.getPok().getNonce(),
            this.userPublicKey.getAddress(),
            this.domain,
            nonceMinTime,
            nonceMaxTime
        )) {
            return false;
        }
        if (this.data.description !== this.Eip712UserDataDescription ) {
            return false;
        }
        return true;
    }

    public verify(): boolean {
        if (!this.attestationRequestWithUsage.verify()) {
            return false;
        }
        return true;
    }
}
