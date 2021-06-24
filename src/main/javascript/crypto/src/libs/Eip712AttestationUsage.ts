import {JsonEncodable} from "../intefaces/JsonEncodable";
import {Verifiable} from "./Verifiable";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";
import {Eip712Token} from "./Eip712Token";
import {UseAttestation} from "./UseAttestation";
import {base64ToUint8array, hexStringToBase64Url, uint8tohex} from "./utils";
import {AttestationCrypto, Pedestren_G} from "./AttestationCrypto";
import {CURVE_BN256, Point} from "./Point";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {Nonce} from "./Nonce";
import {TokenValidateable} from "./TokenValidateable";
import {Timestamp} from "./Timestamp";

export class Eip712AttestationUsage extends Eip712Token implements JsonEncodable, Verifiable, TokenValidateable {
    public PLACEHOLDER_CHAIN_ID: number = 0;
    public Eip712PrimaryName: string = "AttestationUsage";
    public Eip712Description: string = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\".";
    public Eip712UserTypes: {name: string, type: string}[]  = [
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'payload', type: 'string'},
        {name: 'timestamp', type: 'string'},
        {name: 'expirationTime', type: 'string'},
    ]

    private useAttestation: UseAttestation;
    private jsonEncoding: string;
    private attestorKey: KeyPair;
    private userKey: KeyPair;
    private maxTokenValidityInMs: number;

    protected data: {
        payload: string,
        description: string,
        identifier: string,
        timestamp: string,
        expirationTime: string,
    }

    constructor(userKey: KeyPair = null, maxTokenValidityInMs:number = Timestamp.DEFAULT_TOKEN_TIME_LIMIT) {
        super();
        this.maxTokenValidityInMs = maxTokenValidityInMs;
        this.userKey = userKey;
    }

    // TODO make signingKey universal
    public async addData(attestorDomain: string, identifier: string, useAttestation: UseAttestation) {
        this.setDomain(attestorDomain);
        this.useAttestation = useAttestation;

        try {
            this.jsonEncoding = await this.makeToken(identifier, useAttestation);
        } catch ( e ) {
            console.error(e);
            throw new Error("Could not encode object. " + e);
        }

        try {
            // decode JSON and fill publicKey
            this.fillJsonData(this.jsonEncoding);
        } catch (e){
            console.log(e);
            return false;
        }

        this.constructorCheck();
    }

    fillJsonData(json: string, attestorKey: KeyPair = null){
        if (!json) {
            throw new Error('Empty json');
        }

        if (attestorKey !== null) {
            this.attestorKey = attestorKey;
        }

        this.jsonEncoding = json;
        let tokenData = JSON.parse(json);
        let signatureInHex = tokenData.signatureInHex;

        let jsonSigned = JSON.parse(tokenData.jsonSigned);
        this.eip712DomainData = jsonSigned.domain;
        this.data = jsonSigned.message;

        try {
            let publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
            this.requestorKeys = KeyPair.fromPublicHex(publicKey.substr(2));
            // console.log('restored address: ' + this.requestorKeys.getAddress());
        } catch (e){
            let m = "Recover Address failed with error:" + e;
            console.log(m)
            throw new Error(m);
        }

        if (!this.useAttestation){
            try {
                // console.log(uint8tohex(base64ToUint8array(this.data.payload)));
                this.useAttestation = UseAttestation.fromBytes(base64ToUint8array(this.data.payload), this.attestorKey);
            } catch (e){
                let m = "Failed to read UseAttestation. " + e;
                console.log(m);
                throw new Error(m);
            }
        }

        this.constructorCheck();
    }

    constructorCheck() {
        if (!this.verify()) {
            throw new Error("Could not verify Eip712 use attestation");
        }
    }

    // use Att
    async makeToken(identifier: string, useAttestation: UseAttestation): Promise<string>{
        if (!this.userKey) {
            await SignatureUtility.connectMetamaskAndGetAddress();
        }

        let userData = {
            payload: hexStringToBase64Url(useAttestation.getDerEncoding()),
            description: this.Eip712Description,
            timestamp: new Timestamp().getTimeAsString(),
            identifier: identifier,
            expirationTime: new Timestamp(Date.now() + this.maxTokenValidityInMs).getTimeAsString(),
        };

        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712UserTypes, this.Eip712PrimaryName, this.userKey );
    }

    proofLinking() {

        let crypto = new AttestationCrypto();
        let candidateExponent = crypto.mapToCurveMultiplier(this.getType(), this.getIdentifier());
        let commitmentPoint: Point = Point.decodeFromUint8(this.getAttestation().getUnsignedAttestation().getCommitment(), CURVE_BN256);
        let candidateRiddle: Point = commitmentPoint.subtract(Pedestren_G.multiplyDA(candidateExponent));

        if (!candidateRiddle.equals(this.getPok().getRiddle())) {
            console.log('candidateRiddle.equals(this.getPok().getRiddle()) error');
            return false;
        }
        return true;
    }

    getPok(): FullProofOfExponent{
        return this.useAttestation.getPok();
    }

    getType(): number {
        return this.useAttestation.type;
    }

    getIdentifier(): string {
        return this.data.identifier;
    }

    getAttestation(){
        return this.useAttestation.getAttestation();
    }

    getJsonEncoding(): string {
        return this.jsonEncoding;
    }

    checkTokenValidity(): boolean {

        let nonceMinTime: number = Timestamp.stringTimestampToLong(this.data.expirationTime) - this.maxTokenValidityInMs - 2 * Timestamp.ALLOWED_ROUNDING;
        let nonceMaxTime: number = Timestamp.stringTimestampToLong(this.data.expirationTime);

        if (!this.useAttestation.checkValidity()){
            console.log('useAttestation.checkValidity failed');
            return false;
        };

        if (this.data.description != this.Eip712Description) {
            console.log('wrong description');
            return false;
        };

        let time: Timestamp = new Timestamp(this.data.timestamp);
        time.setValidity(this.maxTokenValidityInMs);
        if (!time.validateAgainstExpiration(Timestamp.stringTimestampToLong(this.data.expirationTime))) {

            console.log('verify timestamp failed.\n' + this.data.timestamp + "\n" + this.maxTokenValidityInMs + "\n" + this.data.expirationTime + "\n" + Timestamp.stringTimestampToLong(this.data.expirationTime) + "\n");
            return false;
        }

        if (this.requestorKeys.getAddress().toLowerCase() !== this.useAttestation.getAttestation().getUnsignedAttestation().getAddress().toLowerCase()) {
            console.log('wrong address');
            return false;
        };

        if (!(new Nonce().validateNonce(
            this.useAttestation.getPok().getNonce(),
            (this.useAttestation.getAttestation().getUnsignedAttestation()).getAddress(),
            this.domain,
            nonceMinTime,
            nonceMaxTime
        ))) {
            console.log('wrong Nonce');
            return false;
        };

        if (!this.proofLinking()) {
            console.log('wrong proofLinking');
            return false;
        };

        return true;
    }


    verify(): boolean {
        if (!this.useAttestation.verify()) {
            return false;
        }
        return true;
    }

    public getSessionPublicKey(): KeyPair {
        return this.useAttestation.getSessionPublicKey();
    }

}
