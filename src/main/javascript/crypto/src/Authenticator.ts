import {Ticket} from "./Ticket";
import {KeyPair} from "./libs/KeyPair";
import {base64ToUint8array, uint8ToBn} from "./libs/utils";
import {SignedIdentityAttestation} from "./libs/SignedIdentityAttestation";
import {AttestedObject} from "./libs/AttestedObject";
import {XMLconfigData} from "./data/tokenData";
import {AttestationCrypto} from "./libs/AttestationCrypto";
import {AttestationRequest} from "./libs/AttestationRequest";
import {Nonce} from "./libs/Nonce";
import {Eip712AttestationRequest} from "./libs/Eip712AttestationRequest";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {SignatureUtility} from "./libs/SignatureUtility";
import {FullProofOfExponent} from "./libs/FullProofOfExponent";
import {UseAttestation} from "./libs/UseAttestation";
import {Eip712AttestationUsage} from "./libs/Eip712AttestationUsage";
import {Verifiable} from "./libs/Verifiable";
import {TokenValidateable} from "./libs/TokenValidateable";
import {Eip712AttestationRequestWithUsage} from "./libs/Eip712AttestationRequestWithUsage";
import {AttestationRequestWithUsage} from "./libs/AttestationRequestWithUsage";
import {Validateable} from "./libs/Validateable";

const { subtle } = require('crypto').webcrypto;

declare global {
    interface Window {
        attachEvent: any;
        detachEvent: any;
    }
}

const ALPHA_CONFIG = {
    indexedDBname: "AlphaDB",
    indexedDBobject: "AlphaKeyStore",
    indexedDBid: "TK",
    keysAlgorithm: {
        name: "ECDSA",
        // namedCurve: "P-384"
        namedCurve: "P-256"
    },
    signAlgorithm: {
        name: "ECDSA",
        // hash: {name: "SHA-384"},
        hash: {name: "SHA-256"},
    }
};

export interface devconToken {
    ticketBlob: string,
    ticketSecret: bigint,
    attestationOrigin: string,
}

export class Authenticator {
    private signedTokenBlob: string;
    private signedTokenSecret: bigint;

    private attestationBlob: string;
    private attestationSecret: bigint;

    private attestationOrigin: string;
    private authResultCallback: Function;

    private iframe: any;
    private iframeWrap: any;
    private base64senderPublicKey: string;
    private base64attestorPubKey: string;

    private webDomain: string;

    constructor(private negotiator: any = false) {
        let XMLconfig = XMLconfigData;

        this.base64senderPublicKey = XMLconfig.base64senderPublicKey;
        this.base64attestorPubKey = XMLconfig.base64attestorPubKey;
        this.webDomain = XMLconfig.webDomain;
    }

    getAuthenticationBlob(tokenObj: devconToken, authResultCallback: Function) {
        // TODO - what is tokenType, where can we see structure etc.
        // 1. Find the token type (using TokenScript)
        // Oleg: we can avoid Autenticator -> Negotiator request, just have to receive everything in single input object
        // let tokenType = Negotiator.getTokenType(tokenObj.tokenClass);
        // 2. Trace from its TokenScript which website has the needed data object
        // if (tokenType.attestationOrigin) { // always return true in Devcon project,
        // unless DevCon changed their tokenscript and moved all tickets to the contract

        this.signedTokenBlob = tokenObj.ticketBlob;
        this.signedTokenSecret = tokenObj.ticketSecret;
        this.attestationOrigin = tokenObj.attestationOrigin;
        this.authResultCallback = authResultCallback;
        this.getIdentifierAttestation();

    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    getIdentifierAttestation() {
        console.log('getIdentifierAttestation. create iframe.')
        // attach postMessage listener and wait for attestation data
        this.attachPostMessageListener(this.postMessageAttestationListener.bind(this));
        const iframe = document.createElement('iframe');
        this.iframe = iframe;
        iframe.src = this.attestationOrigin;
        iframe.style.width = '800px';
        iframe.style.height = '700px';
        iframe.style.maxWidth = '100%';
        iframe.style.background = '#fff';
        let iframeWrap = document.createElement('div');
        this.iframeWrap = iframeWrap;
        iframeWrap.setAttribute('style', 'width:100%;min-height: 100vh; position: fixed; align-items: center; justify-content: center;display: none;top: 0; left: 0; background: #fffa');
        iframeWrap.appendChild(iframe);

        document.body.appendChild(iframeWrap);
    }

    async getUseTicket(
        // userKey: KeyPair,
        ticketSecret: bigint,
        attestationSecret: bigint,
        base64ticket: string,
        base64attestation: string,
        base64attestationPublicKey: string,
        base64senderPublicKey: string
    )
    {
        // let ticket: Ticket = Ticket.fromBase64(base64ticket, KeyPair.fromPublicHex(base64senderPublicKey));
        let ticket: Ticket = Ticket.fromBase64(base64ticket, KeyPair.publicFromBase64(base64senderPublicKey));
        if (!ticket.checkValidity()) {
            console.log("Could not validate cheque");
            throw new Error("Validation failed");
        }
        if (!ticket.verify()) {
            console.log("Could not verify ticket");
            throw new Error("Verification failed");
        }
        console.log('ticked valid (signature OK)');

        // let keyUint8data = base64ToUint8array(base64attestationPublicKey);
        // let key:SubjectPublicKeyInfo = AsnParser.parse(keyUint8data, SubjectPublicKeyInfo);

        // let attestorKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(key.value.publicKey)));
        let attestorKey = KeyPair.publicFromBase64(base64attestationPublicKey);

        console.log('lets test attestaion:');

        let att = SignedIdentityAttestation.fromBytes(base64ToUint8array(base64attestation), attestorKey);

        if (!att.checkValidity()) {
            console.log("Could not validate attestation");
            throw new Error("Validation failed");
        }
        if (!att.verify()) {
            console.log("Could not verify attestation");
            throw new Error("Verification failed");
        }
        console.log('attestaion valid');

        let redeem: AttestedObject = new AttestedObject();
        redeem.create(ticket, att,
            BigInt(attestationSecret), BigInt(ticketSecret));
        redeem.setWebDomain(this.webDomain);

        // console.log("redeem.getDerEncodeProof(): ");
        // console.log(redeem.getDerEncodeProof());
        // TODO sign EIP712 with Metamask
        let signed = await redeem.sign();
        console.log(signed);
        return signed;

    }

    postMessageAttestationListener(event: MessageEvent){
        let attestURL = new URL(this.attestationOrigin);

        if (event.origin !== attestURL.origin) {
            return;
        }

        console.log('postMessageAttestationListener event');
        console.log(event)

        if (
            typeof event.data.ready !== "undefined"
            && event.data.ready === true
        ) {
            this.iframe.contentWindow.postMessage({force: false}, this.attestationOrigin);
            return;
        }


        if (
            typeof event.data.display !== "undefined"
        ) {
            if (event.data.display === true) {
                this.iframeWrap.style.display = 'flex';
                this.negotiator && this.negotiator.commandDisplayIframe();
            } else {
                this.iframeWrap.style.display = 'none';
                this.negotiator && this.negotiator.commandHideIframe();
            }
        }

        if (
            !event.data.hasOwnProperty('attestation')
            || !event.data.hasOwnProperty('requestSecret')
        ) {
            return;
        }
        this.iframeWrap.remove();
        this.attestationBlob = event.data.attestation;
        this.attestationSecret = event.data.requestSecret;

        // console.log('attestation data received.');
        // console.log(this.attestationBlob);
        // console.log(this.attestationSecret);
        // console.log(this.base64attestorPubKey);

        try {
            this.getUseTicket(
                this.signedTokenSecret,
                this.attestationSecret,
                this.signedTokenBlob ,
                this.attestationBlob ,
                this.base64attestorPubKey,
                this.base64senderPublicKey,
            ).then(useToken => {
                if (useToken){
                    console.log('this.authResultCallback(useToken): ');
                    this.authResultCallback(useToken);
                } else {
                    console.log('this.authResultCallback( empty sting ): ');
                    this.authResultCallback(useToken);
                }

            })


        } catch (e){
            console.log(`UseDevconTicket. Something went wrong. ${e}`);
            this.authResultCallback(false);
        }
        // construct UseDevconTicket, see
        // https://github.com/TokenScript/attestation/blob/main/data-modules/src/UseDevconTicket.asd

        // TODO we dont have ready UseDevconTicket constructor yet
        // let useDevconTicket = new UseDevconTicket({
        //     signedDevconTicket: signedDevonTicket,
        //     identifierAttestation: identifierAttestation,
        //     proof: proof
        // })
        // // Serialise it (for use as a transaction parameter) and return it
        // return useDevconTicket.serialize();
    }

    attachPostMessageListener(listener: Function){
        if (window.addEventListener) {
            window.addEventListener("message", (e) => {
                listener(e);
            }, false);
        } else {
            // IE8
            window.attachEvent("onmessage", (e: MessageEvent) => {
                listener(e);
            });
        }
    }


    /*
     * get ticket attestation from wallet, or issuer site's local storage through iframe
     *  - Open an Iframe and obtain the data object (in this case SignedDevonTicket)
     */
    // function

    // getTokenAttestation(tokenObj) {
    // }

    static async requestAttest( receiverId: string, type: string, attestorDomain: string, secret: bigint, userKey: KeyPair = null ){

        let crypto = new AttestationCrypto();
        let userAddress;
        if (userKey) {
            userAddress = userKey.getAddress();
        } else {
            try {
                userAddress = await SignatureUtility.connectMetamaskAndGetAddress();
            } catch (e){
                console.log('Cant find user Ethereum Address. Please check Metamask. ' + e);
                return;
            }
        }

        let nonce = await Nonce.makeNonce(userAddress, attestorDomain);

        let pok = crypto.computeAttestationProof(secret, nonce);
        let attRequest = AttestationRequest.fromData(crypto.getType(type), pok);
        let attest = new Eip712AttestationRequest(userKey);
        await attest.addData(attestorDomain, 20*1000, receiverId, attRequest);
        let attestJson = attest.getJsonEncoding();

        return attestJson;

    }

    // static async constructAttest(
    //     attestorKey: KeyPair,
    //     receiverId: string,
    //     type: string,
    //     ATTESTOR_DOMAIN: string,
    //     attestationSecretBase64: string,
    //     sessionKey: KeyPair,
    // ){
    //
    // }

    static constructAttest(
        attestorKey: KeyPair,
        issuerName: string,
        validityInMilliseconds: number ,
        attestRequestJson: string,
        attestorDomain: string ){
        let att: IdentifierAttestation;
        let crypto = new AttestationCrypto();
        let attestationRequest;
        let commitment;

        try {
            // decode JSON and fill publicKey
            attestationRequest = new Eip712AttestationRequest();
            attestationRequest.setDomain(attestorDomain);
            attestationRequest.fillJsonData(attestRequestJson);

            Authenticator.checkAttestRequestVerifiability(attestationRequest);
            Authenticator.checkAttestRequestValidity(attestationRequest);

        } catch (e){
            let m = "Failed to fill attestation data from json. " + e + "\nRestores as an Eip712AttestationRequestWithUsage object instead";
            console.log(m);
            try {
                attestationRequest = new Eip712AttestationRequestWithUsage();
                attestationRequest.setDomain(attestorDomain);
                attestationRequest.fillJsonData(attestRequestJson);
                Authenticator.checkAttestRequestVerifiability(attestationRequest);
                Authenticator.checkAttestRequestValidity(attestationRequest);
            } catch (e) {
                let m = "Failed to parse Eip712AttestationRequestWithUsage. " + e;
                console.log(m);
                throw new Error(m);
            }
        }

        commitment = crypto.makeCommitmentFromHiding(attestationRequest.getIdentifier(), attestationRequest.getType(), attestationRequest.getPok().getRiddle());

        att = new IdentifierAttestation();
        att.fromCommitment(commitment, attestationRequest.getUserPublicKey());
        att.setIssuer("CN=" + issuerName);
        att.setSerialNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER) );
        let now = Date.now();
        att.setNotValidBefore(now);
        att.setNotValidAfter(now + validityInMilliseconds);
        let signed: SignedIdentityAttestation = SignedIdentityAttestation.fromData(att, attestorKey);
        return signed.getDerEncoding();
    }

    // PREFIX + "user-priv.pem", PREFIX + "attestation.crt", PREFIX + "attestation-secret.pem", PREFIX + "attestor-pub.pem", "test@test.ts", "mail", PREFIX + "session-priv.pem", PREFIX + "use-attestation.json"
    static async useAttest(
        attestationBase64: string,
        attestationSecretBase64: string ,
        attestorKey: KeyPair,
        receiverId: string,
        type: string,
        webDomain: string,
        sessionKey: KeyPair = null,
        userKey: KeyPair = null){



        const attestationUint8 = base64ToUint8array(attestationBase64);
        let att = SignedIdentityAttestation.fromBytes(attestationUint8, attestorKey);
        let attestationSecretDerUint8 = base64ToUint8array(attestationSecretBase64);
        // remove first 4 bytes because us der encoding
        let attestationSecret = uint8ToBn(attestationSecretDerUint8.slice(4));

        let crypto = new AttestationCrypto();

        let address;
        if (userKey) {
            address = userKey.getAddress();
        } else {
            address = await SignatureUtility.connectMetamaskAndGetAddress();
        }

        let nonce = await Nonce.makeNonce(address, webDomain);

        let pok: FullProofOfExponent = crypto.computeAttestationProof(attestationSecret, nonce);

        try {
            let attUsage: UseAttestation = UseAttestation.fromData(att, crypto.getType(type), pok, sessionKey);
            let usageRequest: Eip712AttestationUsage = new Eip712AttestationUsage(userKey);
            let res = await usageRequest.addData(webDomain, receiverId, attUsage);
            // console.log('usageRequest ready state = ' + res);
            // console.log('usageRequest.getJsonEncoding() = ' + usageRequest.getJsonEncoding());
            return usageRequest.getJsonEncoding();
        } catch (e) {
            console.error(e);
        }

    }

    static checkAttestRequestVerifiability( input:Verifiable) {
        if (!input.verify()) {
            console.log("Could not verify attestation signing request");
            throw new Error("Verification failed");
        }
    }

    static checkAttestRequestValidity( input:Validateable) {
        if (!input.checkValidity()) {
            console.log("Could not validate attestation signing request");
            throw new Error("Validation failed");
        }
    }

    static checkUsageVerifiability(input: Verifiable) {
        if (!input.verify()) {
            console.error("Could not verify usage request");
            throw new Error("Verification failed");
        }
    }

    static checkUsageValidity( input: TokenValidateable) {
        if (!input.checkTokenValidity()) {
            console.error("Could not validate usage request");
            throw new Error("Validation failed");
        }
    }

    static async verifyUsage(
        jsonRequest: string,
        attestorKey: KeyPair,
        message: string,
        WEB_DOMAIN: string,
        signature: Uint8Array){

        let sessionPublicKey: KeyPair;

        try {
            // console.log('lets create Eip712AttestationUsage from json');
            let usageRequest: Eip712AttestationUsage = new Eip712AttestationUsage();
            usageRequest.setDomain(WEB_DOMAIN);
            usageRequest.fillJsonData( jsonRequest, attestorKey);

            Authenticator.checkUsageVerifiability(usageRequest);
            Authenticator.checkUsageValidity(usageRequest);
            sessionPublicKey = usageRequest.getSessionPublicKey();

        } catch (e) {
            // Try as an  Eip712AttestationRequestWithUsage object instead, which is NOT linked to a specific website
            console.log('Eip712AttestationUsage failed. ' + e + '. Lets try to verify Eip712AttestationRequestWithUsage');
            let usageRequest: Eip712AttestationRequestWithUsage = new Eip712AttestationRequestWithUsage();
            usageRequest.setDomain(WEB_DOMAIN);
            usageRequest.fillJsonData( jsonRequest );
            Authenticator.checkUsageVerifiability(usageRequest);

            Authenticator.checkUsageValidity(usageRequest);
            sessionPublicKey = usageRequest.getSessionPublicKey();
            // console.log('sessionPublicKey from Eip712AttestationRequestWithUsage = '+ sessionPublicKey.getAddress());
        }

        // Validate signature
        try {
            let res = await sessionPublicKey.verifyStringWithSubtle(KeyPair.anySignatureToRawUint8(signature) , message);
            if (!res) {
                console.error("Could not verify message signature");
                throw new Error("Signature verification failed");
            }
             return "SUCCESSFULLY validated usage request!";
        } catch (e) {
            let m = "Cant verify session with subtle. " + e;
            console.log(m);
            console.error(e);
            // console.error(sessionPublicKey);
            // throw new Error(m);
        }
    }

    static async requestAttestAndUsage(
        userKey: KeyPair,
        receiverId: string,
        type: string,
        ATTESTOR_DOMAIN: string,
        attestationSecretBase64: string,
        sessionKey: KeyPair,
        ){
        try {
            let attestationSecret = uint8ToBn(base64ToUint8array(attestationSecretBase64));

            let address;
            if (userKey) {
                address = userKey.getAddress();
            } else {
                address = await SignatureUtility.connectMetamaskAndGetAddress();
            }

            let nonce: Uint8Array = await Nonce.makeNonce(address, ATTESTOR_DOMAIN, new Uint8Array(0), Date.now());
            let crypto = new AttestationCrypto();

            let pok: FullProofOfExponent = crypto.computeAttestationProof(attestationSecret, nonce);

            let attRequest: AttestationRequestWithUsage =  AttestationRequestWithUsage.fromData(crypto.getType(type), pok, sessionKey);
            let request: Eip712AttestationRequestWithUsage = new Eip712AttestationRequestWithUsage(userKey);
            await request.fromData(ATTESTOR_DOMAIN, undefined, undefined, receiverId, attRequest);
            // console.log('request.getJsonEncoding() = ' + request.getJsonEncoding());
            return request.getJsonEncoding();
        } catch (e) {
            let m = "requestAttestAndUsage error. " + e;
            console.log(m);
            console.error(e);
        }

    }


/*
    static async signMessageWithSessionKey(message: Uint8Array, sessionKey: Uint8Array = new Uint8Array(0)){
        let privKey, signature;
        // console.log("message = " + uint8tohex(message));

        try {
            if (sessionKey && sessionKey.length) {
                // its nodejs and session primary key received in Uint8Array
                console.log("sessionKey = " + uint8tohex(sessionKey));
                console.log(sessionKey);

            } else {
                // TODO read key from local storage
            }
            // signature = await crypto.subtle.sign(ALPHA_CONFIG.signAlgorithm, privKey, message);
        } catch (e){
            console.log(e);
            // throw new Error(e);
        }
        // let signatureHex = uint8tohex(new Uint8Array(signature));
        // return signatureHex;
    }

    static async verifyMessageSignatureWithSessionKey(message: Uint8Array, signature: string, sessionKey: Uint8Array = new Uint8Array(0)){
        let privKey;
        if (sessionKey && sessionKey.length) {
            // its nodejs and session primary key received in Uint8Array
            privKey = await subtle.importKey(
                'raw',
                sessionKey,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ['sign', 'verify']
            );
        } else {
            // TODO read key from local storage
        }

        let signatureUint8 = hexStringToUint8(signature);

        const result = await crypto.subtle.verify(ALPHA_CONFIG.keysAlgorithm, privKey.publicKey, signatureUint8, message );
    }

 */

}
