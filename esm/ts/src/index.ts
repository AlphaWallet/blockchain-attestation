import { Asn1Der } from "./libs/DerUtility";
import { AttestationRequest } from "./libs/AttestationRequest";
import { AttestationCrypto } from "./libs/AttestationCrypto";
import { keyPair } from "./libs/interfaces";
import { Cheque } from "./libs/Cheque";
import { ProofOfExponent } from "./libs/ProofOfExponent";
import {hexStringToArray} from "./libs/utils";
import {KeyPair} from "./libs/KeyPair";
const ASN1 = require('@lapo/asn1js');
// const Hex = require('@lapo/asn1js/hex');

// let EC = require("elliptic");
// let ec = new EC.ec('secp256k1');

class main {
    crypto: AttestationCrypto;
    Asn1Der: Asn1Der;
    Asn1: any;
    // Hex: any;
    constructor() {
        this.crypto = new AttestationCrypto();
        this.Asn1Der = new Asn1Der();
        this.Asn1 = ASN1;
        // this.Hex = Hex;
    }
    createKeys() {
        return KeyPair.createKeys();
    }

    keysFromPrivateBase64(str: string){
        return KeyPair.privateFromAsn1base64(str);
    }

    createCheque(amount: number, receiverId: string, type: string, validityInMilliseconds: number, keys: KeyPair, secret: bigint) {
        let cheque: Cheque = new Cheque(receiverId, type, amount, validityInMilliseconds, keys, secret);
        return cheque.createAndVerify();
    }

    requestAttest(receiverId: string, type: string, keys: KeyPair) {
        let secret: bigint = this.crypto.makeSecret();
        let pok:ProofOfExponent = this.crypto.constructProof(receiverId, type, secret);
        let request = AttestationRequest.fromData(receiverId, type, pok.encoding, keys);
        return {
            request: request.getDerEncoding(),
            requestSignature: request.signature,
            requestSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', secret.toString(16)))
        }
    }

    constructAttest( keys: KeyPair, issuerName: string, validityInMilliseconds: number, requestBytesDehHexStr: string): string {
        console.log("Signing attestation...");

        let attestRequest = AttestationRequest.fromBytes(Uint8Array.from(hexStringToArray(requestBytesDehHexStr)));

        // if (!request.checkValidity()) {
        //     console.log("Could not validate attestation signing request");
        //     throw new Error("Validation failed");
        // }
        // if (!request.verify()) {
        //     System.err.println("Could not verify attestation signing request");
        //     throw new Error("Validation failed");
        // }
        // let att = new IdentifierAttestation(request.getIdentity(), request.getType(), request.getPok().getRiddle().getEncoded(false), request.getPublicKey());
        // att.setIssuer("CN=" + issuerName);
        // att.setSerialNumber(new Random().nextLong());
        // Date now = new Date();
        // att.setNotValidBefore(now);
        // att.setNotValidAfter(new Date(System.currentTimeMillis() + validityInMilliseconds));
        // SignedAttestation signed = new SignedAttestation(att, keys);
        // if (!writeFile(attestationDir, DERUtility.printDER(signed.getDerEncoding(), "ATTESTATION"))) {
        //     System.err.println("Could not write attestation to disc");
        //     throw new IOException("Could not write file");
        // }
        return '';
    }

    // receiveCheque(userKeysDER: string, chequeSecret: string, attestationSecret: string, cheque: string, attestation: string, attestorKey: string){
    //     let userKeys = DERUtility.restoreBase64Keys(userKeysDER);
        // byte[] chequeSecretBytes = DERUtility.restoreBytes(readFile(chequeSecretDir));
        // BigInteger chequeSecret = DERUtility.decodeSecret(chequeSecretBytes);
        // byte[] attestationSecretBytes = DERUtility.restoreBytes(readFile(attestationSecretDir));
        // BigInteger attestationSecret = DERUtility.decodeSecret(attestationSecretBytes);
        // byte[] chequeBytes = DERUtility.restoreBytes(readFile(chequeDir));
        // Cheque cheque = new Cheque(chequeBytes);
        // byte[] attestationBytes = DERUtility.restoreBytes(readFile(attestationDir));
        // AsymmetricKeyParameter attestationProviderKey = PublicKeyFactory.createKey(
        //     DERUtility.restoreBytes(readFile(attestorKeyDir)));
        // SignedAttestation att = new SignedAttestation(attestationBytes, attestationProviderKey);
        //
        // if (!cheque.checkValidity()) {
        //     System.err.println("Could not validate cheque");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!cheque.verify()) {
        //     System.err.println("Could not verify cheque");
        //     throw new RuntimeException("Verification failed");
        // }
        // if (!att.checkValidity()) {
        //     System.err.println("Could not validate attestation");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!att.verify()) {
        //     System.err.println("Could not verify attestation");
        //     throw new RuntimeException("Verification failed");
        // }
        //
        // RedeemCheque redeem = new RedeemCheque(cheque, att, userKeys, attestationSecret, chequeSecret);
        // if (!redeem.checkValidity()) {
        //     System.err.println("Could not validate redeem request");
        //     throw new RuntimeException("Validation failed");
        // }
        // if (!redeem.verify()) {
        //     System.err.println("Could not verify redeem request");
        //     throw new RuntimeException("Verification failed");
        // }
        // // TODO how should this actually be?
        // SmartContract sc = new SmartContract();
        // if (!sc.testEncoding(redeem.getPok())) {
        //     System.err.println("Could not submit proof of knowledge to the chain");
        //     throw new RuntimeException("Chain submission failed");
        // }
    // }

}
(window as any).CryptoTicket = main;

