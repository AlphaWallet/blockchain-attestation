import { Asn1Der } from "./libs/DerUtility";
import { AttestationRequest } from "./libs/AttestationRequest";
import { AttestationCrypto } from "./libs/AttestationCrypto";
import { keyPair } from "./libs/interfaces";
import { Cheque } from "./libs/Cheque";
import { ProofOfExponent } from "./libs/ProofOfExponent";
import {hexStringToArray} from "./libs/utils";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

class main {
    crypto: AttestationCrypto;
    Asn1Der: Asn1Der;
    constructor() {
        this.crypto = new AttestationCrypto();
        this.Asn1Der = new Asn1Der();
    }
    createKeys() {
        return this.crypto.createKeys();
    }

    createCheque(amount: number, receiverId: string, type: string, validityInMilliseconds: number, keys: keyPair, secret: bigint) {
        let cheque: Cheque = new Cheque(receiverId, type, amount, validityInMilliseconds, keys, secret);
        return cheque.createAndVerify();
    }

    requestAttest(receiverId: string, type: string, keys: keyPair) {
        let secret: bigint = this.crypto.makeSecret();
        let pok:ProofOfExponent = this.crypto.constructProof(receiverId, type, secret);
        let request = AttestationRequest.fromData(receiverId, type, pok.encoding, keys);
        return {
            request: request.getDerEncoding(),
            requestSignature: request.signature,
            requestSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', secret.toString(16)))
        }
    }

    constructAttest( keys: keyPair, issuerName: string, validityInMilliseconds: number, requestBytesDehHexStr: string): string {
        console.log("Signing attestation...");
        let decodedRequest =
            hexStringToArray(requestBytesDehHexStr)

        // urlBase64String = "30820285308201001A0D7465737440746573742E636F6D0201013081EB044104389C0DFD1617028AEA21035CA32879C3315518A2DA6E63A2D33D8144E1D6442F04D5A8B9921BF25793870F1B65B4442710BA1C840B75AC117EEF4195787F63C7044104A7CE38E4FABEFA76D90E93F781DD903818D68D4C3D8C8809C1202E6F5FBB908188799AC41954D925AF231C3E39F57985613E2BF5D14787E6CC33D00E93B8C9F004203B9B2E572844E746ACC2E9B177C144432586578162C66D530BDF38375695CEEE04410459EA4C2B9A8BC62ED7DF5B56228B16BC7A2C4F0005C35C90818DCB4D4676801C098ED921A747D04DF950F85E7C07AFBCBDAD756AF31767747C177DD4A97F8C7D308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101034200040D20FB5768855C9B4105C59FD1F046273C0E5F62014AECA8C8BE5E33AEB05808685BF04FB9A73814DD4EA5773FDE0240BC0D6B041A93F5629C6D4935FDE1A5E503480030450221009AC40862E551F0150B137628D22D42ABEA3BD7F97FF672EBE04B0CCDFD860323022071ADAA2C5E2233B249CFF33685E199CB550F9D6C4B2F80D70E13F438C6A9A878";

        let decoder = new Asn1Der();
        let request = decoder.readFromUrlBase64String(requestBytesDehHexStr);


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

