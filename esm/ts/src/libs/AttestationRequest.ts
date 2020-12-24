import { keyPair } from "./interfaces";
import { Asn1Der } from "./DerUtility";
import { ATTESTATION_TYPE } from "./interfaces";
import {hexStringToArray} from "./utils";
import {ProofOfExponent} from "./ProofOfExponent";
import {KeyPair} from "./KeyPair";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');
const ASN1 = require('@lapo/asn1js');

let sha3 = require("js-sha3");

/*
export interface derAttestRequest {
    0: { //unsignedEncoding
        0: string, //identity: string
        1: number, //type: number
        2: {
            0: string, // base: string
            1: string, // riddle: string
            2: string, // challenge: string
            3: string, // tPoint: string
        } //pok: string
    },
    1: {//pubPoint
        0: {
            0: number, // protocol ID 06072A8648CE3D0201
            1: {
                0: bigint, // 020101
                1: {
                    0: number, // 06072A8648CE3D0101
                    1: number // field size
                }, //
                2: {
                    0: string, // curve.a
                    1: string  // curve.b
                }
                3: string, // G coords with leading 04 + (der encoded, 128 bytes)
                4: bigint, // curveOrder
                5: bigint  // 020101
            }
        },
        1: bigint // pubPoint with leading 04 (der encoded, 128 bytes)
    },
    2: string //signature
    // length: number;
}
*/

export class AttestationRequest {
    signature: string;
    private identity: string;
    private type: number;
    private pok: string;
    private keys: KeyPair;
    constructor() {}
    static fromData(identity: string, type: string, pok: string, keys: KeyPair): AttestationRequest {
        let me = new this();
        me.create(identity, ATTESTATION_TYPE[type], pok, keys);
        return me;
    }
    create(identity: string, type: number, pok: string, keys: KeyPair){
        this.identity = identity;
        this.type = type;
        this.pok = pok;
        this.keys = keys;

        console.log('requestAttest request ready');
        let ecKey = ec.keyFromPrivate(this.keys.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(this.getUnsignedEncoding()))
        let signature = ecKey.sign(encodingHash);
        this.signature = signature.toDER('hex');
    }
    getUnsignedEncoding(){
        let res = Asn1Der.encode('VISIBLE_STRING',this.identity) +
            Asn1Der.encode('INTEGER',this.type) +
            this.pok;
        return Asn1Der.encode('SEQUENCE_30',res);
    }
    getDerEncoding(){
        // let ecKey = ec.keyFromPrivate(this.keys.getPrivateAsHexString(), 'hex');
        // var pubPoint = ecKey.getPublic().encode('hex');
        var pubPoint = this.keys.getPublicKeyAsHexStr();
        let pubPointTypeDescrDER = "3081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101";
        let pubKeyDer = Asn1Der.encode('SEQUENCE_30',
            pubPointTypeDescrDER +
            Asn1Der.encode('BIT_STRING', pubPoint)
        );

        let res = this.getUnsignedEncoding() +
            pubKeyDer +
            Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', res);
    }
    static fromBytes(asn1: Uint8Array): AttestationRequest {
        console.log("AttestationRequest fromBytes(asn1: Uint8Array)..");
        let me = new this();

        let mainSequence = ASN1.decode(asn1);
        if (mainSequence.typeName() != "SEQUENCE" || mainSequence.sub.length != 3) {
            throw new Error('Wrong attestation format');
        }

        let UnsignedEncodingSequence = mainSequence.sub[0];
        if (UnsignedEncodingSequence.typeName() != "SEQUENCE" || UnsignedEncodingSequence.sub.length != 3) {
            throw new Error('Wrong attestation format(UnsignedEncodingSequence)');
        }
        me.identity = UnsignedEncodingSequence.sub[0].content() as string;
        me.type = UnsignedEncodingSequence.sub[1].content();

        let pokSequence = UnsignedEncodingSequence.sub[2];
        if (pokSequence.typeName() != "SEQUENCE" || pokSequence.sub.length != 4) {
            throw new Error('Wrong attestation format(pokSequence)');
        }
        let baseEnc = pokSequence.sub[0].content().replace(/\(.+\)\s+/,'');
        let riddleEnc = pokSequence.sub[1].content().replace(/\(.+\)\s+/,'');
        let challengeEnc = pokSequence.sub[2].content().replace(/\(.+\)\s+/,'');
        let tPointEnc = pokSequence.sub[3].content().replace(/\(.+\)\s+/,'');

        console.log(`me.identity = ${me.identity}`);
        console.log(`me.type = ${me.type}`);
        console.log(`baseEnc = ${baseEnc}`);
        console.log(`riddleEnc = ${riddleEnc}`);
        console.log(`challengeEnc = ${challengeEnc}`);
        console.log(`tPointEnc = ${tPointEnc}`);

        console.log("lets do ProofOfExponent.fromArray..");
        let pok = ProofOfExponent.fromArray(baseEnc,riddleEnc,challengeEnc,tPointEnc)

        let pubKeySequence = mainSequence.sub[1];


        if (pubKeySequence.typeName() != "SEQUENCE" || pubKeySequence.sub.length != 2) {
            throw new Error('Wrong attestation format(pubKeySequence)');
        }

        let publicKeyDerHex = pubKeySequence.sub[1].toHexString();
        // console.log(`publicKeyDerHex = ${publicKeyDerHex}`);
        let publicKey = (new Asn1Der()).decode(Uint8Array.from(hexStringToArray(publicKeyDerHex)));

        let signatureDerHex = mainSequence.sub[2].toHexString();
        // console.log(`signatureBitStringHex = ${signatureDerHex}`);
        let signature = (new Asn1Der()).decode(Uint8Array.from(hexStringToArray(signatureDerHex)));

        console.log(`publicKey = ${publicKey}`);
        console.log(`signature = ${signature}`);
        console.log(`pokSequence = ${pokSequence}`);
        (window as any).bit = UnsignedEncodingSequence.sub[2];

        // if (!verify()) {
        //     throw new IllegalArgumentException("The signature is not valid");
        // }

        return me;
    }
}

