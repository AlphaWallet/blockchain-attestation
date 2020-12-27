import {ATTESTATION_TYPE, keyPair} from "./interfaces";
import {Asn1Der} from "./DerUtility";
import { AttestationCrypto } from "./AttestationCrypto";
import {bufToBn, hexStringToArray, uint8tohex} from "./utils";
import {KeyPair} from "./KeyPair";

let sha3 = require("js-sha3");
let EC = require("elliptic");
let ec = new EC.ec('secp256k1');


export class Cheque {
    publicKey: string;
    riddle: Uint8Array;
    encoded: string;
    // TODO code it
    constructor(private identifier: string, private type: string, private amount: number, private validity: number, private keys: KeyPair, private secret: bigint) {}

    createAndVerify(){
        let crypto = new AttestationCrypto();
        // this.riddle = crypto.makeRiddle(this.identifier, ATTESTATION_TYPE[this.type], this.secret);
        this.riddle = crypto.makeCommitment(this.identifier, ATTESTATION_TYPE[this.type], this.secret);

        this.publicKey = this.keys.getPublicKeyAsHexStr();
        let current =  new Date().getTime() ;
        let notValidBefore = current - (current % 1000); // Round down to nearest second
        let notValidAfter = notValidBefore + this.validity * 1000;
        let cheque = this.makeCheque(notValidBefore, notValidAfter);

        let ecKey = ec.keyFromPrivate(this.keys.getPrivateAsHexString(), 'hex');
        let chequeHash = sha3.keccak256(hexStringToArray(cheque));
        var signature = ecKey.sign( chequeHash );
        let pubPointHEX = this.keys.getPublicKeyAsHexStr();

        // console.log("signature.toDER() = " + bufToBn(signature.toDER()).toString(16) );
        // let signatureSequence = Asn1Der.encode('SEQUENCE_30',
        //     Asn1Der.encode('INTEGER',signature.r) +
        //     Asn1Der.encode('INTEGER',signature.s)
        // );

        // let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', bufToBn(signature.toDER()).toString(16));
        let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', signature.toDER('hex'));
        // console.log("signatureHexDerDitString = " + signatureHexDerDitString);

        this.encoded = this.encodeSignedCheque(
            cheque,
            signatureHexDerDitString,
            pubPointHEX);

        let verify = ecKey.verify(chequeHash, signature);
        // console.log('verify = ' + verify);

        if (!verify) {
            throw new Error("Public and private keys are incorrect");
        }
        // console.log(Asn1Der.encode('OCTET_STRING', this.secret.toString(16)));
        return {
            cheque,
            chequeEncoded: this.encoded,
            derSignature: signatureHexDerDitString,
            derSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', this.secret.toString(16)))
        }
    }

    encodeSignedCheque(cheque: string, derSign: string, pubPoint: string){
        let fullSequence = cheque + Asn1Der.encode('BIT_STRING', pubPoint) + derSign;
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }

    makeCheque(notValidBefore: number, notValidAfter: number){
        let timeList =
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(notValidBefore)) +
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(notValidAfter));
        // console.log('timeList = ' + timeList);
        let fullSequence =
            Asn1Der.encode('INTEGER', this.amount) +
            Asn1Der.encode('SEQUENCE_30', timeList) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle));
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }


    // TODO code it
    getDerEncoding(): Uint8Array{
        return Uint8Array.from([]);
    }
}

// TODO add timezone
function formatGeneralizedDateTime(date: any):string {
    var d = new Date(date),
        month = '' + (d.getUTCMonth() + 1),
        day = '' + d.getUTCDate(),
        year = d.getUTCFullYear();
    let hour = '' + d.getUTCHours(),
        min = '' + d.getUTCMinutes(),
        sec = '' + d.getUTCSeconds()

    if (month.length < 2)
        month = '0' + month;
    if (day.length < 2)
        day = '0' + day;
    if (hour.length < 2)
        hour = '0' + hour;
    if (min.length < 2)
        min = '0' + min;
    if (sec.length < 2)
        sec = '0' + sec;

    return [year, month, day, hour, min, sec].join('') + 'Z';
}
