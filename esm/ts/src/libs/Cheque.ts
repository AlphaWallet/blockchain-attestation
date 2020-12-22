import {keyPair} from "./interfaces";
import {Asn1Der} from "./DerUtility";
import { AttestationCrypto } from "./AttestationCrypto";
import { uint8tohex } from "./utils";
let EC = require("elliptic");
let ec = new EC.ec('secp256k1');


export class Cheque {
    publicKey: bigint;
    riddle: Uint8Array;
    encoded: string;
    // TODO code it
    constructor(private identifier: string, private type: string, private amount: number, private validity: number, private keys: keyPair, private secret: bigint) {}

    createAndVerify(){
        let crypto = new AttestationCrypto();
        this.riddle = crypto.makeRiddle(this.identifier, this.type, this.secret);
        // this.publicKey = this.keys.pub;
        let current =  new Date().getTime() ;
        let notValidBefore = current - (current % 1000); // Round down to nearest second
        let notValidAfter = notValidBefore + this.validity * 1000;
        let cheque = this.makeCheque(notValidBefore, notValidAfter);

        let ecKey = ec.keyFromPrivate(this.keys.priv);
        var signature = ecKey.sign(cheque);
        let pubPoint = ecKey.getPublic();
        var pubPointHEX = pubPoint.getX().toString(16) + pubPoint.getY().toString(16);

        let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', signature.r.toString(16) + signature.s.toString(16));

        this.encoded = this.encodeSignedCheque(
            cheque,
            signatureHexDerDitString,
            pubPointHEX);

        let verify = ecKey.verify(cheque, signature);
        // console.log('verify = ' + verify);

        if (!verify) {
            throw new Error("Public and private keys are incorrect");
        }
        console.log(Asn1Der.encode('OCTET_STRING', this.secret.toString(16)));
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
    if (day.length < 2)
        sec = '0' + sec;

    return [year, month, day, hour, min, sec].join('') + 'Z';
}
