import {ATTESTATION_TYPE, keyPair} from "./interfaces";
import {Asn1Der} from "./DerUtility";
import { AttestationCrypto } from "./AttestationCrypto";
import {bufToBn, hexStringToArray, uint8tohex} from "./utils";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";

let sha3 = require("js-sha3");
let EC = require("elliptic");
let ec = new EC.ec('secp256k1');


export class Cheque {
    // publicKey: string;
    // riddle: Uint8Array;
    private commitment: Uint8Array;
    public encoded: string;
    private identifier: string;
    private type: string;
    private amount: number;
    private validity: number;
    private keys: KeyPair;
    private secret: bigint;
    private notValidBefore: number;
    private notValidAfter: number;
    private signature: Uint8Array;
    // TODO code it
    constructor() {}

    static fromData(commitment: Uint8Array, amount: number, notValidBefore: number, notValidAfter: number, signature: Uint8Array, keys: KeyPair) {
        const me = new this();

        me.commitment = commitment;
        me.keys = keys;
        me.amount = amount;
        if (notValidBefore % 1000 != 0 || notValidAfter % 1000 != 0) {
            throw new Error("Can only support time granularity to the second");
        }
        me.notValidBefore = notValidBefore;
        me.notValidAfter = notValidAfter;
        me.signature = signature;
        let cheque = me.makeCheque();
        me.encoded = me.encodeSignedCheque(cheque, uint8tohex(signature));

        if (!me.verify()) {
            throw new Error("Signature is invalid");
        }

        return me;
    }

    static createAndVerify(identifier: string, type: string, amount: number, validity: number, keys: KeyPair, secret: bigint){

        let me = new this();

        me.identifier = identifier;
        me.type = type;
        me.amount = amount;
        me.validity = validity;
        me.keys = keys;
        me.secret = secret;

        let crypto = new AttestationCrypto();
        // this.riddle = crypto.makeRiddle(this.identifier, ATTESTATION_TYPE[this.type], this.secret);
        me.commitment = crypto.makeCommitment(me.identifier, ATTESTATION_TYPE[me.type], me.secret);

        // me.publicKey = me.keys.getPublicKeyAsHexStr();
        let current =  new Date().getTime() ;
        me.notValidBefore = current - (current % 1000); // Round down to nearest second
        me.notValidAfter = me.notValidBefore + me.validity * 1000;
        let cheque = me.makeCheque();

        let ecKey = ec.keyFromPrivate(me.keys.getPrivateAsHexString(), 'hex');
        let chequeHash = sha3.keccak256(hexStringToArray(cheque));
        var signature = ecKey.sign( chequeHash );

        // console.log("signature.toDER() = " + bufToBn(signature.toDER()).toString(16) );
        // let signatureSequence = Asn1Der.encode('SEQUENCE_30',
        //     Asn1Der.encode('INTEGER',signature.r) +
        //     Asn1Der.encode('INTEGER',signature.s)
        // );

        // let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', bufToBn(signature.toDER()).toString(16));
        let signatureHexDerDitString = Asn1Der.encode('BIT_STRING', signature.toDER('hex'));
        // console.log("signatureHexDerDitString = " + signatureHexDerDitString);

        me.encoded = me.encodeSignedCheque(
            cheque,
            signatureHexDerDitString,
        );

        let verify = ecKey.verify(chequeHash, signature);
        // console.log('verify = ' + verify);

        if (!verify) {
            throw new Error("Public and private keys are incorrect");
        }
        // console.log(Asn1Der.encode('OCTET_STRING', this.secret.toString(16)));
        return {
            cheque,
            chequeEncoded: me.encoded,
            derSignature: signatureHexDerDitString,
            derSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', me.secret.toString(16)))
        }
    }

    encodeSignedCheque(cheque: string, signature: string){
        let fullSequence = cheque + Asn1Der.encode('BIT_STRING', this.keys.getPublicKeyAsHexStr()) + signature;
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }

    // makeCheque(notValidBefore: number, notValidAfter: number){
    makeCheque(){
        let timeList =
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(this.notValidBefore)) +
            Asn1Der.encode('GENERALIZED_TIME', formatGeneralizedDateTime(this.notValidAfter));
        // console.log('timeList = ' + timeList);
        let fullSequence =
            Asn1Der.encode('INTEGER', this.amount) +
            Asn1Der.encode('SEQUENCE_30', timeList) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
        return Asn1Der.encode('SEQUENCE_30', fullSequence);
    }


    verify(): boolean{
        let cheque = this.makeCheque();

        // let ecKey = ec.keyFromPublic(this.keys.getPrivateAsHexString(), 'hex');
        // let chequeHash = sha3.keccak256(hexStringToArray(cheque));
        // return ecKey.verify(chequeHash, this.signature);

        return SignatureUtility.verify(cheque, uint8tohex(this.signature), this.keys);
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
