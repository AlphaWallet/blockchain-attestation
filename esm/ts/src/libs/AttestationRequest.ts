import { keyPair } from "./interfaces";
import { Asn1Der } from "./DerUtility";
import { ATTESTATION_TYPE } from "./interfaces";
import {hexStringToArray} from "./utils";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

interface derAttestRequest {
    0: { //unsignedEncoding
        0: string, //identity: string
        1: number, //type: number
        2: string //pok: string
    },
    1: string, //pubPoint
    2: string //signature
    length: number;
}

export class AttestationRequest {
    signature: string;
    private identity: string;
    private type: number;
    private pok: string;
    private keys: keyPair;
    constructor() {}
    static fromData(identity: string, type: string, pok: string, keys: keyPair): AttestationRequest {
        let me = new this();
        me.create(identity, type, pok, keys);
        return me;
    }
    create(identity: string, type: string, pok: string, keys: keyPair){
        this.identity = identity;
        this.type = type;
        this.pok = pok;
        this.keys = keys;

        let ecKey = ec.keyFromPrivate(this.keys.priv);
        let signature = ecKey.sign(this.getUnsignedEncoding());
        this.signature = signature.toDER('hex');
    }
    getUnsignedEncoding(){
        let res = Asn1Der.encode('VISIBLE_STRING',this.identity) +
            Asn1Der.encode('INTEGER',ATTESTATION_TYPE[this.type]) +
            this.pok;
        return Asn1Der.encode('SEQUENCE_30',res);
    }
    getDerEncoding(){
        let ecKey = ec.keyFromPrivate(this.keys.priv);
        var pubPoint = ecKey.getPublic().encode('hex');

        let res = this.getUnsignedEncoding() +
            Asn1Der.encode('OCTET_STRING', pubPoint) +
            Asn1Der.encode('OCTET_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', res);
    }
    static fromDecodedObj(asn1: derAttestRequest): AttestationRequest {
        let me = new this();

        let unsigned = asn1[0];
        me.identity = unsigned[0];
        me.type = unsigned[1];
        // me.pok = new ProofOfExponent(unsigned.shift());
        let publicKey = asn1[2][1]; // skip asn1[2][0] as its a curve description
        let signature = asn1[2];

        // if (!verify()) {
        //     throw new IllegalArgumentException("The signature is not valid");
        // }

        return me;
    }
}

