import { keyPair } from "./interfaces";
import { Asn1Der } from "./DerUtility";
import { ATTESTATION_TYPE } from "./interfaces";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

export class AttestationRequest {
    signature: string;
    private identity: string;
    private type: string;
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
    static fromBytes(urlBase64String: string): AttestationRequest {
        let me = new this();

        urlBase64String = "30820285308201001A0D7465737440746573742E636F6D0201013081EB044104389C0DFD1617028AEA21035CA32879C3315518A2DA6E63A2D33D8144E1D6442F04D5A8B9921BF25793870F1B65B4442710BA1C840B75AC117EEF4195787F63C7044104A7CE38E4FABEFA76D90E93F781DD903818D68D4C3D8C8809C1202E6F5FBB908188799AC41954D925AF231C3E39F57985613E2BF5D14787E6CC33D00E93B8C9F004203B9B2E572844E746ACC2E9B177C144432586578162C66D530BDF38375695CEEE04410459EA4C2B9A8BC62ED7DF5B56228B16BC7A2C4F0005C35C90818DCB4D4676801C098ED921A747D04DF950F85E7C07AFBCBDAD756AF31767747C177DD4A97F8C7D308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101034200040D20FB5768855C9B4105C59FD1F046273C0E5F62014AECA8C8BE5E33AEB05808685BF04FB9A73814DD4EA5773FDE0240BC0D6B041A93F5629C6D4935FDE1A5E503480030450221009AC40862E551F0150B137628D22D42ABEA3BD7F97FF672EBE04B0CCDFD860323022071ADAA2C5E2233B249CFF33685E199CB550F9D6C4B2F80D70E13F438C6A9A878";

        let decoder = new Asn1Der();
        let asn1 = decoder.readFromUrlBase64String(urlBase64String);
        let unsigned = asn1.shift();
        me.identity = unsigned.shift();
        me.type = unsigned.shift();
        // me.pok = new ProofOfExponent(unsigned.shift());
        let spki = asn1.shift();
        let spkiCurveDescription = spki.shift();
        let publicKey = spki.shift();
        let signature = asn1.shift();

        // if (!verify()) {
        //     throw new IllegalArgumentException("The signature is not valid");
        // }

        return me;
    }
}

