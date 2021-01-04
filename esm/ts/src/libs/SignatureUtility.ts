import {hexStringToArray} from "./utils";
import {KeyPair} from "./KeyPair";
let EC = require("elliptic");
let ec = new EC.ec('secp256k1');
// const ASN1 = require('@lapo/asn1js');

let sha3 = require("js-sha3");

export class SignatureUtility {
    static sign(str: string, keys: KeyPair):string {
        let ecKey = ec.keyFromPrivate(keys.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(str))
        let signature = ecKey.sign(encodingHash);
        return signature.toDER('hex');
    }
    static verify(str: string, signature: string, keys: KeyPair):boolean {
        let ecKey = ec.keyFromPublic(keys.getPublicKeyAsHexStr(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(str))
        return ecKey.verify(encodingHash, signature);
    }
}
