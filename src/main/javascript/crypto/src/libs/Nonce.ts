import {
    getInt64Bytes,
    hashStringTo32bytesUint8,
    stringToArray,
    uint8merge, uint8ToBn, uint8tohex, uint8toString
} from "./utils";
import {SignatureUtility} from "./SignatureUtility";
import {ValidationTools} from "./ValidationTools";
import {Timestamp} from "./Timestamp";

export class Nonce {
    static LONG_BYTES:number = 8;

    public DEFAULT_NONCE_TIME_LIMIT_MS:number = 1000*60*20; // 20 min

    private static senderAddressIndexStart: number = 0;
    private static senderAddressIndexStop: number = ValidationTools.ADDRESS_LENGTH_IN_BYTES;
    private static receiverIdentifierIndexStart: number = Nonce.senderAddressIndexStop;
    // private static receiverIdentifierIndexStop: number = Nonce.receiverIdentifierIndexStart + AttestationCrypto.BYTES_IN_DIGEST;
    private static receiverIdentifierIndexStop: number = Nonce.receiverIdentifierIndexStart + 256 / 8;//AttestationCrypto.BYTES_IN_DIGEST;
    private static timestampIndexStart: number = Nonce.receiverIdentifierIndexStop;
    private static timestampIndexStop: number = Nonce.timestampIndexStart + Nonce.LONG_BYTES;
    private static otherDataIndexStart: number = Nonce.timestampIndexStop;

    static async makeNonce(senderAddress: string = '', receiverIdentifier: string, otherData: Uint8Array = new Uint8Array(0), timestampInMs: number = 0) {
        // Hash to ensure all variable length components is encoded with constant length
        if (!senderAddress) {
            senderAddress = await SignatureUtility.connectMetamaskAndGetAddress();
        }

        if (!ValidationTools.isAddress(senderAddress)) {
            throw new Error("Address is not valid");
        }

        // senderAddress = '0x'+senderAddress.substr(2,40).toUpperCase();
        senderAddress = senderAddress.toUpperCase();

        if (!timestampInMs) {
            timestampInMs = Date.now();
        }

        return uint8merge([
            Uint8Array.from(stringToArray(senderAddress)),
            hashStringTo32bytesUint8(receiverIdentifier),
            getInt64Bytes(timestampInMs),
            otherData
        ]);
    }

    validateNonce(nonce: Uint8Array, senderAddress: string, receiverIdentifier: string, minTime:number, maxTime:number, otherData: Uint8Array = new Uint8Array(0)): boolean{

        if (!Nonce.validateAddress(nonce, senderAddress)) {
            console.log('validateAddress check failed');
            return false;
        }

        if (!this.validateReceiverIdentifier(nonce, receiverIdentifier)) {
            console.log('validateReceiverIdentifier check failed');
            return false;
        }

        if (!this.validateTimestamp(nonce, minTime, maxTime)) {
            console.log('timestamp check failed');
            return false;
        }

        if (!this.validateOtherData(nonce, otherData)) {
            console.log('otherData check failed');
            return false;
        }


        return this.validateOtherData(nonce, otherData);

    }

    validateTimestamp(nonce: Uint8Array, minTime:number, maxTime: number): boolean {

        let nonceTimeStamp: number = Nonce.getTimestamp(nonce);

        let nonceStamp = new Timestamp(nonceTimeStamp);
        nonceStamp.setValidity(maxTime - minTime);
        return nonceStamp.validateAgainstExpiration(maxTime);
    }

    static validateAddress(nonce: Uint8Array, address: string):boolean {
        if (address.toUpperCase() === uint8toString(nonce.slice(Nonce.senderAddressIndexStart, Nonce.senderAddressIndexStop)).toUpperCase()) return true;
        return false;
    }

    validateReceiverIdentifier(nonce: Uint8Array, receiverIdentifier: string):boolean {
        if (uint8tohex(hashStringTo32bytesUint8(receiverIdentifier)).toLowerCase() === uint8tohex(nonce.slice(Nonce.receiverIdentifierIndexStart, Nonce.receiverIdentifierIndexStop)).toLowerCase()) return true;
        return false;
    }

    validateOtherData(nonce: Uint8Array, otherData: Uint8Array):boolean {
        if (uint8tohex(otherData).toLowerCase() === uint8tohex(nonce.slice(Nonce.otherDataIndexStart, Nonce.otherDataIndexStart + otherData.length )).toLowerCase()) return true;
        return false;
    }

    static getTimestamp(nonce: Uint8Array): number {
        let time = nonce.slice(Nonce.timestampIndexStart,Nonce.timestampIndexStop);
        let bn = uint8ToBn(time);
        // console.log('time in uint8' + uint8tohex(time));
        // console.log('time in bn' + bn);
        if (bn > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('timestamp value bigger than MAX_SAFE_INTEGER');
        return Number(bn);
    }

}
