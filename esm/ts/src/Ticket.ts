import {AttestationCrypto} from "./libs/AttestationCrypto";
import {KeyPair} from "./libs/KeyPair";
import {ATTESTATION_TYPE} from "./libs/interfaces";
import {Asn1Der} from "./libs/DerUtility";
import {stringToArray} from "./libs/utils";
import {SignatureUtility} from "./libs/SignatureUtility";

class TicketClass {
    list: {[index:string]: number} = {
        REGULAR: 0,
        VIP: 1,
        SPEAKER: 2,
        STAFF: 3,
    }

    constructor(private value: string) {
    }

    public getValue() { return this.list[this.value]; }
}

class Ticket {

    private mail: string;
    private devconId: number;
    private secret: bigint;
    private commitment: Uint8Array;
    private encoded: string;
    // private publicKey: string;
    private signature: string;
    // private algorithm: string;

    private constructor(private ticketId: bigint, private ticketClass: TicketClass, private conferenceId: number, private keys: KeyPair) {}

    static createWithRiddle(ticketId: bigint, ticketClass: TicketClass, conferenceId: number, commitment: Uint8Array, signature: string, keys: KeyPair): Ticket {
        let me = new this(ticketId, ticketClass, conferenceId, keys);
        me.commitment = commitment;
        me.signature = signature;
        // me.algorithm = keys.getAsnDerPublic();
        me.encoded = me.encodeSignedTicket(me.makeTicket());
        if (!me.verify()) {
            throw new Error("Signature is invalid");
        }

        return me;
    }

    static createWithMail(mail: string, devconId:number , ticketId: bigint, ticketClass: TicketClass, conferenceId: number, keys: KeyPair, secret: bigint): Ticket {
        let me = new this(ticketId, ticketClass, conferenceId, keys);
        me.devconId = devconId;
        me.mail = mail;
        me.secret = secret;
        let crypto = new AttestationCrypto();
        me.commitment = crypto.makeCommitment(mail, ATTESTATION_TYPE['mail'], secret);

        // let algorithm = keys.getAsnDerPublic();

        let asn1Tic = me.makeTicket();

        me.signature = SignatureUtility.sign(asn1Tic, keys);
        me.encoded = me.encodeSignedTicket(asn1Tic);

        // me.publicKey = keys.getPublicKeyAsHexStr();
        if (!me.verify()) {
            throw new Error("Public and private keys are incorrect");
        }

        return me;
    }
    // static derDecode(derEncoded: string, keys: KeyPair): Ticket {
    //
    //     let me = new this(ticketId, ticketClass, conferenceId, keys);
    //
    //     return me;
    // }


    private makeTicket() {
        let ticket: string =
            Asn1Der.encode('INTEGER', this.devconId)
            + Asn1Der.encode('INTEGER', this.ticketId)
            + Asn1Der.encode('INTEGER', this.ticketClass.getValue());
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    encodeSignedTicket(ticket: string)  {
        let signedTicket:string =
            ticket
            + Asn1Der.encode('OCTET_STRING', this.commitment)
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncodingWithPK(): string {
        let ticket = this.makeTicket();
        let signedTicket: string =
            ticket
            + Asn1Der.encode('OCTET_STRING', this.commitment)
            + this.keys.getAsnDerPublic()
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncoding(): string {
        return this.encoded;
    }

    public verify(): boolean {
        return SignatureUtility.verify(this.makeTicket(), this.signature, this.keys);
    }

    public getTicketId():bigint {
        return this.ticketId;
    }

    public getTicketClass(): TicketClass {
        return this.ticketClass;
    }

    public getConferenceId(): number {
        return this.conferenceId;
    }

    public getСommitment(): Uint8Array {
        return this.commitment;
    }

    // public getAlgorithm(): string {
    //     return algorithm;
    // }

    // public getSignature(): string {
    //     return this.signature;
    // }

}
