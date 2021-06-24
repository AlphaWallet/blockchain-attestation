import {AttestationCrypto} from "./libs/AttestationCrypto";
import {KeyPair} from "./libs/KeyPair";
import {ATTESTATION_TYPE} from "./libs/interfaces";
import {Asn1Der} from "./libs/DerUtility";
import {SignatureUtility} from "./libs/SignatureUtility";
import {AttestableObject} from "./libs/AttestableObject";
import {base64ToUint8array, hexStringToArray, uint8toBuffer, uint8tohex} from "./libs/utils";
import {SignedDevconTicket} from "./asn1/shemas/SignedDevconTicket";
import {AsnParser} from "@peculiar/asn1-schema";
import {Attestable} from "./libs/Attestable";
/*
class TicketClass {
    list: {[index:string]: number} = {
        REGULAR: 0,
        VIP: 1,
        SPEAKER: 2,
        STAFF: 3,
    }

    static decodeList: {[index:number]: string} = {
        0: "REGULAR",
        1: "VIP",
        2: "SPEAKER",
        3: "STAFF"
    }

    constructor(private value: string) {
    }

    static fromInt(value: number): TicketClass {
        return new this(TicketClass.decodeList[value]);
    }

    public getValue() { return this.list[this.value]; }
}

 */

export class Ticket extends AttestableObject implements Attestable {

    private ticketId: bigint;
    private ticketClass: number;
    private devconId: string;
    private magicLinkURLPrefix:string = "https://ticket.devcon.org/";

    private signature: string;
    // private commitment: Uint8Array;

    private keys: KeyPair;
    // protected encoded: string;


    constructor() {
        super();
    }

    fromData(devconId: string, ticketId: bigint, ticketClass:number, keys: KeyPair){
        this.ticketId = ticketId;
        this.ticketClass = ticketClass;
        this.devconId = devconId;
        this.keys = keys;
    }

    createWithCommitment(devconId: string, ticketId: bigint, ticketClass: number, commitment: Uint8Array, signature: string, keys: KeyPair) {
        this.fromData(devconId, ticketId, ticketClass, keys);
        this.commitment = commitment;
        this.signature = signature;
        this.encoded = this.encodeSignedTicket(this.makeTicket());
        if (!this.verify()) {
            throw new Error("Signature is invalid");
        }
    }

    static createWithMail(mail: string, devconId:string , ticketId: bigint, ticketClass: number, keys: KeyPair, secret: bigint): Ticket {
        let me = new this();
        me.fromData(devconId, ticketId, ticketClass, keys);

        let crypto = new AttestationCrypto();
        let commitment,signature;

        let asn1Tic = me.makeTicket();
        try {
            commitment = crypto.makeCommitment(mail, crypto.getType('mail'), secret);
            signature = keys.signBytesWithEthereum(hexStringToArray(asn1Tic));
        } catch (e) {
            throw new Error(e);
        }

        me.createWithCommitment(devconId, ticketId, ticketClass, commitment, signature, keys);
        return me;
    }

    private makeTicket() {
        let ticket: string =
            Asn1Der.encode('UTF8STRING', this.devconId)
            + Asn1Der.encode('INTEGER', this.ticketId)
            + Asn1Der.encode('INTEGER', this.ticketClass);
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    encodeSignedTicket(ticket: string)  {
        let signedTicket:string =
            ticket
            + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment))
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncodingWithPK(): string {
        let ticket = this.makeTicket();
        let signedTicket: string =
            ticket
            + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment))
            + this.keys.getAsnDerPublic()
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncoding():string {
        return this.encoded;
    }

    public verify(): boolean {
        return this.keys.verifyBytesWithEthereum(hexStringToArray(this.makeTicket()), this.signature);
    }

    public checkValidity(): boolean {
        // The ticket is always valid on its own. It depends on which conference it is used
        // and whether it has been revoked that decides if it can be used
        return true;
    }

    public getTicketId():bigint {
        return this.ticketId;
    }

    public getTicketClass(): number {
        return this.ticketClass;
    }

    public getSignature(): string {
        return this.signature;
    }

    static fromBase64(base64str: string, keys: KeyPair): Ticket {
        let me = new this();
        me.fromBytes(base64ToUint8array(base64str), keys);
        return me;
    }

    fromBytes(bytes: Uint8Array, keys: KeyPair) {
        const signedDevconTicket: SignedDevconTicket = AsnParser.parse(uint8toBuffer(bytes), SignedDevconTicket);

        let devconId:string = signedDevconTicket.ticket.devconId;
        let ticketId:bigint = BigInt(signedDevconTicket.ticket.ticketId);
        let ticketClassInt:number = signedDevconTicket.ticket.ticketClass;

        let commitment:Uint8Array = signedDevconTicket.commitment;
        let signature:Uint8Array = signedDevconTicket.signatureValue;
        this.createWithCommitment(devconId, ticketId, ticketClassInt, new Uint8Array(commitment), uint8tohex(new Uint8Array(signature)) , keys );
    }

    public getCommitment(): Uint8Array {
        return this.commitment;
    }


    public getUrlEncoding() {
        // TODO implement
        // SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.publicKey);
        // return URLUtility.encodeList(Arrays.asList(this.encoded, keyInfo.getPublicKeyData().getEncoded()));
    }

}
