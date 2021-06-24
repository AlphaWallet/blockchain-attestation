import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { ValidityValue, AlgorithmIdentifierASN} from "./AuthenticationFramework";

export class DevconTicket {
    @AsnProp({ type: AsnPropTypes.Utf8String }) public devconId: string;
    @AsnProp({ type: AsnPropTypes.Integer }) public ticketId: number;
    @AsnProp({ type: AsnPropTypes.Integer }) public ticketClass: number;
}

export class PublicKeyInfo {
    @AsnProp({ type: AlgorithmIdentifierASN }) public algorithm: AlgorithmIdentifierASN;
    @AsnProp({ type: AsnPropTypes.BitString }) public publicKey:AsnPropTypes.BitString;
}

export class SignedDevconTicket {

    @AsnProp({ type: DevconTicket })
    public ticket: DevconTicket;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public commitment: Uint8Array;

    @AsnProp({ type: PublicKeyInfo, optional: true })
    public publicKeyInfo?: PublicKeyInfo;

    @AsnProp({ type: AsnPropTypes.BitString })
    public signatureValue: Uint8Array;

}
