import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

export class Proof {

    @AsnProp({ type: AsnPropTypes.OctetString })
    public riddle: Uint8Array;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public challengePoint: Uint8Array;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public responseValue: Uint8Array;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public nonce: Uint8Array;

}

export class UsageProof {

    @AsnProp({ type: AsnPropTypes.OctetString })
    public challengePoint: Uint8Array;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public responseValue: Uint8Array;

    @AsnProp({ type: AsnPropTypes.OctetString })
    public nonce: Uint8Array;

}
