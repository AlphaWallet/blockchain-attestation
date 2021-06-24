import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

export class Signature {

    @AsnProp({ type: AsnPropTypes.Integer })
    public r: bigint;

    @AsnProp({ type: AsnPropTypes.Integer })
    public s: bigint;

}
