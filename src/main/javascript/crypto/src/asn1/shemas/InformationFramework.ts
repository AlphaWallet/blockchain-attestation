import {AsnArray, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";

/*
// RelativeDistinguishedName ::=
//     SET SIZE (1..MAX) OF AttributeTypeAndValue
// @AsnType({ type: AsnTypeTypes.Set })
export class RelativeDistinguishedName {
    @AsnProp({ type: AttributeTypeAndValue})
    public rdnSequence?: AttributeTypeAndValue;
}

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// export class RDNSequence {
//     @AsnProp({ type: RelativeDistinguishedName})
//     public rdnSequence?: RelativeDistinguishedName;
// }
// @AsnType({ type: AsnTypeTypes.Set })
*/

class AttributeTypeAndValue {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    type: string;

    // @AsnProp({ type: AsnPropTypes.Any })//ANY -- DEFINED BY AttributeType
    // value: ArrayBuffer;
    // hardcode as UTF8String
    @AsnProp({ type: AsnPropTypes.Utf8String })
    value: string;
}

@AsnType({ type: AsnTypeTypes.Set, itemType: AttributeTypeAndValue })
class RelativeDistinguishedName extends AsnArray<AttributeTypeAndValue> {
    constructor(items?: AttributeTypeAndValue[]) {
        super(items);
        Object.setPrototypeOf(this, RelativeDistinguishedName.prototype);
    }
}

@AsnType({ type: AsnTypeTypes.Sequence, itemType: RelativeDistinguishedName })
class RDNSequence extends AsnArray<RelativeDistinguishedName> {
    constructor(items?: RelativeDistinguishedName[]) {
        super(items);
        Object.setPrototypeOf(this, RDNSequence.prototype);
    }
}

@AsnType({ type: AsnTypeTypes.Choice })
export class Name {
    @AsnProp({ type: RDNSequence })
    rdnSequence?: RDNSequence;

    @AsnProp({ type: AsnPropTypes.Null })
    null?: any;
}


