import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

import {Proof} from "./ProofOfExponentASN";

// IdentifierType ::= INTEGER { email(0), phone(1)}

// class IdentityPayload {
export class Identity {

    @AsnProp({ type: AsnPropTypes.Integer })
    public type: number;

    @AsnProp({ type: Proof })
    public proof: Proof;

}


