import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {SubjectPublicKeyInfo} from "./AttestationFramework";
import {Proof} from "./ProofOfExponentASN";

// IdentifierType ::= INTEGER { email(0), phone(1)}

class UnsignedIdentifier {

    @AsnProp({ type: AsnPropTypes.VisibleString })
    public identifier: string;

    @AsnProp({ type: AsnPropTypes.Integer })
    public type: number;

    @AsnProp({ type: Proof })
    public proof: Proof;

}

export class Identifier {

    @AsnProp({ type: UnsignedIdentifier })
    public unsignedIdentifier: UnsignedIdentifier;

    @AsnProp({ type: SubjectPublicKeyInfo })
    public publicKey: SubjectPublicKeyInfo;

    @AsnProp({ type: AsnPropTypes.BitString })
    public signatureValue: Uint8Array;

}


