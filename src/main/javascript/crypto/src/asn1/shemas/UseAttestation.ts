import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {Proof} from "./ProofOfExponentASN";
import {MyAttestation, PublicKeyInfoValue} from "./AttestationFramework";

export class UseAttestation {

    @AsnProp({ type: MyAttestation })
    public attestation: MyAttestation;

    @AsnProp({ type: AsnPropTypes.Integer })
    public type: number;

    @AsnProp({ type: Proof })
    public proof: Proof;

    @AsnProp({ type: PublicKeyInfoValue })
    public sessionKey: PublicKeyInfoValue;

}

