import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {SignedDevconTicket} from "./SignedDevconTicket";
import {MyAttestation, SmartContract} from "./AttestationFramework";
import {UsageProof} from "./ProofOfExponentASN";

export class UseToken {

    // stay it as Uint8Array to save original encoding for future verification and object decoding
    // @AsnProp({ type: SignedDevconTicket })
    // public signedDevconTicket: SignedDevconTicket;
    @AsnProp({ type: AsnPropTypes.Any })
    public signedToken: Uint8Array;

    // stay it as Uint8Array to save original encoding for future verification and object decoding
    // @AsnProp({ type: MyAttestation })
    // public attestation: MyAttestation;
    @AsnProp({ type: AsnPropTypes.Any })
    public attestation: Uint8Array;

    // @AsnProp({ type: UsageProof })
    // public proof: UsageProof;
    @AsnProp({ type: AsnPropTypes.Any })
    public proof: Uint8Array;

    @AsnProp({ type: AsnPropTypes.BitString, optional: true })
    public signatureValue?: Uint8Array;

}
