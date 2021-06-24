import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {AlgorithmIdentifierASN, Extensions, ValidityValue, Version} from "./AuthenticationFramework";
import {Name} from "./InformationFramework";
import {AttestsTo, SmartContract, SubjectPublicKeyInfo} from "./AttestationFramework";

// IMPORTS
// AlgorithmIdentifier,
//     CertificateSerialNumber,
//     Extensions
// FROM AuthenticationFramework
// Name
// FROM InformationFramework;

export class UriIdAttestation {

    // dont decode signedInfo to stay is solid for verification
    @AsnProp({type: AsnPropTypes.Any}) public signedInfo: Uint8Array = new Uint8Array();
    // @AsnProp({ type: SignedInfo }) public signedInfo:SignedInfo;
    @AsnProp({type: AlgorithmIdentifierASN}) public signatureAlgorithm: AlgorithmIdentifierASN;
    @AsnProp({type: AsnPropTypes.BitString}) public signatureValue: Uint8Array;
}

export class SignedInfo {
    @AsnProp({ type: Version }) public version: Version; // [0]  EXPLICIT Version,
    @AsnProp({ type: AsnPropTypes.Integer }) public serialNumber: number; // CertificateSerialNumber,
    @AsnProp({ type: AlgorithmIdentifierASN }) public signature: AlgorithmIdentifierASN; // AlgorithmIdentifier,
    @AsnProp({ type: Name }) public issuer:Name; // Name,
    // TODO validity             Validity,
    @AsnProp({ type: ValidityValue, optional: true }) public validity?:ValidityValue; // Validity,
    // TODO subject              Subject,
    @AsnProp({ type: Name }) public subject: Name; //  Name,
    @AsnProp({ type: SubjectPublicKeyInfo }) public subjectPublicKeyInfo: SubjectPublicKeyInfo; // SubjectPublicKeyInfo,
    // TODO extensions      [3]  EXPLICIT Extensions
    @AsnProp({ type: Extensions }) public extensions: Extensions;
}

// Validity ::= SEQUENCE {
//     notBefore       GeneralizedTime,
//         notAfter        GeneralizedTime  ("99991231235959Z") -- Unlimited validity --
// }
//
// Subject ::= SEQUENCE SIZE (1) OF Identifier
//
// Identifier ::= SET SIZE (1) OF IdentifierTypeAndValue
// IdentifierTypeAndValue ::= SEQUENCE {
//     type     OBJECT IDENTIFIER
//     -- MUST be labeledURI --
//     DEFAULT {iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 250 1 labeledURI(57)},
//     value    UniversalString -- MUST be an URI, optionally followed by a space character and then a label
// }


