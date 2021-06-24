import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {UriIdAttestation} from "./UriIdAttestation";

// -- The 256 bit non-negative integer uniquely representing the ERC721 token in question in binary --
// TokenId ::= OCTET STRING (SIZE(32))
//
// -- The binary encoding of the 20 bytes representing an Ethereum address --
// Address ::= OCTET STRING (SIZE(20))

export class ERC721 {
    @AsnProp({ type: AsnPropTypes.OctetString }) public TokenId: Uint8Array;
    @AsnProp({ type: AsnPropTypes.OctetString }) public Address: Uint8Array;
}

// Tokens ::= SEQUENCE SIZE (1..MAX) OF ERC721
//
// -- See https://eips.ethereum.org/EIPS/eip-721 for details --
//     ERC721 ::= SEQUENCE {
//     tokenId       TokenId,
//         address       Address
// }
// TODO implement SEQUENCE SIZE (1..MAX) OF ERC721
export class Tokens {
    @AsnProp({ type: ERC721, optional: true }) public tokens: ERC721;
}

export class NFTAttestation {
    @AsnProp({ type: Tokens, optional: true }) public tokens?: Tokens;
    // -- A hash digest --
    // Digest ::= OCTET STRING (SIZE(32..MAX))
    // @AsnProp({ type: Digest, optional: true }) public nftDigest?: Digest;
    @AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public nftDigest?: Uint8Array;
    @AsnProp({ type: UriIdAttestation }) public creator: UriIdAttestation;
    @AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}


