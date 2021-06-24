import {ATTESTATION_TYPE} from "./interfaces";
import {Point, CURVE_BN256} from "./Point";
import {
    mod,
    uint8merge,
    stringToArray,
    BnPowMod,  bnToUint8, uint8ToBn
} from "./utils";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {UsageProofOfExponent} from "./UsageProofOfExponent";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";

const crypto = require('crypto');

let sha3 = require("js-sha3");

// Generator for message part of Pedersen commitments generated deterministically from mapToInteger queried on 0 and mapped to the curve using try-and-increment
export const Pedestren_G = new Point(21282764439311451829394129092047993080259557426320933158672611067687630484067n, 3813889942691430704369624600187664845713336792511424430006907067499686345744n, CURVE_BN256);
export const Pedestren_H = new Point(10844896013696871595893151490650636250667003995871483372134187278207473369077n, 9393217696329481319187854592386054938412168121447413803797200472841959383227n, CURVE_BN256);


export class AttestationCrypto {
    rand: bigint;
    static OID_SIGNATURE_ALG: string = "1.2.840.10045.2.1";
    private curveOrderBitLength: bigint = 254n;
    static BYTES_IN_DIGEST: number = 256 / 8;
    constructor() {
        this.rand = this.makeSecret();
        // if (mod(CURVE_BN256.P,4n) != 3n) {
        //     throw new Error("The crypto will not work with this choice of curve");
        // }
        if (!this.verifyCurveOrder(CURVE_BN256.n)) {
            throw new Error("Static values do not work with current implementation");
        }

    }

    private verifyCurveOrder(curveOrder: bigint): boolean{
        // Verify that the curve order is less than 2^256 bits, which is required by mapToCurveMultiplier
        // Specifically checking if it is larger than 2^curveOrderBitLength and that no bits at position curveOrderBitLength+1 or larger are set
        let curveOrderBitLength: bigint = BigInt(curveOrder.toString(2).length);
        // console.log(`curve length = ${curveOrderBitLength}`);
        if (curveOrder < (1n << (curveOrderBitLength-1n)) || (curveOrder >> curveOrderBitLength) > 0n) {
            console.log("Curve order is not 253 bits which is required by the current implementation");
            return false;
        }
        return true;
    }

    getType(type: string): number {
        switch (type.toLowerCase()) {
            case "mail":
                return ATTESTATION_TYPE.mail;
            case "phone":
                return ATTESTATION_TYPE.phone;
            default:
                throw new Error("Wrong type of identifier");
        }
    }

    // makeRiddle(identity: string, type: number, secret: bigint): Uint8Array {
    //     let hashedIdentity = this.hashIdentifier(type, identity);
    //     return hashedIdentity.multiplyDA(secret).getEncoded(false);
    // }

    /**
     * Construct a Pedersen commitment to an identifier using a specific secret.
     * @param identity The common identifier
     * @param type The type of identifier
     * @param secret The secret randomness to be used in the commitment
     * @return
     */
    makeCommitment(identity: string, type: number, secret: bigint): Uint8Array {
        let hashedIdentity = this.mapToCurveMultiplier(type, identity);

        let commitment: Point = Pedestren_G.multiplyDA(hashedIdentity).add(Pedestren_H.multiplyDA(secret));
        return commitment.getEncoded(false);

        // let hiding:Point = Pedestren_H.multiplyDA(secret);
        // return this.makeCommitmentFromHiding(identity, type, hiding);
    }
    /**
     * Constructs a commitment to an identity based on hidden randomization supplied from a user.
     * This is used to construct an attestation.
     * @param identity The user's identity.
     * @param type The type of identity.
     * @param hiding The hiding the user has picked
     * @return
     */
    makeCommitmentFromHiding(identity: string, type: number, hiding: Point): Uint8Array {
        // let hashedIdentity:bigint = this.mapToIntegerIntString(type, identity);
        let hashedIdentity:bigint = this.mapToCurveMultiplier(type, identity);
        // Construct Pedersen commitment
        let commitment:Point = Pedestren_G.multiplyDA(hashedIdentity).add(hiding);
        return commitment.getEncoded(false);
    }

    // hashIdentifier(type: number , identity: string): Point {
    //     let idenNum = this.mapToInteger(type, Uint8Array.from(stringToArray(identity.trim().toLowerCase())));
    //     // console.log(`idenNum(for base point) = ${idenNum}`);
    //     return this.computePoint_bn256(idenNum);
    // }

    injectIdentifierType(type: number, arr: Uint8Array): Uint8Array{
        // add prefix [0,0,0,1] for email type
        return uint8merge([Uint8Array.from([0,0,0,type]),arr]);
    }

    mapToInteger(arr: Uint8Array ):bigint {
        return BigInt('0x' + sha3.keccak256(arr))>>(256n - this.curveOrderBitLength);
    }

    mapToCurveMultiplier(type: number, identity: string):bigint {

        let identityBytes:Uint8Array = Uint8Array.from(stringToArray(identity.trim().toLowerCase() ) );

        let uintArr:Uint8Array = this.injectIdentifierType(type, identityBytes);
        let sampledVal:bigint = uint8ToBn(uintArr);
        do {
            sampledVal = this.mapToInteger(bnToUint8(sampledVal));
        } while (sampledVal >= CURVE_BN256.n);
        return sampledVal;
    }

    // mapToIntegerFromUint8(arr: Uint8Array ):bigint {
    //     let hash0: string = sha3.keccak256( uint8merge([Uint8Array.from([0]),arr]) );
    //     let hash1: string = sha3.keccak256( uint8merge([Uint8Array.from([1]),arr]) );
    //
    //     return BigInt('0x' + hash0 + hash1);
    // }

    // computePoint_SECP256k1( x: bigint ): Point {
    //     x = mod ( x );
    //     let y = 0n, expected = 0n, ySquare = 0n;
    //     let resPoint,referencePoint: Point;
    //     let p = CURVE_SECP256k1.P;
    //     let a = CURVE_SECP256k1.A;
    //     let b = CURVE_SECP256k1.B;
    //     do {
    //         do {
    //             x = mod(x + 1n);
    //             ySquare = mod(BnPowMod(x, 3n, p) + a * x + b);
    //             y = BnPowMod(ySquare, CURVE_SECP256k1.magicExp, p);
    //             expected = mod(y * y);
    //         } while (expected !== ySquare);
    //         resPoint = new Point(x, y);
    //         // TODO add Point.negate() and use following logic
    //         // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
    //         if (resPoint.y > (p / 2n)) {
    //             resPoint = new Point(x, p - y);
    //         }
    //         referencePoint = resPoint.multiplyDA(CURVE_SECP256k1.n - 1n);
    //         if (referencePoint.y > (p / 2n)) {
    //             referencePoint = new Point(referencePoint.x, p - referencePoint.y);
    //         }
    //     } while (!resPoint.equals(referencePoint))
    //     return resPoint;
    // }

    computePoint_bn256( x: bigint ): Point {
        let fieldSize = CURVE_BN256.P;
        x = mod ( x, fieldSize );
        let y = 0n, ySquare = 0n;
        let resPoint,referencePoint: Point;
        let quadraticResidue: bigint;
        let magicExp = (fieldSize + 1n) >> 2n; // fieldSize + 1 / 4
        let quadraticResidueExp = (fieldSize - 1n) >> 1n;

        do {
            do {
                x = mod(x + 1n);
                // console.log('x = ' + x );
                ySquare = mod(BnPowMod(x, 3n, fieldSize) + CURVE_BN256.A * x + CURVE_BN256.B);
                quadraticResidue = BnPowMod(ySquare, quadraticResidueExp, fieldSize);
            } while (quadraticResidue !== 1n);
            // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)

            y = BnPowMod(ySquare, magicExp, fieldSize);
            resPoint = new Point(x, y, CURVE_BN256);
            // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
            if (resPoint.x > (fieldSize >> 1n)) {
                resPoint = new Point(x, fieldSize - y, CURVE_BN256);
            }
            referencePoint = resPoint.multiplyDA(CURVE_BN256.n - 1n);
            if (referencePoint.y > (fieldSize >> 1n) ) {
                referencePoint = new Point(referencePoint.x, fieldSize - referencePoint.y, CURVE_BN256);
            }
            // Verify that the element is a member of the expected (subgroup) by ensuring that it has the right order, through Fermat's little theorem
            // NOTE: this is ONLY needed if we DON'T use secp256k1, so currently it is superflous but we are keeping it this check is crucial for security on most other curves!
        } while (!resPoint.equals(referencePoint) || resPoint.isInfinity())
        return resPoint;
    }

    makeSecret(bytes = 48): bigint{

        return mod(BigInt(AttestationCrypto.generateRandomHexString(bytes)), CURVE_BN256.n);
    }

    static generateRandomHexString(len: number): string {
        var array = new Uint8Array(len);

        if (window && window.crypto){
            window.crypto.getRandomValues(array);
        } else {
            array = new Uint8Array(crypto.randomBytes(len));
        }

        let output = '0x';
        for (var i = 0; i < array.length; i++) {
            output += array[i].toString(16).padStart(2,'0');
        }

        return output;
    }


    /**
     * Computes a proof of knowledge of a random exponent
     * This is used to convince the attestor that the user knows a secret which the attestor will
     * then use to construct a Pedersen commitment to the user's identifier.
     * @param randomness The randomness used in the commitment
     * @return
     */
    public computeAttestationProof(randomness: bigint, nonce: Uint8Array = new Uint8Array([])): FullProofOfExponent {
        // Compute the random part of the commitment, i.e. H^randomness
        let riddle: Point = Pedestren_H.multiplyDA(randomness);
        let challengeList: Point[] = [Pedestren_H, riddle];
        return this.constructSchnorrPOK(riddle, randomness, challengeList, nonce);
    }
    /**
     * Compute a proof that commitment1 and commitment2 are Pedersen commitments to the same message and that the user
     * knows randomness1-randomness2.
     * NOTE: We are actually not proving that the user knows the message and randomness1 and randomness2.
     * This is because we assume the user has already proven knowledge of his message (mail) and the
     * randomness1 used in the attestation to the attestor. Because of this assumption it is enough to prove
     * knowledge of randomness2 (equivalent to proving knowledge of randomness1-randomness2) and that the
     * commitments are to the same message.
     * The reason we do this is that this weaker proof is significantly cheaper to execute on the blockchain.
     *
     * In conclusion what this method actually proves is knowledge that randomness1-randomness2 is the
     * discrete log of commitment1/commitment2.
     * I.e. that commitment1/commitment2 =H^(randomness1-randomness2)
     * @param commitment1 First Pedersen commitment to some message m
     * @param commitment2 Second Pedersen commitment to some message m
     * @param randomness1 The randomness used in commitment1
     * @param randomness2 The randomness used in commitment2
     * @return
     */
    public computeEqualityProof(commitment1:string, commitment2: string, randomness1:bigint, randomness2:bigint, nonce: Uint8Array = new Uint8Array([])):UsageProofOfExponent {
        let comPoint1: Point = Point.decodeFromHex(commitment1, CURVE_BN256);
        let comPoint2: Point = Point.decodeFromHex(commitment2, CURVE_BN256);
        // Compute H*(randomness1-randomness2=commitment1-commitment2=G*msg+H*randomness1-G*msg+H*randomness2
        let riddle: Point = comPoint1.subtract(comPoint2);
        let exponent: bigint = mod(randomness1 - randomness2, CURVE_BN256.n);
        let challengeList: Point[] = [Pedestren_H, comPoint1, comPoint2];
        return this.constructSchnorrPOK(riddle, exponent, challengeList, nonce).getUsageProofOfExponent();
    }
    /**
     * Constructs a Schnorr proof of knowledge of exponent of a riddle to base H.
     * The challenge value used (c) is computed from the challengeList and the internal t value.
     * The method uses rejection sampling to ensure that the t value is sampled s.t. the
     * challenge will always be less than curveOrder.
     */
    private constructSchnorrPOK(riddle: Point, exponent: bigint, challengePoints: Point[], nonce: Uint8Array):FullProofOfExponent {
        let t: Point;
        let hiding, c, d:bigint;
        // Use rejection sampling to sample a hiding value s.t. the random oracle challenge c computed from it is less than curveOrder
        do {
            hiding = this.makeSecret();
            t = Pedestren_H.multiplyDA(hiding);
            // c = this.mapToInteger(this.makeArray(challengeList.concat([t])));
            c = this.computeChallenge(t, challengePoints, nonce);
        } while (c >= CURVE_BN256.n);
        d = mod(hiding + c * exponent, CURVE_BN256.n);
        return FullProofOfExponent.fromData(riddle, t, d, nonce);
    }
    computeChallenge(t: Point, challengeList: Point[], nonce: Uint8Array): bigint {
        let finalChallengeList = challengeList.concat(t);
        let challengePointBytes: Uint8Array = this.makeArray(finalChallengeList);
        let challengeBytes = uint8merge([challengePointBytes, nonce]);
        return this.mapToInteger(challengeBytes);
    }

    /**
     * Verifies a zero knowledge proof of knowledge of a riddle used in an attestation request
     * @param pok The proof to verify
     * @return True if the proof is OK and false otherwise
     */
    public verifyFullProof(pok: FullProofOfExponent): boolean  {
        // let c:bigint = this.mapToInteger(this.makeArray([Pedestren_H, pok.getRiddle(), pok.getPoint()]));
        let c:bigint = this.computeChallenge(pok.getPoint(),[Pedestren_H, pok.getRiddle()], pok.getNonce());

        return this.verifyPok(pok, c);
    }

    /**
     * Verifies a zero knowledge proof of knowledge of the two riddles used in two different
     * commitments to the same message.
     * This is used by the smart contract to verify that a request is ok where one commitment is the
     * riddle for a cheque/ticket and the other is the riddle from an attesation.
     * @param pok The proof to verify
     * @return True if the proof is OK and false otherwise
     */
    public verifyEqualityProof(commitment1: Uint8Array, commitment2: Uint8Array, pok: ProofOfExponentInterface): boolean  {
        let comPoint1: Point = Point.decodeFromUint8(commitment1, CURVE_BN256);
        let comPoint2: Point = Point.decodeFromUint8(commitment2, CURVE_BN256);
        // Compute the value the riddle should have
        let riddle: Point = comPoint1.subtract(comPoint2);
        // let c: bigint = this.mapToInteger(this.makeArray([Pedestren_H, comPoint1, comPoint2, pok.getPoint()]));
        let c: bigint = this.computeChallenge(pok.getPoint(), [Pedestren_H, comPoint1, comPoint2], pok.getNonce());
        return this.verifyPok(FullProofOfExponent.fromData(riddle, pok.getPoint(), pok.getChallenge(), pok.getNonce()), c);
    }

    private verifyPok(pok: FullProofOfExponent, c: bigint): boolean {
        // Check that the c has been sampled correctly using rejection sampling
        if (c >= CURVE_BN256.n) {
            return false;
        }
        let lhs: Point = Pedestren_H.multiplyDA(pok.getChallenge());
        let rhs: Point = pok.getRiddle().multiplyDA(c).add(pok.getPoint());

        return lhs.equals(rhs);
    }


    // computeProof(base: Point, riddle: Point, exponent: bigint): ProofOfExponent{
    //     let r: bigint = this.makeSecret();
    //     let t: Point = base.multiplyDA(r);
    //     // TODO ideally Bob's ethreum address should also be part of the challenge
    //     let c: bigint = mod(this.mapToIntegerFromUint8(this.makeArray([base, riddle, t])), CURVE_BN256.n);
    //     let d: bigint = mod(r + c * exponent, CURVE_BN256.n);
    //     return  new ProofOfExponent(base, riddle, t, d);
    // }

    makeArray(pointArray: Point[]): Uint8Array{
        let output: Uint8Array = new Uint8Array(0);
        pointArray.forEach( (item:Point) => {
            output = new Uint8Array([ ...output, ...item.getEncoded(false)]);
        })
        return output;
    }
    // verifyProof(pok: ProofOfExponent)  {
    //     let c = mod(this.mapToIntegerFromUint8(this.makeArray([pok.getBase(), pok.getRiddle(), pok.getPoint()])), CURVE_BN256.n);
    //     let lhs: Point = pok.getBase().multiplyDA(pok.getChallenge());
    //     let rhs: Point = pok.getRiddle().multiplyDA(c).add(pok.getPoint());
    //     return lhs.equals(rhs);
    // }

    static hashWithKeccak(data: Uint8Array): Uint8Array {
        return sha3.keccak256(data);
    }

}
