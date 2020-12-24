import {ATTESTATION_TYPE} from "./interfaces";
import {Point, CURVE_SECP256k1, CURVE_BN256} from "./Point";
import {
    mod,
    uint8merge,
    stringToArray,
    BnPowMod,
    uint8tohex,
    bufToBn,
    base64ToUint8array,
    hexStringToArray
} from "./utils";
import {ProofOfExponent } from "./ProofOfExponent";

let sha3 = require("js-sha3");

export class AttestationCrypto {
    rand: bigint;
    constructor() {
        this.rand = this.makeSecret();
        if (mod(CURVE_BN256.P,4n) != 3n) {
            throw new Error("The crypto will not work with this choice of curve");
        }
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
    makeRiddle(identity: string, type: string, secret: bigint) {
        let hashedIdentity = this.hashIdentifier(type, identity);
        return hashedIdentity.multiplyDA(secret).getEncoded(false);
    }
    // TODO use type
    hashIdentifier(type: string , identity: string): Point {
        let idenNum = this.mapToInteger(type, Uint8Array.from(stringToArray(identity.trim().toLowerCase())));
        // console.log(`idenNum(for base point) = ${idenNum}`);
        return this.computePoint_bn256(idenNum);
    }
    // TODO change arr type
    mapToInteger(type: string, arr: Uint8Array ):bigint {
        // add prefix [0,0,0,1] for email type
        let prefix = [0,0,0,ATTESTATION_TYPE[type]];
        let uintArr = uint8merge([Uint8Array.from(prefix),arr]);
        return this.mapToIntegerFromUint8(uintArr);

        // return mod(BigInt('0x'+sha3.keccak384()),CURVE_BN256.P);
    }
    mapToIntegerFromUint8(arr: Uint8Array ):bigint {
        let idenNum = BigInt( '0x'+ sha3.keccak384(arr));
        return mod(idenNum, CURVE_BN256.P);
    }

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

        let quadraticResidueExp = (fieldSize - 1n) >> 1n;
        do {
            do {
                x = mod(x + 1n, fieldSize);
                // console.log('x = ' + x );
                ySquare = mod(BnPowMod(x, 3n, fieldSize) + CURVE_BN256.A * x + CURVE_BN256.B, fieldSize);
                quadraticResidue = BnPowMod(ySquare, quadraticResidueExp, fieldSize);
            } while (quadraticResidue !== 1n);
            // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)

            y = BnPowMod(ySquare, CURVE_BN256.magicExp, fieldSize);
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
            // console.log('resPoint.equals(referencePoint) = ' + resPoint.equals(referencePoint) );
            // console.log('resPoint.x = ' + resPoint.x.toString(16) );
            // console.log('referencePoint.x = ' + referencePoint.x.toString(16) );
        } while (!resPoint.equals(referencePoint) || resPoint.isInfinity())
        // console.log("resPoint = ",resPoint);
        // console.log("resPointY = ",resPoint.y.toString(16));
        // console.log("referencePoint = ",referencePoint);
        // console.log("referencePointY = ",referencePoint.y.toString(16));
        return resPoint;
    }

    makeSecret(bytes = 48): bigint{
        var array = new Uint8Array(bytes);
        window.crypto.getRandomValues(array);

        let output = '0x';
        for (var i = 0; i < array.length; i++) {
            output += array[i].toString(16);
        }
        return mod(BigInt(output));
    }
    constructProof(identity: string, type: string, secret: bigint){
        const hashedIdentity: Point = this.hashIdentifier(type, identity);
        // console.log(`hashedIdentity = (${hashedIdentity.x}, ${hashedIdentity.y})`);
        const identifier = hashedIdentity.multiplyDA(secret);
        return this.computeProof(hashedIdentity, identifier, secret);
    }

    computeProof(base: Point, riddle: Point, exponent: bigint){
        let r: bigint = this.makeSecret();
        let t: Point = base.multiplyDA(r);
        // TODO ideally Bob's ethreum address should also be part of the challenge
        let c: bigint = mod(this.mapToIntegerFromUint8(this.makeArray([base, riddle, t])), CURVE_BN256.n);
        let d: bigint = mod(r + c * exponent);
        return  new ProofOfExponent(base, riddle, t, d);
    }
    makeArray(pointArray: Point[]): Uint8Array{
        let output: Uint8Array = new Uint8Array(0);
        pointArray.forEach( (item:Point) => {
            // console.log('Point.getEncoded');
            // console.log(item.getEncoded(false));
            output = new Uint8Array([ ...output, ...item.getEncoded(false)]);
        })
        return output;
    }
    verifyProof(pok: ProofOfExponent)  {
        let c = mod(this.mapToIntegerFromUint8(this.makeArray([pok.getBase(), pok.getRiddle(), pok.getPoint()])), CURVE_BN256.n);
        // console.log(`pok.getChallenge = ( ${pok.getChallenge()} )`);
        // console.log(`c = ( ${c} )`);
        let lhs: Point = pok.getBase().multiplyDA(pok.getChallenge());
        let rhs: Point = pok.getRiddle().multiplyDA(c).add(pok.getPoint());
        console.log(`Point lhs = ( ${lhs.x} , ${lhs.y})`);
        console.log(`Point rhs = ( ${rhs.x} , ${rhs.y})`);
        return lhs.equals(rhs);
    }
}
