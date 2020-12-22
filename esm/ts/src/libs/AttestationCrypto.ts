import {ATTESTATION_TYPE} from "./interfaces";
import {Point, getPublicKey, CURVE} from "./Point";
import {mod, uint8merge, stringToArray, BnPowMod, uint8tohex} from "./utils";
import {ProofOfExponent } from "./ProofOfExponent";

let sha3 = require("js-sha3");

export class AttestationCrypto {
    rand: bigint;
    constructor() {
        this.rand = this.makeSecret();
        if (mod(CURVE.P,4n) != 3n) {
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
        return this.computePoint(idenNum);
    }
    // TODO change arr type
    mapToInteger(type: string, arr: Uint8Array ):bigint {
        // add prefix [0,0,0,1] for email type
        let prefix = [0,0,0,type === "mail" ? 0 : 1];
        return mod(BigInt('0x'+sha3.keccak384(uint8merge([Uint8Array.from(prefix),arr]))));
    }
    mapToIntegerFromUint8(arr: Uint8Array ):bigint {
        let idenNum = BigInt( '0x'+ sha3.keccak384(arr));
        return mod(idenNum);
    }
    /*
    computePoint_SECP256k1( x: bigint ): Point {
        x = mod ( x );
        let y = 0n, expected = 0n, ySquare = 0n;
        let resPoint,referencePoint: Point;
        let p = CURVE.P;
        let a = CURVE.A;
        let b = CURVE.B;
        do {
            do {
                x = mod(x + 1n);
                ySquare = mod(BnPowMod(x, 3n, p) + a * x + b);
                y = BnPowMod(ySquare, CURVE.magicExp, p);
                expected = mod(y * y);
            } while (expected !== ySquare);
            resPoint = new Point(x, y);
            // TODO add Point.negate() and use following logic
            // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
            if (resPoint.y > (p / 2n)) {
                resPoint = new Point(x, p - y);
            }
            referencePoint = resPoint.multiplyDA(CURVE.n - 1n);
            if (referencePoint.y > (p / 2n)) {
                referencePoint = new Point(referencePoint.x, p - referencePoint.y);
            }
        } while (!resPoint.equals(referencePoint))
        return resPoint;
    }
     */
    computePoint( x: bigint ): Point {
        x = mod ( x );
        let y = 0n, ySquare = 0n;
        let resPoint,referencePoint: Point;
        let quadraticResidue: bigint;
        let fieldSize = CURVE.P;
        let quadraticResidueExp = (fieldSize - 1n) >> 1n;
        do {
            do {
                x = mod(x + 1n);
                ySquare = mod(BnPowMod(x, 3n, fieldSize) + CURVE.A * x + CURVE.B);
                quadraticResidue = BnPowMod(ySquare, quadraticResidueExp, fieldSize);
            } while (quadraticResidue !== 1n);
            // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)
            y = BnPowMod(ySquare, CURVE.magicExp, fieldSize);
            resPoint = new Point(x, y);
            // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
            if (resPoint.x > (fieldSize >> 1n)) {
                resPoint = new Point(x, fieldSize - y);
            }
            referencePoint = resPoint.multiplyDA(CURVE.n - 1n);
            if (referencePoint.y > (fieldSize >> 1n) ) {
                referencePoint = new Point(referencePoint.x, fieldSize - referencePoint.y);
            }
            // Verify that the element is a member of the expected (subgroup) by ensuring that it has the right order, through Fermat's little theorem
            // NOTE: this is ONLY needed if we DON'T use secp256k1, so currently it is superflous but we are keeping it this check is crucial for security on most other curves!
        } while (!resPoint.equals(referencePoint) || resPoint.isInfinity())
        // console.log("resPoint = ",resPoint);
        // console.log("resPointY = ",resPoint.y.toString(16));
        // console.log("referencePoint = ",referencePoint);
        // console.log("referencePointY = ",referencePoint.y.toString(16));
        return resPoint;
    }
    // async genaratePrivateKey(): Promise<bigint> {
    //     // using subtlecrypto to generate a key. note that we are using an AES key
    //     // as an secp256k1 key here, since browsers don't support the latter;
    //     // that means all the keys must be created exportable to work with.
    //     const keyPair = await crypto.subtle.generateKey(
    //         {
    //             name: 'AES-GCM',
    //             length: 256
    //         },
    //         true,
    //         ['encrypt']
    //     );
    //     let hex = ['0x'];
    //     const exported = await crypto.subtle.exportKey('raw', keyPair);
    //     (new Uint8Array(exported)).forEach(i => {
    //         var h = i.toString(16);
    //         if (h.length % 2) { h = '0' + h; }
    //         hex.push(h);
    //     });
    //     // the next line works if AES key is always positive
    //     console.log(hex);
    //     return BigInt(hex.join('')) % CURVE.n;
    // }
    async createKeys(): Promise<{priv: bigint, pub: any}> {
        // let priv = await this.genaratePrivateKey();
        let priv = BigInt('0x'+uint8tohex(crypto.getRandomValues(new Uint8Array(32))) ) % CURVE.n;
        return {
            priv,
            pub: getPublicKey(priv)
        }
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
        const identifier = hashedIdentity.multiplyDA(secret);
        return this.computeProof(hashedIdentity, identifier, secret);
    }

    computeProof(base: Point, riddle: Point, exponent: bigint){
        let r: bigint = this.makeSecret();
        let t: Point = base.multiplyDA(r);
        // TODO ideally Bob's ethreum address should also be part of the challenge
        let c: bigint = mod(this.mapToIntegerFromUint8(this.makeArray([base, riddle, t])), CURVE.n);
        let d: bigint = mod(r + c * exponent);
        return  new ProofOfExponent(base, riddle, t, d);
    }
    makeArray(pointArray: Point[]): Uint8Array{
        let output: Uint8Array = new Uint8Array(0);
        pointArray.forEach( (item:Point) => {
            output = new Uint8Array([ ...output, ...item.getEncoded(false)]);
        })
        return output;
    }
    verifyProof(pok: ProofOfExponent)  {
        // let c = mod(this.mapToIntegerFromUint8(this.makeArray([pok.getBase(), pok.getRiddle(), pok.getPoint()]));
        // ECPoint lhs = pok.getBase().multiply(pok.getChallenge());
        // ECPoint rhs = pok.getRiddle().multiply(c).add(pok.getPoint());
        // return lhs.equals(rhs);
    }
}
