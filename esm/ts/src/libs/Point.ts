import {mod, invert, bnToBuf, uint8merge, BnPowMod} from "./utils";

// curve SECP256k1
export let CURVE_SECP256k1 = {
    P: 2n ** 256n - 2n ** 32n - 977n,
    n: 2n ** 256n - 432420386565659656852420866394968145599n,
    magicExp: (2n ** 256n - 2n ** 32n - 977n + 1n) / 4n,
    A: 0n,
    B: 7n
};
// bn256
// export let CURVE_BN256 = {
//     P: 115792089237314936872688561244471742058375878355761205198700409522629664518163n,
//     n: 115792089237314936872688561244471742058035595988840268584488757999429535617037n,
//     magicExp: 115792089237314936872688561244471742058375878355761205198700409522629664518164n >> 2n,
//     A: 0n,
//     B: 3n,
//     h: 1n
// };
// Updated parameters #60
export let CURVE_BN256 = {
    P: 21888242871839275222246405745257275088696311157297823662689037894645226208583n,
    n: 21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    // magicExp: 115792089237314936872688561244471742058375878355761205198700409522629664518164n >> 2n,
    A: 0n,
    B: 3n,
    h: 1n
};

export class Point {
    //static ZERO = new Point(0n, 0n); // Point at infinity aka identity point aka zero
    constructor(public x: bigint, public y: bigint, private useCurve: {[index: string]:bigint} = CURVE_SECP256k1 ) {}

    // Adds point to itself. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    double(): Point {
        const X1 = this.x;
        const Y1 = this.y;
        const lam = mod(3n * X1 ** 2n * invert(2n * Y1, this.useCurve.P), this.useCurve.P);
        const X3 = mod(lam * lam - 2n * X1, this.useCurve.P);
        const Y3 = mod(lam * (X1 - X3) - Y1, this.useCurve.P);
        return new Point(X3, Y3, this.useCurve);
    }

    newZero(): Point{
        return new Point(0n, 0n, this.useCurve);
    }

    // Adds point to other point. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
    add(other: Point): Point {
        const [a, b] = [this, other];
        const [X1, Y1, X2, Y2] = [a.x, a.y, b.x, b.y];
        if (X1 === 0n || Y1 === 0n) return b;
        if (X2 === 0n || Y2 === 0n) return a;
        if (X1 === X2 && Y1 === Y2) return this.double();
        if (X1 === X2 && Y1 === -Y2) return this.newZero();
        const lam = mod((Y2 - Y1) * invert(X2 - X1, this.useCurve.P), this.useCurve.P);
        const X3 = mod(lam * lam - X1 - X2, this.useCurve.P);
        const Y3 = mod(lam * (X1 - X3) - Y1, this.useCurve.P);
        return new Point(X3, Y3, this.useCurve);
    }

    // Elliptic curve point multiplication with double-and-add algo.
    multiplyDA(n: bigint) {
        let p = this.newZero();
        let d: Point = this;
        while (n > 0n) {
            if (n & 1n) p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }

    isInfinity(): boolean{
        return this.x == null || this.y == null;
    }

    getEncoded(compressed = false): Uint8Array{
        if (this.isInfinity())
        {
            return new Uint8Array(0);
        }

        let X = bnToBuf(this.x);
        if (compressed) {
            return uint8merge([Uint8Array.from([2]),X]);
        }

        return uint8merge([Uint8Array.from([4]), X , bnToBuf(this.y)]);
    }

    equals(other: Point): boolean {
        if (null == other) {
            return false;
        }

        let i1 = this.isInfinity();
        let i2 = other.isInfinity();

        if (i1 || i2) {
            return (i1 && i2);
        }

        let p1 = this;
        let p2 = other;
        return (p1.x === p2.x) && (p1.y === p2.y);
    }

    static decodeFromHex(hex: string, useCurve: {[index: string]:bigint} = CURVE_SECP256k1){
        if (hex.length != 130) {
            throw new Error('only decompressed points allowed. 65 bytes.');
        }
        let p;
        let type = hex.slice(0,2);
        switch (type) {
            case '04':
                let X = BigInt('0x' + hex.slice(2,66));
                let Y = BigInt('0x' + hex.slice(66,130));
                // console.log(X,Y);
                p = new Point(X, Y, useCurve);
                break;
            default:
                throw new Error('only decompressed points allowed');
        }
        if (!p.validate()) {
            throw new Error(`Point not valid (${p.x},${p.y})`);
        }
        return p;
    }

    validate(): boolean{
        return (
            mod(this.y * this.y, this.useCurve.P)
            - mod(BnPowMod(this.x, 3n, this.useCurve.P) + this.x * this.useCurve.A + this.useCurve.B , this.useCurve.P) ) == 0n;
    }

    negate(): Point {
        return new Point(this.x, this.useCurve.P - this.y, this.useCurve);
    }

    subtract(anotherPoint: Point): Point {
        return  this.add(anotherPoint.negate());
    }
}
