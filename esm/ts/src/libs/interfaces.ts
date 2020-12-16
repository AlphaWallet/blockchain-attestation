import { Point } from "./Point";

export interface keyPair {
    priv: bigint,
    pub: Point,
}

export const ATTESTATION_TYPE: {[index: string]:number} = {
    phone: 0,
    mail: 1
}

export const CURVE = {
    P: 2n ** 256n - 2n ** 32n - 977n,
    n: 2n ** 256n - 432420386565659656852420866394968145599n,
    magicExp: (2n ** 256n - 2n ** 32n - 977n + 1n) / 4n,
    A: 0n,
    B: 7n
};
