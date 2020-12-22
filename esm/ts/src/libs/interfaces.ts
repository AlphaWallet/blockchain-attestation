import { Point } from "./Point";

export interface keyPair {
    priv: bigint,
    pub: Point,
}

export const ATTESTATION_TYPE: {[index: string]:number} = {
    phone: 0,
    mail: 1
}


