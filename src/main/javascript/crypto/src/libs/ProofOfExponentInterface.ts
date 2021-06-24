import {Point} from "./Point";

export interface ProofOfExponentInterface {
    getPoint(): Point;
    getChallenge(): bigint;
    getNonce(): Uint8Array;
    getDerEncoding(): string;
}
