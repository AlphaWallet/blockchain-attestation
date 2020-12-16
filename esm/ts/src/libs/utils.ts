import {CURVE} from "./interfaces";

export function stringToHex(str: string) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}

export function mod(a: bigint, b: bigint = CURVE.P): bigint {
    const result = a % b;
    return result >= 0 ? result : b + result;
}

export function invert(number: bigint, modulo: bigint = CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('invert: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('invert: does not exist');
    }
    return mod(x, modulo);
}

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
export function egcd(a: bigint, b: bigint) {
    let [x, y, u, v] = [0n, 1n, 1n, 0n];
    while (a !== 0n) {
        let [q, r] = [b / a, b % a];
        let [m, n] = [x - u * q, y - v * q];
        [b, a] = [a, r];
        [x, y] = [u, v];
        [u, v] = [m, n];
    }
    return [b, x, y];
}

export function bufToBn(buf: Uint8Array) {
    let hex: string[] = [];
    let u8 = Uint8Array.from(buf);

    u8.forEach(function (i) {
        var h = i.toString(16);
        if (h.length % 2) { h = '0' + h; }
        hex.push(h);
    });

    return BigInt('0x' + hex.join(''));
}

export function bnToBuf(bn: bigint): Uint8Array {
    var hex = BigInt(bn).toString(16);
    if (hex.length % 2) { hex = '0' + hex; }

    var len = hex.length / 2;
    var u8 = new Uint8Array(len);

    var i = 0;
    var j = 0;
    while (i < len) {
        u8[i] = parseInt(hex.slice(j, j+2), 16);
        i += 1;
        j += 2;
    }

    return u8;
}

export function uint8merge(list : Uint8Array[]): Uint8Array{
    if (list.length === 1) return list[0];

    let out = Uint8Array.from([]);
    if (list.length === 0) return out;

    for (let i = 0; i< list.length; i++){
        let temp = new Uint8Array(out.length + list[i].length);
        temp.set(out);
        temp.set(list[i], out.length);
        out = temp;
    }
    return out;
}
