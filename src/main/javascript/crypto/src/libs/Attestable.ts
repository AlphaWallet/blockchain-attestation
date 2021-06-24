import {ASNEncodable} from "./ASNEncodable";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";

export interface Attestable extends ASNEncodable,Verifiable, Validateable {
    getCommitment(): Uint8Array ;
}
