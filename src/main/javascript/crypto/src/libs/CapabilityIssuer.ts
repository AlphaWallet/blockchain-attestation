import {KeyPair} from "./KeyPair";
import {getInt64Bytes, stringToArray, uint8arrayToBase64, uint8merge} from "./utils";
import {AttestationCrypto} from "./AttestationCrypto";
const jwt = require('jsonwebtoken');

export class CapabilityIssuer {
    private signingKeys: KeyPair;
    static TasksClaimName: string = "org.devcon.ticket.capability";
    // private verifierDomain: string;

    constructor (private privateKeyOrSecret: string, private verifierDomain: string) {}

    makeToken(domain: string, tasks: string[], expirationTimeInDays: number) {
        let flattenedTasks = this.flattenSet(tasks);
        let currentTime: number = Date.now();
        let expirationInMs = currentTime + expirationTimeInDays * 24 * 60 * 60 * 1000;
        return this.buildSignedToken(domain, flattenedTasks, expirationInMs, currentTime);
    }

    buildSignedToken(domain: string, flattenedTasks: string, expirationTimeInMs: number, creationTimeInMs: number) {
        // Only withAudience, withSubject, withIssuer, withExpiresAt, withNotBefore and withClaim(tasksClaimName) are required
        let jwtData: any = {
            aud: this.verifierDomain, //withAudience
            iss: this.verifierDomain, //withIssuer
            sub: domain, //withSubject
            nbf: new Date(creationTimeInMs).valueOf(), //withNotBefore
            exp: new Date(expirationTimeInMs).valueOf(), //withExpiresAt
            // withIssuedAt and withJWTId are OPTIONAL
            iat: new Date(creationTimeInMs).valueOf(), //withIssuedAt
            jti: this.getJWTID(domain, flattenedTasks, expirationTimeInMs, creationTimeInMs)

        };
        let jwtOptions = {
            //algorithm (default: HS256)
            //expiresIn: expressed in seconds or a string describing a time span zeit/ms.
            // Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").

            // notBefore: expressed in seconds or a string describing a time span zeit/ms.
            //     Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
            //
            // audience
            // issuer
            // jwtid
            // subject
            // noTimestamp
            // header
            // keyid
            // mutatePayload
        };

        jwtData[CapabilityIssuer.TasksClaimName] = flattenedTasks;
        // TODO set algorithm
        // jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256' }, function(err, token) {
        //     console.log(token);
        // });
        return jwt.sign(jwtData, this.privateKeyOrSecret, jwtOptions);
    }

    flattenSet(tasks: string[]): string {
        if (!tasks.length || tasks.length == 0) {
            throw new Error("At least one task must be assigned");
        }
        let flattenedList: string = '';
        tasks.forEach(task => {
            let normalizedTask: string = task.toLowerCase().trim();
            if (normalizedTask.includes(",")) {
                throw new Error("A task contains a ',' which is not permitted");
            }
            flattenedList += normalizedTask + ',';
        })

        // Remove trailing ','
        return flattenedList.slice(0,-1);
    }

    getJWTID(domain: string, flattenedTasks: string, expirationTime: number, currentTime: number): string {
        let toHash: Uint8Array = uint8merge([
            new Uint8Array(stringToArray(domain)),
            new Uint8Array(stringToArray(CapabilityIssuer.TasksClaimName)),
            new Uint8Array(stringToArray(flattenedTasks)),
            new Uint8Array(stringToArray(flattenedTasks)),
            getInt64Bytes(expirationTime),
            getInt64Bytes(currentTime)
            ]
        );

        let digest = AttestationCrypto.hashWithKeccak(toHash);
        return uint8arrayToBase64(digest);
    }
}
