import {CapabilityIssuer} from "./CapabilityIssuer";

const jwt = require('jsonwebtoken');
/**
 * Verified a long-term JWT that has been issued to a specific domain in order to give it access to the DevCon ticket API.
 *
 * This is specifically going to be used to allow a third party site to open an iframe to ticket.devcon
 * in order to access the ticket secret stored in the local cache to construct a useDevconTicket request.
 */
export class CapabilityValidator {
    private jwtData: any = {};

    constructor (private verifyingKey: string, private verifierDomain: string) {
        // let verification = jwt.require(getAlgorithm(this.verifyingKey, null))
        this.jwtData['audience'] = verifierDomain;
        this.jwtData['issuer'] = verifierDomain;
    }

    validateRequest(jsonInput: string, domain: string, tasksThatMustBePresent: string[]) {
        try {
            // Note that we already have added Audience, Issuer and that time validity and signature are
            // always verified implicitly.
            jwt.verify(jsonInput, this.verifyingKey, Object.assign(this.jwtData,{
                // https://github.com/auth0/node-jsonwebtoken
                //     algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
                // audience: if you want to check audience (aud), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions.
                //     Eg: "urn:foo", /urn:f[o]{2}/, [/urn:f[o]{2}/, "urn:bar"]
                //
                // complete: return an object with the decoded { payload, header, signature } instead of only the usual content of the payload.
                // issuer (optional): string or array of strings of valid values for the iss field.
                // jwtid (optional): if you want to check JWT ID (jti), provide a string value here.
                //     ignoreExpiration: if true do not validate the expiration of the token.
                //     ignoreNotBefore...
                // subject: if you want to check subject (sub), provide a value here
                // clockTolerance: number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers
                // maxAge: the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span zeit/ms.
                //     Eg: 1000, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
                //
                // clockTimestamp: the time in seconds that should be used as the current time for all necessary comparisons.
                //     nonce: if you want to check nonce claim, provide a string value here. It is used on Open ID for the ID Tokens.
                subject: 'domain',
                issuer: 'urn:issuer'

            }), (err:any, decoded:any) => {
                // if issuer mismatch, err == invalid issuer
                return this.verifyTasks(decoded, tasksThatMustBePresent);
            });

            return false;

        } catch (e) {
            return false;
        }
    }

    verifyTasks(jwt: any, tasksThatMustBePresent: string[]) {
        let tasksString: string = jwt[CapabilityIssuer.TasksClaimName];
        let tasksInJwt: string[] = tasksString.split(",");
        return tasksThatMustBePresent.filter(task => !tasksInJwt.includes(task)).length == 0;
    }
}
