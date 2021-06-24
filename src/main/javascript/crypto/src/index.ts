import {Authenticator} from "./Authenticator";
import {Eip712AttestationRequest} from "./libs/Eip712AttestationRequest";
import {AttestationCrypto} from "./libs/AttestationCrypto";

(window as any).Authenticator = Authenticator;
(window as any).Attest = Eip712AttestationRequest;
(window as any).AttestationCrypto = AttestationCrypto;

