import {hexStringToArray, hexStringToUint8} from "./utils";
import {KeyPair} from "./KeyPair";
import {ethers} from "ethers";
import {_TypedDataEncoder, recoverPublicKey} from "ethers/lib/utils";


let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

let sha3 = require("js-sha3");

export interface Eip712DomainInterface {
    name: string,
    version: string,
    chainId?: number,
    verifyingContract?: string,
    salt?: string
}

export class SignatureUtility {
    static OID_ECDSA_PUBLICKEY:string = "1.2.840.10045.2.1";
    // static Eip712Types: {[index: string]:string}  = {
    //     STRING: "string",
    //     BYTES32: "bytes32",
    //     UINT64: "uint64",
    //     UINT256: "uint256",
    //     ADDRESS: "address",
    // }

    static Eip712Data: {[index: string]:string}  = {
        PROTOCOL_VERSION: "0.1",
        // JSON_RPC_VER: "2.0",
    }

    static Eip712domainTypes = [
        {name: "name", type: "string"},
        {name: "version", type: "string"},
        // {name: "chainId", type: "uint256"},
        // {name: "verifyingContract", type: "address"},
        // {name: "salt", type: "bytes32"},
    ];

    static sign(str: string, keys: KeyPair):string {
        let ecKey = ec.keyFromPrivate(keys.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(str))
        let signature = ecKey.sign(encodingHash);
        return signature.toDER('hex');
    }

    static verify(str: string, signature: string, keys: KeyPair):boolean {
        return SignatureUtility.verifyArrayBuf(hexStringToArray(str), signature, keys);
    }

    static verifyArrayBuf(arr: ArrayBuffer|Uint8Array|number[], signature: string, keys: KeyPair):boolean {
        let ecKey = ec.keyFromPublic(keys.getPublicKeyAsHexStr(), 'hex');
        let encodingHash = sha3.keccak256(arr)
        return ecKey.verify(encodingHash, signature);
    }


    static async signMessageWithBrowserWallet(message: string){
        await SignatureUtility.connectMetamaskAndGetAddress();

        let provider = new ethers.providers.Web3Provider(window.ethereum);
        let signer = provider.getSigner();
        return await signer.signMessage(message);
    }

    static async recoverPublicKeyFromMessageSignature(message: string, signature: string){

        const msgHash = ethers.utils.hashMessage(message);
        const digest = ethers.utils.arrayify(msgHash);

        return await ethers.utils.recoverPublicKey(digest, signature)
    }

    /*
    recover public key in format 0x042f196ec33ad04c6... 132chars
     */
    static recoverPublicKeyFromTypedMessageSignature(messageObj: any, signature: string): string {

        // let rawPayload = messageObj.message.payload;
        // messageObj.message.payload = sha3.keccak256(rawPayload);

        // let completeData: { [index: string]: any } = {
        //     types: {
        //         EIP712Domain: SignatureUtility.Eip712domainTypes,
        //     },
        //     primaryType: primaryName,
        //     message: userDataValues,
        //     domain: domainData,
        // };

        let messageAsPrefixedHexString, pubKey;
        try {
            let rawPayload = messageObj.message.payload;
            // messageObj.message.payload = sha3.keccak256(rawPayload);
            // same result:
            messageObj.message.payload = ethers.utils.id(rawPayload).substr(2);

            // message = TypedDataUtils.sign(messageObj);
            // same result:
            let types = messageObj.types;
            delete types.EIP712Domain;
            messageAsPrefixedHexString = _TypedDataEncoder.hash(messageObj.domain,types,messageObj.message);

            messageObj.message.payload = rawPayload;
        } catch (e){
            const m = 'Cant sign data, possibly wrong format. ' + e
            throw new Error(m);
        }

        try {
            pubKey = recoverPublicKey(hexStringToUint8(messageAsPrefixedHexString.substr(2)), signature);
        } catch (e){
            const m = 'Cant recoverPublicKey. ' + e;
            throw new Error(m);
        }

        return pubKey;
    }

    static async signEIP712WithBrowserWallet(webDomain: string, userDataValues: {[index: string]:string|number}, userDataTypes: Array<{name: string,type: string}>, primaryName: string, userKey: KeyPair = null): Promise<string> {
        // How its encoded at metamask ...
        // All properties on a domain are optional
        // const domain = {
        //     name: 'Devcon Ticket',
        //     version: '1',
        //     chainId: 3,
        //     verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        //     salt: "0x64656667646667657267657274796a74796a6231000000000000000000000000" // 32-byte value
        // };
        // const data = JSON.stringify({
        //     types: {
        //         EIP712Domain: domain,
        //         Bid: bid,
        //         Identity: identity,
        //     },
        //     domain: domainData,
        //     primaryType: "Bid",
        //     message: message
        // });
        // web3.currentProvider.sendAsync(
        // {
        //     method: "eth_signTypedData_v3",
        //     params: [signer, data],
        //     from: signer
        // },

        try {
            let userAddress: string;
            let signer;

            if (userKey) {
                // it should be node.js lets use defined KeyPair
                signer = new ethers.Wallet('0x' + userKey.getPrivateAsHexString());
            } else {
                // it should be browser. use Metamask
                //userAddress = await SignatureUtility.connectMetamaskAndGetAddress();
                let provider = new ethers.providers.Web3Provider(window.ethereum);
                //let network = await provider.getNetwork();
                signer = provider.getSigner();
            }


            if (!signer) throw new Error("Active Wallet required");


            // let ethAddress = await signer.getAddress();

            let Eip712Data = SignatureUtility.Eip712Data;

            // All properties on a domain are optional
            const domainData = {
                // chainId: network.chainId,
                name: webDomain,
                // verifyingContract: userAddress,
                // salt: AttestationCrypto.generateRandomHexString(32), // 32-byte value
                version: Eip712Data['PROTOCOL_VERSION']
            };

            // The named list of all type definitions
            const dataTypes: { [index: string]: any } = {};
            dataTypes[primaryName] = userDataTypes;

            // hash payload string->hexString to make smaller message to sign
            let userDataValuesWithHashedPayload = Object.assign({}, userDataValues);
            userDataValuesWithHashedPayload.payload = sha3.keccak256(userDataValuesWithHashedPayload.payload);

            // this is internal logic, we can use it for debug

            // console.log('lets try to sign data directly');
            // const populated = await _TypedDataEncoder.resolveNames(domainData, dataTypes, userDataValues, (name: string) => {
            //     return window.ethereum.resolveName(name);
            // });
            // console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!');
            // console.log(domainData, dataTypes, userDataValues, populated);
            //
            // let typedMsg = _TypedDataEncoder.getPayload(populated.domain, dataTypes, populated.value);
            // let msgParams = JSON.stringify(typedMsg);
            // console.log('msgParams');
            // console.log(msgParams);

            // let directlySigned = await window.ethereum.send("eth_signTypedData_v4", [
            //      userAddresses[0].toLowerCase(), msgParams
            // ]);
            // let signatureD = directlySigned.result;

            // sign eip712 with custom key
            // let privateKey = "0x0123456789012345678901234567890123456789012345678901234567890123";
            // let wallet = new ethers.Wallet(privateKey);
            // let signature = await wallet._signTypedData(domainData, dataTypes, userDataValuesWithHashedPayload);
            // Connect a wallet to mainnet
            // let provider = ethers.getDefaultProvider();
            // let walletWithProvider = new ethers.Wallet(privateKey, provider);


            let signature = await signer._signTypedData(domainData, dataTypes, userDataValuesWithHashedPayload);

            let completeData: { [index: string]: any } = {
                types: {
                    EIP712Domain: SignatureUtility.Eip712domainTypes,
                },
                primaryType: primaryName,
                message: userDataValues,
                domain: domainData,
            };

            completeData.types[primaryName] = dataTypes[primaryName];

            let dataStringified = JSON.stringify(completeData);
            let externalAuthenticationData: { [index: string]: string | number } = {
                signatureInHex: signature,
                // jsonRpc: Eip712Data['JSON_RPC_VER'],
                // chainId: network.chainId,
                jsonSigned: dataStringified
            };
            return JSON.stringify(externalAuthenticationData);
        } catch (e){
            console.error('Cant sign eip712 data. Error: '+ e);
            return '';
        }
    }

    static async connectMetamaskAndGetAddress(): Promise<string>{

        if (!window.ethereum){
            throw new Error('Please install metamask before.');
        }

        // const userAddresses = await window.ethereum.request({ method: 'eth_accounts' });
        const userAddresses = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (!userAddresses || !userAddresses.length ){
            throw new Error("Active Wallet required");
        }

        return userAddresses[0];
    }

    static getChainIdFromSignature(signature: string):number {
        let recoveryByte: number = Number("0x" + signature.substr(-2));
        if (recoveryByte == 27 || recoveryByte == 28) {
            return 0;
        }
        // recovery byte is chainId * 2 + 35 for chainId >= 1
        return (recoveryByte - 35) >> 1;
    }


}
