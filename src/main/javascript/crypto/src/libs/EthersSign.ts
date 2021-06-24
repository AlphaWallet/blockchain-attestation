import { ethers } from "ethers";

export class EthersSign {
    constructor() {}

    static async signMessage(message: string){
        await window.ethereum.send('eth_requestAccounts');
        // let u = ethers.utils;
        let provider = new ethers.providers.Web3Provider(window.ethereum);
        let signer = provider.getSigner();
        // let ethAddress = await signer.getAddress();

        return await signer.signMessage(message);
    }

    static async signEip712(obj: any){
        await window.ethereum.send('eth_requestAccounts');
        // let u = ethers.utils;
        let provider = new ethers.providers.Web3Provider(window.ethereum);
        let signer = provider.getSigner();
        // let ethAddress = await signer.getAddress();

        // All properties on a domain are optional
        const domain = {
            name: 'Devcon Ticket',
            version: '1',
            chainId: 3,
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
            salt: "0x64656667646667657267657274796a74796a6231000000000000000000000000" // 32-byte value
        };

        // The named list of all type definitions
        const types = {
            // Person: [
            // { name: 'name', type: 'string' },
            // { name: 'wallet', type: 'address' }
            // ],
            Mail: [
                // { name: 'from', type: 'Person' },
                { name: 'attestor', type: 'string' },
                { name: 'contents', type: 'string' }
            ]
        };

        // The data to sign
        const value = {
            attestor: 'AlphaWallet attestaion',
            contents: 'MIGXMAkCAQYCAW8CAQAEQQQvZiRvuwETD_9d_eDp_4b0o0caeQ9FZ7e8hsxMi7SNsx-xkbfqtaNONRXQzQ1wO95bOVk3BRSdbQBNVLox62pCA0cAMEQCIFavePjptmgxBsVuHp7bZSDxK0ovB8d9URp2VjiGos56AiA9apKTL6Kk74Jgf2H7Mb4EZqlsdwJLXSN23sC6aoRyKg=='
        };

        const signature = await signer._signTypedData(domain, types, value);
        return signature;
    }
}
