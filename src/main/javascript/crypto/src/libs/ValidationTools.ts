export class ValidationTools {
    static ADDRESS_LENGTH_IN_BYTES:number = 42;

    static validateTimestamp(timestamp: number, currentTime: number, timestampSlack: number) {
        if (timestamp > currentTime + timestampSlack) {
            return false;
        }
        if (timestamp < currentTime - timestampSlack) {
            return false;
        }
        return true;
    }

    static isAddress(address: string): boolean {
        if (address.toLowerCase().match(/^0x[a-f0-9]{40}$/i) === null) {
            console.log('Wrong Ethereum Address');
            return false;
        }
        return true;
    }

    static isNullOrAddress(address: string): boolean {
        if (address == null) {
            return true;
        }
        return this.isAddress(address);
    }
}
