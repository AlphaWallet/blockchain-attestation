import {stringToHex, hexStringToArray, base64ToUint8array} from "./utils";

const Asn1DerTagByType: {[index: string]:number} = {
    END_OF_CONTENT: 0,
    BOOLEAN: 1,
    INTEGER: 2,
    BIT_STRING: 3,
    OCTET_STRING: 4,
    NULL_VALUE: 5,
    OBJECT_ID: 6,
    OBJECT_DESCRIPTOR: 7,
    EXTERNAL: 8,
    REAL: 9,
    ENUMERATED: 10,
    EMBEDDED_PDV: 11,
    UTF8STRING: 12,
    RELATIVE_OID: 13,
    //reserved: 14,
    //reserved: 15,
    SEQUENCE_10: 16, // SEQUENCE и SEQUENCE OF
    SET_OF: 17, // SET и SET OF
    NUMERABLE_STRING: 18,
    PRINTABLE_STRING: 19,
    T61STRING: 20,
    VIDEO_TEX_STRING: 21,
    IA5STRING: 22,
    UTC_TIME: 23,
    GENERALIZED_TIME: 24,
    // SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", DateUtil.EN_Locale);
    // dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
    // time = Strings.toByteArray(dateF.format(time));
    GRAPHIC_STRING: 25,
    VISIBLE_STRING: 26,
    GENERAL_STRING: 27,
    UNIVERSAL_STRING: 28,
    CHARACTER_STRING: 29,
    BMP_STRING: 30,
    //long_form: 31,
    SEQUENCE_30: 48,
    SET: 49
}
const Asn1DerTagById: {[index: number]:string} = {
    0: "END_OF_CONTENT",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT_STRING",
    4: "OCTET_STRING",
    5: "NULL_VALUE",
    6: "OBJECT_ID",
    7: "OBJECT_DESCRIPTOR",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED_PDV",
    12: "UTF8STRING",
    13: "RELATIVE_OID",
    16: "SEQUENCE_10",
    19: "PRINTABLE_STRING",
    22: "IA5STRING",
    24: "GENERALIZED_TIME",
    26: "VISIBLE_STRING",
    48: "SEQUENCE_30",
    49: "SET",
}

export class Asn1Der {
    static encodeAsInteger(value: bigint) {
        return this.encode('INTEGER', value);
    }
    // static encodeAsInteger(value: bigint) {
    //     return this.encode('INTEGER', value);
    // }

    static encode(type: string, value: any) {
        let encType: number = Asn1DerTagByType[type];
        let encValue = '';
        switch (type) {
            case 'GENERALIZED_TIME':
            case "VISIBLE_STRING":
                encValue = stringToHex(value);
                break;
            case 'INTEGER':
                encValue = BigInt(value).toString(16);
                encValue = (encValue.length % 2 ? '0' : '') + encValue;
                if (parseInt('0x'+encValue.slice(0,1), 16) > 7) {
                    encValue = '00' + encValue;
                }
                break;
            case "SEQUENCE_30":
            case "OCTET_STRING":
                encValue = value;
                break;
            case "BIT_STRING":
                encValue = '00' + value;
                break;
        }

        // TODO maybe worth it to code indefinite form
        // 8.1.3.6	For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5), and shall consist of a single octet.
        // 8.1.3.6.1	The single octet shall have bit 8 set to one, and bits 7 to 1 set to zero.
        // 8.1.3.6.2	If this form of length is used, then end-of-contents octets (see 8.1.5) shall be present in the encoding following the contents octets.

        let encLength = '';
        let dataLength: number = Math.ceil(encValue.length / 2);

        let dataLengthHex = dataLength.toString(16);
        dataLengthHex = (dataLengthHex.length % 2 ? '0' : '') + dataLengthHex;

        if (dataLength < 128) {
            encLength = dataLengthHex;
        } else {
            encLength = (128 + Math.round(dataLengthHex.length / 2)).toString(16) + dataLengthHex;
        }
        encValue = (encValue.length % 2 ? '0' : '') + encValue;

        return encType.toString(16).padStart(2, '0') + encLength + encValue;
    }

    decode(byteArray: Uint8Array) {
        let arr = Array.from(byteArray);
        return this.read(arr);
    }

    lenEncoded(derArr: number[]) {
        let b1 = derArr.shift();
        if (b1 < 128) {
            return b1;
        } else if (b1 > 128){
            let extLength = 0;
            for (let i=0; i<(b1-128);i++){
                extLength = (extLength << 8) + derArr.shift();
            }
            return extLength;
        } else if (b1 == 128) {
            // TODO
            throw new Error('have to code variable length')
        }
    }

    readFromHexString(str: string) {
        return this.read(hexStringToArray(str));
    }

    readFromUint8Array(u8: Uint8Array) {
        return this.read(Array.from(u8));
    }

    readFromBase64String(base64str: string) {
        return this.readFromUint8Array(base64ToUint8array(base64str));
    }

    readFromUrlBase64String(urlBase64str: string) {
        let base64str = urlBase64str
            .split('_').join('-')
            .split('/').join('+')
            .split('.').join('=');
            // .replace('.','');
        return this.readFromBase64String(base64str);
    }

    read(derArr: number[]) {
        let typeTag:number = derArr.shift();
        let len:number = this.lenEncoded(derArr);
        let typeTagName:string = Asn1DerTagById[typeTag];
        // console.log(typeTagName);
        let content: number[] = [];

        for (let i = 0; i < len; i++){
            content.push(derArr.shift());
        }
        // console.log(content);
        let outputStr = '';
        switch (typeTagName) {
            case "SEQUENCE_30":
                return this.BodySequence(content);
            case "INTEGER":
            case "BIT_STRING":
                let output = 0n;
                while (content.length) {
                    output = output << 8n;
                    output += BigInt(content.shift());
                }
                return output;
            case "OCTET_STRING":
                while (content.length) {
                    outputStr += content.shift().toString(16).padStart(2,'0');
                }
                return outputStr;
            case "GENERALIZED_TIME":
            case "VISIBLE_STRING":
                while (content.length) {
                    outputStr += String.fromCharCode(content.shift());
                }
                return outputStr;
        }
    }

    BodySequence(derArr: number[]): any {
        let entries = [];
        while (derArr.length) {
            entries.push(this.read(derArr));
        }
        return entries;
    }


    // var BodyUtf8string = Asn1Der.BodyUtf8string = (function() {
    //     function BodyUtf8string(_io, _parent, _root) {
    //         this._read();
    //     }
    //     BodyUtf8string.prototype._read = function() {
    //         this.str = KaitaiStream.bytesToStr(this._io.readBytesFull(), "UTF-8");
    //     }
    //     return BodyUtf8string;
    // })();

    /**
     * @see {@link https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-object-identifier|Source}
     */

    // var BodyObjectId = Asn1Der.BodyObjectId = (function() {
    //     function BodyObjectId(_io, _parent, _root) {
    //         this._read();
    //     }
    //     BodyObjectId.prototype._read = function() {
    //         this.firstAndSecond = this._io.readU1();
    //         this.rest = this._io.readBytesFull();
    //     }
    //     Object.defineProperty(BodyObjectId.prototype, 'first', {
    //         get: function() {
    //             if (this._m_first !== undefined)
    //                 return this._m_first;
    //             this._m_first = Math.floor(this.firstAndSecond / 40);
    //             return this._m_first;
    //         }
    //     });
    //     Object.defineProperty(BodyObjectId.prototype, 'second', {
    //         get: function() {
    //             if (this._m_second !== undefined)
    //                 return this._m_second;
    //             this._m_second = KaitaiStream.mod(this.firstAndSecond, 40);
    //             return this._m_second;
    //         }
    //     });
    //
    //     return BodyObjectId;
    // })();



    // var BodyPrintableString = Asn1Der.BodyPrintableString = (function() {
    //     function BodyPrintableString(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodyPrintableString.prototype._read = function() {
    //         this.str = KaitaiStream.bytesToStr(this._io.readBytesFull(), "ASCII");
    //     }
    //
    //     return BodyPrintableString;
    // })();
}


