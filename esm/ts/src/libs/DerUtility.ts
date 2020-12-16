import { stringToHex } from "./utils";

export class DERUtility {
    static restoreBase64Keys(der: string){

    }
}

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
const Asn1DerTagById = {
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
    48: "SEQUENCE_30",
    49: "SET",
}

export class Asn1Der {
    static encode(type: string, value: any) {
        let encType: number = Asn1DerTagByType[type];
        let encValue = '';
        switch (type) {
            case 'GENERALIZED_TIME':
            case "VISIBLE_STRING":
                encValue = stringToHex(value);
                break;
            case 'INTEGER':
                encValue = parseInt(value).toString(16);
                encValue = (encValue.length % 2 ? '0' : '') + encValue;
                break;
            case "SEQUENCE_30":
            case "OCTET_STRING":
            case "BIT_STRING":
                encValue = value;
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

    // function Asn1Der(byteArray, _parent, _root) {
    // decode(byteArray) {
    //     this._io = byteArray;
    //     // this._parent = _parent;
    //     // this._root = _root || this;
    //     this._read();
    // }
    // _read() {
    //     // this.typeTag = this._io.readU1();
    //     this.typeTag = this._io.shift();
    //     this.len = new LenEncoded(this._io, this, this._root);
    //     switch (this.typeTag) {
    //         /*
    //         case Asn1Der.TypeTag.PRINTABLE_STRING:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodyPrintableString(_io__raw_body, this, this._root);
    //             break;
    //         case Asn1Der.TypeTag.SEQUENCE_10:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodySequence(_io__raw_body, this, this._root);
    //             break;
    //         case Asn1Der.TypeTag.SET:
    //             this._raw_body = this._io.readBytes(this.len.result);
    //             var _io__raw_body = new KaitaiStream(this._raw_body);
    //             this.body = new BodySequence(_io__raw_body, this, this._root);
    //             break;
    //
    //          */
    //         case Asn1Der.TypeTag.SEQUENCE_30:
    //             this._raw_body = this._io.splice(0,this.len.result);
    //             // var _io__raw_body = new KaitaiStream(this._raw_body);
    //             // this.body = new BodySequence(_io__raw_body, this, this._root);
    //             this.body = (new BodySequence(this._raw_body)).entries;
    //             break;
    //         /*
    //     case Asn1Der.TypeTag.UTF8STRING:
    //         this._raw_body = this._io.readBytes(this.len.result);
    //         var _io__raw_body = new KaitaiStream(this._raw_body);
    //         this.body = new BodyUtf8string(_io__raw_body, this, this._root);
    //         break;
    //     case Asn1Der.TypeTag.OBJECT_ID:
    //         this._raw_body = this._io.readBytes(this.len.result);
    //         var _io__raw_body = new KaitaiStream(this._raw_body);
    //         this.body = new BodyObjectId(_io__raw_body, this, this._root);
    //         break;
    //
    //          */
    //         default:
    //             this.body = this._io.splice(0,this.len.result);
    //             break;
    //     }
    //     console.log(this.body);
    // }

    // var BodySequence = Asn1Der.BodySequence = (function() {
    //     // function BodySequence(_io, _parent, _root) {
    //     function BodySequence(_io) {
    //         this._io = _io;
    //         // this._parent = _parent;
    //         // this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodySequence.prototype._read = function() {
    //         this.entries = [];
    //         var i = 0;
    //         while (this._io.length) {
    //             this.entries.push( (new Asn1Der(this._io)).body );
    //             i++;
    //         }
    //     }
    //
    //     return BodySequence;
    // })();

    // var BodyUtf8string = Asn1Der.BodyUtf8string = (function() {
    //     function BodyUtf8string(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     BodyUtf8string.prototype._read = function() {
    //         this.str = KaitaiStream.bytesToStr(this._io.readBytesFull(), "UTF-8");
    //     }
    //
    //     return BodyUtf8string;
    // })();

    /**
     * @see {@link https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-object-identifier|Source}
     */

    // var BodyObjectId = Asn1Der.BodyObjectId = (function() {
    //     function BodyObjectId(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
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

    // var LenEncoded = Asn1Der.LenEncoded = (function() {
    //     function LenEncoded(_io, _parent, _root) {
    //         this._io = _io;
    //         this._parent = _parent;
    //         this._root = _root || this;
    //
    //         this._read();
    //     }
    //     LenEncoded.prototype._read = function() {
    //         this.b1 = this._io.shift();
    //         if (this.b1 == 130) {
    //             let bite1 = this._io.shift();
    //             let bite2 = this._io.shift();
    //             this.int2 = bite1 << 8 + bite2;
    //         }
    //         if (this.b1 == 129) {
    //             this.int1 = this._io.shift();
    //         }
    //     }
    //     Object.defineProperty(LenEncoded.prototype, 'result', {
    //         get: function() {
    //             if (this._m_result !== undefined)
    //                 return this._m_result;
    //             this._m_result = (this.b1 == 129 ? this.int1 : (this.b1 == 130 ? this.int2 : this.b1));
    //             return this._m_result;
    //         }
    //     });
    //
    //     return LenEncoded;
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


