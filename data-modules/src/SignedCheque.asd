<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedCheque" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
<import name="ValidityValue"
         schemaLocation="AuthenticationFramework.asd"/>
    <namedType name="SignedCheque">
        <type>
            <sequence>
                <element name="cheque" type="Cheque">
                    <annotation>The actual, unsigned, cheque object</annotation>
                </element>
                <element name="publicKey" type="asnx:BIT-STRING"/>
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
    <namedType name="Cheque">
        <type>
            <sequence>
                <element name="amount" type="asnx:INTEGER"/>
                <element name="validity" type="ValidityValue"/>
                <element name="commitment" type="asnx:OCTET-STRING">
                    <annotation>The elliptic curve point that is the commitment to the user's identifier</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
