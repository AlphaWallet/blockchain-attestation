<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedTicket" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
<import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>
    <namedType name="SignedDevconTicket">
        <type>
            <sequence>
                <element name="ticket" type="DevconTicket">
                    <annotation>The actual, unsigned, ticket object</annotation>
                </element>
                <element name="signatureAlgorithm" type="AlgorithmIdentifier"/>
                <element name="signatureValue" type="asnx:BIT-STRING">
                </element>
            </sequence>
        </type>
    </namedType>
    <namedType name="DevconTicket">
        <type>
            <sequence>
                <element name="devconId" type="asnx:INTEGER"/>
                <element name="ticketId" type="asnx:INTEGER"/>
                <element name="ticketClass" type="asnx:INTEGER"/>
                <element name="riddle" type="asnx:OCTET-STRING">
                    <annotation>The elliptic curve point that is the riddle</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
