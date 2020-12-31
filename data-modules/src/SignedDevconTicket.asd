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
                <element name="commitment" type="asnx:OCTET-STRING">
                  <annotation>The elliptic curve point that is a commitment to the ticket holder's identity</annotation>
                </element>
                <!-- The algorithm and public key are optional since they will normally be internally defined from devconId -->
                <optional>
                  <element name="publicKeyInfo" type="PublicKeyInfo"/>
                </optional>
                <element name="signatureValue" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="DevconTicket">
        <type>
            <sequence>
                <element name="devconId" type="asnx:INTEGER"/>
                <element name="ticketId" type="asnx:INTEGER"/>
                <element name="ticketClass" type="asnx:INTEGER"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="PublicKeyInfo">
      <type>
        <sequence>
          <element name="signatureAlgorithm" type="AlgorithmIdentifier"/>
          <element name="publicKey" type="asnx:BIT-STRING"/>
        </sequence>
      </type>
    </namedType>
</asnx:module>
