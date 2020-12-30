<?xml version="1.0" encoding="UTF-8"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx" name="AttestationRequest">
  <import name="SubjectPublicKeyInfo" schemaLocation="AttestationFramework.asd"/>
  <import name="Proof" schemaLocation="ProofOfExponent.asd"/>

  <namedType name="Identity">
    <type>
      <sequence>
        <element name="unsignedIdentity" type="UnsignedIdentity">
          <annotation>The user's identity.</annotation>
        </element>
        <element name="subjectPublicKeyInfo" type="SubjectPublicKeyInfo">
          <annotation>The information about the user's Ethereum key that is supposed to be attested and used to sign this request</annotation>
        </element>
        <element name="signatureValue" type="asnx:BIT-STRING">
          <annotation>A signature on this request by the user's Ethereum key</annotation>
        </element>
      </sequence>
    </type>
  </namedType>

  <namedType name="UnsignedIdentity">
    <type>
      <sequence>
        <element name="identifier" type="asnx:VisibleString">
          <annotation>The identity to be validated. Either an email address or a phone number</annotation>
        </element>
        <element name="type" type="IdentifierType">
          <annotation>Integer describing the type of identifier.</annotation>
        </element>
        <element name="proof" type="Proof">
          <annotation>A proof containing the user's chosen hiding for his certificate and a proof that this has been correctly constructed.</annotation>
        </element>
      </sequence>
    </type>
  </namedType>

  <namedType name="IdentifierType">
    <type>
      <namedNumberList>
        <namedNumber name="phone" number="0"/>
        <namedNumber name="email" number="1"/>
      </namedNumberList>
    </type>
  </namedType>
</asnx:module>
