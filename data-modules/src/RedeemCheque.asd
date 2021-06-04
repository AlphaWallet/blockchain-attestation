<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="RedeemCheque" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="MyAttestation"
         schemaLocation="AttestationFramework.asd"/>
    <import name="SignedCheque"
         schemaLocation="SignedCheque.asd"/>
    <import name="Proof"
         schemaLocation="ProofOfExponent.asd"/>
    <namedType name="RedeemCheque">
        <type>
            <sequence>
                <element name="signedCheque" type="SignedCheque">
                    <annotation>The actual, signed, cheque object</annotation>
                </element>
                <element name="attestation" type="MyAttestation">
                    <annotation>The X509v3 certificate that is the attestation to be used for redeeming</annotation>
                </element>
                <element name="proof" type="Proof">
                    <annotation>Schnorr proof of knowledge</annotation>
                </element>
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
    <namedType name="Proof">
        <type>
            <sequence>
                <element name="base" type="asnx:OCTET-STRING">
                    <annotation>The base used in the proof, i.e. the digest of the redeemers identifier</annotation>
                </element>
                <element name="riddle" type="asnx:OCTET-STRING">
                    <annotation>The elliptic curve point that is the riddle</annotation>
                </element>
                <element name="challengePoint" type="asnx:OCTET-STRING">
                    <annotation>The random point which the prover knows the DL of</annotation>
                </element>
                <element name="responseValue" type="asnx:OCTET-STRING">
                    <annotation>The response value in the proof</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
