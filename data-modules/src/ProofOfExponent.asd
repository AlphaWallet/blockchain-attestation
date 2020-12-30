<?xml version="1.0" encoding="UTF-8"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx" name="ProofOfExponent">
  <namedType name="Proof">
    <type>
      <sequence>
        <element name="base" type="asnx:OCTET-STRING">
          <annotation>The generator</annotation>
        </element>
        <element name="riddle" type="asnx:OCTET-STRING">
          <annotation>The value of which to prove knowledge its discrete logarithm</annotation>
        </element>
        <element name="challengePoint" type="asnx:OCTET-STRING">
          <annotation>The random challenge which is the hash digest of the parameters</annotation>
        </element>
        <element name="responseValue" type="asnx:OCTET-STRING">
          <annotation>The response to the challenge based on the secret exponent</annotation>
        </element>
      </sequence>
    </type>
  </namedType>
</asnx:module>
