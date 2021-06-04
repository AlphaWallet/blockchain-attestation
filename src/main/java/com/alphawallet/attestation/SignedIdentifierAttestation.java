package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.io.InvalidObjectException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class SignedIdentifierAttestation implements ASNEncodable, Verifiable, Validateable {
  private static final Logger logger = LogManager.getLogger(SignedIdentifierAttestation.class);

  public static final AlgorithmIdentifier ECDSA_WITH_SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

  private final IdentifierAttestation att;
  private final byte[] signature;
  private final AsymmetricKeyParameter attestationVerificationKey;

  public SignedIdentifierAttestation(IdentifierAttestation att, AsymmetricCipherKeyPair attestationSigningKey) {
    this.att = att;
    this.signature = SignatureUtility.signWithEthereum(att.getPrehash(), attestationSigningKey.getPrivate());
    this.attestationVerificationKey = attestationSigningKey.getPublic();
    constructorCheck(attestationSigningKey.getPublic());
  }

  public SignedIdentifierAttestation(byte[] derEncoding, AsymmetricKeyParameter verificationKey) throws IOException {
    ASN1InputStream input = new ASN1InputStream(derEncoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
    // TODO ideally this should be refactored to SignedAttestation being augmented with an generic
    // Attestation type and an encoder to construct such an attestation
    this.att = new IdentifierAttestation(attestationEnc.getEncoded());
    DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(2));
    this.signature = signatureEnc.getBytes();
    this.attestationVerificationKey = verificationKey;
    if (!algorithmEncoded.equals(att.getSigningAlgorithm())) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Algorithm specified is not consistent"));
    }
    constructorCheck(verificationKey);
  }

  void constructorCheck(AsymmetricKeyParameter verificationKey) {
    if (!(verificationKey instanceof ECPublicKeyParameters)) {
      throw ExceptionUtil.throwException(logger,
          new UnsupportedOperationException("Attestations must be signed with ECDSA key"));
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is not valid"));
    }
  }

  public IdentifierAttestation getUnsignedAttestation() {
    return att;
  }

  public byte[] getSignature() {
    return signature;
  }

  /**
   * Returns the public key of the attestation signer
   */
  public AsymmetricKeyParameter getAttestationVerificationKey() { return attestationVerificationKey; }

  @Override
  public byte[] getDerEncoding() {
    return constructSignedAttestation(this.att, this.signature);
  }

  static byte[] constructSignedAttestation(Attestation unsignedAtt, byte[] signature) {
    try {
      byte[] rawAtt = unsignedAtt.getPrehash();
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawAtt));
      res.add(unsignedAtt.getSigningAlgorithm());
      res.add(new DERBitString(signature));
      return new DERSequence(res).getEncoded();
    } catch (Exception e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  @Override
  public boolean checkValidity() {
    return getUnsignedAttestation().checkValidity();
  }

  @Override
  public boolean verify() {
    try {
      if (!SignatureUtility.verifyEthereumSignature(att.getDerEncoding(), signature, attestationVerificationKey)) {
        logger.error("Could not verify signature");
        return false;
      }
    } catch (InvalidObjectException e) {
      logger.error("Could not decode the signature");
      return false;
    }
    return true;
  }

}