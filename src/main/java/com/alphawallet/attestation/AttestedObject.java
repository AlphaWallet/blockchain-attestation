package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class AttestedObject<T extends Attestable> implements ASNEncodable, Verifiable {
  private static final Logger logger = LogManager.getLogger(AttestedObject.class);
  private final T attestableObject;
  private final SignedIdentifierAttestation att;
  private final ProofOfExponent pok;
  private final byte[] signature;

  private final AsymmetricKeyParameter userPublicKey;

  private final byte[] unsignedEncoding;
  private final byte[] encoding;

  public AttestedObject(T attestableObject, SignedIdentifierAttestation att, AsymmetricCipherKeyPair userKeys,
      BigInteger attestationSecret, BigInteger chequeSecret,
      AttestationCrypto crypto) {
    this.attestableObject = attestableObject;
    this.att = att;
    this.userPublicKey = userKeys.getPublic();

    try {
      this.pok = makeProof(attestationSecret, chequeSecret, crypto);
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(ASN1Sequence.getInstance(this.attestableObject.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(att.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
      this.unsignedEncoding = new DERSequence(vec).getEncoded();
      this.signature = SignatureUtility.signPersonalMsgWithEthereum(this.unsignedEncoding, userKeys.getPrivate());
      vec.add(new DERBitString(this.signature));
      this.encoding = new DERSequence(vec).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify object"));
    }
  }

  public AttestedObject(T object, SignedIdentifierAttestation att, ProofOfExponent pok, byte[] signature) {
    this.attestableObject = object;
    this.att = att;
    this.pok = pok;
    this.signature = signature;

    try {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(ASN1Sequence.getInstance(object.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(att.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
      this.unsignedEncoding = new DERSequence(vec).getEncoded();
      vec.add(new DERBitString(this.signature));
      this.encoding = new DERSequence(vec).getEncoded();
      this.userPublicKey = PublicKeyFactory.createKey(att.getUnsignedAttestation().getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify object"));
    }
  }

  public AttestedObject(byte[] derEncoding, AttestableObjectDecoder<T> decoder,
      AsymmetricKeyParameter attestationVerificationKey) {
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      this.attestableObject = decoder.decode(asn1.getObjectAt(0).toASN1Primitive().getEncoded());
      this.att = new SignedIdentifierAttestation(asn1.getObjectAt(1).toASN1Primitive().getEncoded(), attestationVerificationKey);
      this.pok = new UsageProofOfExponent(asn1.getObjectAt(2).toASN1Primitive().getEncoded());
      this.unsignedEncoding = new DERSequence(Arrays.copyOfRange(asn1.toArray(), 0, 3)).getEncoded();
      if (asn1.size() > 3) {
        this.signature = DERBitString.getInstance(asn1.getObjectAt(3)).getBytes();
        this.encoding = derEncoding;
      } else{
        this.signature = null;
        this.encoding = unsignedEncoding;
      }
      this.userPublicKey = PublicKeyFactory.createKey(att.getUnsignedAttestation().getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is not valid"));
    }
  }

  public T getAttestableObject() {
    return attestableObject;
  }

  public SignedIdentifierAttestation getAtt() {
    return att;
  }

  public ProofOfExponent getPok() {
    return pok;
  }

  public byte[] getSignature() {
    return signature;
  }

  public AsymmetricKeyParameter getUserPublicKey() {
    return userPublicKey;
  }

  /**
   * Verifies that the redeem request will be accepted by the smart contract
   * @return true if the redeem request should be accepted by the smart contract
   */
  public boolean checkValidity() {
    // CHECK: that it is an identifier attestation otherwise not all the checks of validity needed gets carried out
    try {
      byte[] attEncoded = att.getUnsignedAttestation().getDerEncoding();
      IdentifierAttestation std = new IdentifierAttestation(attEncoded);
      // CHECK: perform the needed checks of an identifier attestation
      if (!std.checkValidity()) {
        logger.error("The attestation is not a valid standard attestation");
        return false;
      }
    } catch (InvalidObjectException e) {
      logger.error("The attestation is invalid");
      return false;
    } catch (IOException e) {
      logger.error("The attestation could not be parsed as a standard attestation");
      return false;
    }

    // CHECK: that the cheque is still valid
    if (!getAttestableObject().checkValidity()) {
      logger.error("Cheque is not valid");
      return false;
    }

    // CHECK: the Ethereum address on the attestation matches receivers signing key
    String attestationEthereumAddress = getAtt().getUnsignedAttestation().getAddress();
    if (!attestationEthereumAddress.equals(SignatureUtility.addressFromKey(getUserPublicKey()))) {
      logger.error("The attestation is not to the same Ethereum user who is sending this request");
      return false;
    }

    // CHECK: verify signature on RedeemCheque is from the same party that holds the attestation
    if (signature != null) {
      SubjectPublicKeyInfo spki = getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
      try {
        AsymmetricKeyParameter parsedSubjectKey = PublicKeyFactory.createKey(spki);
        if (!SignatureUtility
            .verifyPersonalEthereumSignature(this.unsignedEncoding, this.signature, parsedSubjectKey)) {
          logger.error("The signature on RedeemCheque is not valid");
          return false;
        }
      } catch (IOException e) {
        logger.error("The attestation SubjectPublicKey cannot be parsed");
        return false;
      }
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!attestableObject.verify()) {
      logger.error("Could not verify attestable object");
      return false;
    }
    if (!att.verify()) {
      logger.error("Could not verify attestation");
      return false;
    }
    if (!AttestationCrypto.verifyEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), pok)) {
      logger.error("Could not verify the consistency between the commitment in the attestation and the attested object");
      return false;
    }
    if (signature != null) {
      if (!SignatureUtility.verifyPersonalEthereumSignature(unsignedEncoding, signature, userPublicKey)) {
        logger.error("Could not verify the signature");
        return false;
      }
    }
    return true;
  }

  private ProofOfExponent makeProof(BigInteger attestationSecret, BigInteger objectSecret, AttestationCrypto crypto) {
    // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
    // We require that the internal attestation is an IdentifierAttestation
    ProofOfExponent pok = crypto.computeEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), attestationSecret, objectSecret);
    if (!crypto.verifyEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), pok)) {
      throw ExceptionUtil.throwException(logger,
          new RuntimeException("The redeem proof did not verify"));
    }
    return pok;
  }

  public byte[] getDerEncodingWithSignature() { return encoding; }

  @Override
  public byte[] getDerEncoding() {
    return unsignedEncoding;
  }

  // TODO override equals and hashcode
}
