package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class AttestedObject<T extends Attestable> implements ASNEncodable, Verifiable {
  private final T attestableObject;
  private final SignedAttestation att;
  private final ProofOfExponent pok;
  private final byte[] signature;

  private final AsymmetricKeyParameter userPublicKey;

  private final byte[] unsignedEncoding;
  private final byte[] encoding;

  public AttestedObject(T attestableObject, SignedAttestation att, AsymmetricCipherKeyPair userKeys,
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
      this.signature = SignatureUtility.signDeterministic(this.unsignedEncoding, userKeys.getPrivate());
      vec.add(new DERBitString(this.signature));
      this.encoding = new DERSequence(vec).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("The redeem request is not valid");
    }
  }

  public AttestedObject(T object, SignedAttestation att, ProofOfExponent pok, byte[] signature, AsymmetricKeyParameter publicAttestationSigningKey, AsymmetricKeyParameter userPublicKey) {
    this.attestableObject = object;
    this.att = att;
    this.userPublicKey = userPublicKey;
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
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("The redeem request is not valid");
    }
  }

  public AttestedObject(byte[] derEncoding, AttestableObjectDecoder<T> decoder, AsymmetricKeyParameter publicAttestationSigningKey, AsymmetricKeyParameter userPublicKey) {
    this.encoding = derEncoding;
    this.userPublicKey = userPublicKey;
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      this.attestableObject = decoder.decode(asn1.getObjectAt(0).toASN1Primitive().getEncoded());
      this.att = new SignedAttestation(asn1.getObjectAt(1).toASN1Primitive().getEncoded(), publicAttestationSigningKey);
      this.pok = new ProofOfExponent(asn1.getObjectAt(2).toASN1Primitive().getEncoded());
      this.unsignedEncoding = new DERSequence(Arrays.copyOfRange(asn1.toArray(), 0, 3)).getEncoded();
      this.signature = DERBitString.getInstance(asn1.getObjectAt(3)).getBytes();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("The redeem request is not valid");
    }
  }

  public T getAttestableObject() {
    return attestableObject;
  }

  public SignedAttestation getAtt() {
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
    // CHECK: that it is an identity attestation otherwise not all the checks of validity needed gets carried out
    try {
      byte[] attEncoded = att.getUnsignedAttestation().getDerEncoding();
      IdentifierAttestation std = new IdentifierAttestation(attEncoded);
      // CHECK: perform the needed checks of an identity attestation
      if (!std.checkValidity()) {
        System.err.println("The attestation is not a valid standard attestation");
        return false;
      }
    } catch (InvalidObjectException e) {
      System.err.println("The attestation is invalid");
      return false;
    } catch (IOException e) {
      System.err.println("The attestation could not be parsed as a standard attestation");
      return false;
    }

    // CHECK: that the cheque is still valid
    if (!getAttestableObject().checkValidity()) {
      System.err.println("Cheque is not valid");
      return false;
    }

    // CHECK: verify signature on RedeemCheque is from the same party that holds the attestation
    SubjectPublicKeyInfo spki = getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
    try {
      AsymmetricKeyParameter parsedSubjectKey = PublicKeyFactory.createKey(spki);
      if (!SignatureUtility.verify(this.unsignedEncoding, getSignature(), parsedSubjectKey)) {
        System.err.println("The signature on RedeemCheque is not valid");
        return false;
      }
    } catch (IOException e) {
      System.err.println("The attestation SubjectPublicKey cannot be parsed");
      return false;
    }

    // CHECK: the Ethereum address on the attestation matches receivers signing key
    // TODO
    return true;
  }

  @Override
  public boolean verify() {
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    ASN1Sequence extensions = DERSequence.getInstance(att.getUnsignedAttestation().getExtensions().getObjectAt(0));
    // Index in the second DER sequence is 2 since the third object in an extension is the actual value
    byte[] attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
    return attestableObject.verify() && att.verify() && AttestationCrypto.verifyEqualityProof(attCom, attestableObject.getCommitment(), pok) && SignatureUtility.verify(unsignedEncoding, signature, userPublicKey);
  }

  private ProofOfExponent makeProof(BigInteger attestationSecret, BigInteger objectSecret, AttestationCrypto crypto) {
    // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    ASN1Sequence extensions = DERSequence.getInstance(att.getUnsignedAttestation().getExtensions().getObjectAt(0));
    // Index in the second DER sequence is 2 since the third object in an extension is the actual value
    byte[] attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
    ProofOfExponent pok = crypto.computeEqualityProof(attCom, attestableObject.getCommitment(), attestationSecret, objectSecret);
    if (!crypto.verifyEqualityProof(attCom, attestableObject.getCommitment(), pok)) {
      throw new RuntimeException("The redeem proof did not verify");
    }
    return pok;
  }

  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

  // TODO override equals and hashcode
}
