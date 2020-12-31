package com.alphawallet.attestation.cheque;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Cheque implements Attestable {
  private final byte[] commitment;
  private final long amount;
  private final long notValidBefore;
  private final long notValidAfter;
  private final AsymmetricKeyParameter publicKey;
  private final byte[] signature;

  private final byte[] encoded;

  /**
   *
   * @param identifier The identifier of the receiver
   * @param type The type of identifier given
   * @param amount Amount of units the cheque should be valid for
   * @param validity time from now which the cheque should be valid, in milliseconds
   * @param keys the keys used to sign the cheque
   * @param secret the secret that must be known to cash the cheque
   */
  public Cheque(String identifier, AttestationType type, long amount, long validity, AsymmetricCipherKeyPair keys, BigInteger secret) {
    this.commitment = AttestationCrypto.makeCommitment(identifier, type, secret);
    this.publicKey = keys.getPublic();
    this.amount = amount;
    long current =  System.currentTimeMillis();
    this.notValidBefore = current - (current % 1000); // Round down to nearest second
    this.notValidAfter = this.notValidBefore + validity;
    ASN1Sequence cheque = makeCheque(this.commitment, amount, notValidBefore, notValidAfter);
    try {
      this.signature = SignatureUtility.signDeterministic(cheque.getEncoded(), keys.getPrivate());
      this.encoded = encodeSignedCheque(cheque, this.signature, this.publicKey);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("Public and private keys are incorrect");
    }
  }

  public Cheque(byte[] commitment, long amount, long notValidBefore, long notValidAfter, byte[] signature, AsymmetricKeyParameter publicKey) {
    this.commitment = commitment;
    this.publicKey = publicKey;
    this.amount = amount;
    if (notValidBefore % 1000 != 0 || notValidAfter % 1000 != 0) {
      throw new IllegalArgumentException("Can only support time granularity to the second");
    }
    this.notValidBefore = notValidBefore;
    this.notValidAfter = notValidAfter;
    this.signature = signature;
    ASN1Sequence cheque = makeCheque(this.commitment, amount, notValidBefore, notValidAfter);
    try {
      this.encoded = encodeSignedCheque(cheque, this.signature, this.publicKey);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("Signature is invalid");
    }
  }

  private ASN1Sequence makeCheque(byte[] commitment, long amount, long notValidBefore, long notValidAfter) {
    ASN1EncodableVector cheque = new ASN1EncodableVector();
    cheque.add(new ASN1Integer(amount));

    ASN1GeneralizedTime notValidBeforeEnc = new ASN1GeneralizedTime(new Date(notValidBefore));
    ASN1GeneralizedTime notValidAfterEnc = new ASN1GeneralizedTime(new Date(notValidAfter));
    ASN1Sequence validityEnc = new DERSequence(new ASN1Encodable[] {notValidBeforeEnc, notValidAfterEnc});
    cheque.add(validityEnc);

    cheque.add(new DEROctetString(commitment));

    return new DERSequence(cheque);
  }

  private byte[] encodeSignedCheque(ASN1Sequence cheque, byte[] signature, AsymmetricKeyParameter publicKey) throws IOException {
      ASN1EncodableVector signedCheque = new ASN1EncodableVector();
      signedCheque.add(cheque);

      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
      signedCheque.add(spki.getPublicKeyData());

      signedCheque.add(new DERBitString(signature));
      return new DERSequence(signedCheque).getEncoded();
  }

  @Override
  public boolean checkValidity() {
    long currentTime = System.currentTimeMillis();
    if (!(currentTime >= getNotValidBefore() && currentTime < getNotValidAfter())) {
      System.err.println("Cheque is no longer valid");
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    try {
      ASN1Sequence cheque = makeCheque(this.commitment, this.amount, this.getNotValidBefore(),
          this.notValidAfter);
      return SignatureUtility.verify(cheque.getEncoded(), signature, this.publicKey);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] getDerEncoding() {
    return encoded;
  }

  @Override
  public byte[] getCommitment() {
    return commitment;
  }

  public long getAmount() {
    return amount;
  }

  public long getNotValidBefore() {
    return notValidBefore;
  }

  public long getNotValidAfter() {
    return notValidAfter;
  }

  public byte[] getSignature() {
    return signature;
  }

  public AsymmetricKeyParameter getPublicKey() {
    return this.publicKey;
  }
}
