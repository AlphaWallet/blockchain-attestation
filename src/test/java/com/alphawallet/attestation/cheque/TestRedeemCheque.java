package com.alphawallet.attestation.cheque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.DERUtility;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestRedeemCheque {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair issuerKeys;
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private AttestedObject<Cheque> attestedCheque;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    issuerKeys = SignatureUtility.constructECKeys(rand);
    senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @BeforeEach
  public void makeAttestedCheque() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret, "test@test.ts" );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    attestedCheque = new AttestedObject(cheque, signed, subjectKeys, subjectSecret, senderSecret, crypto);
    assertTrue(attestedCheque.verify());
    assertTrue(attestedCheque.checkValidity());
  }

  @Test
  public void testSunshine() {
        // *** PRINT DER ENCODING OF OBJECTS ***
    try {
      PublicKey pk;
      PrintStream a = System.out;
      System.out.println("Signed attestation:");
      DERUtility.writePEM(attestedCheque.getAtt().getDerEncoding(), "SIGNEABLE", System.out);
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuerKeys.getPublic()));
      System.out.println("Attestation verification key:");
      DERUtility.writePEM(pk.getEncoded(),"PUBLIC KEY", System.out);
      System.out.println("Cheque:");
      DERUtility.writePEM(attestedCheque.getAttestableObject().getDerEncoding(), "CHEQUE", System.out);
      System.out.println("Signed cheque verification key:");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic()));
      DERUtility.writePEM(pk.getEncoded(),"PUBLIC KEY", System.out);
      System.out.println("Attested Cheque:");
      DERUtility.writePEM(attestedCheque.getDerEncoding(), "REDEEM", System.out);
      System.out.println("Signed user public key (for redeem verification):");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic()));
      DERUtility.writePEM(pk.getEncoded(),"PUBLIC KEY", System.out);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testDecoding() throws InvalidObjectException {
    AttestedObject newRedeem = new AttestedObject(attestedCheque.getDerEncodingWithSignature(), new ChequeDecoder(),
        issuerKeys.getPublic());
    assertTrue(newRedeem.getAttestableObject().verify());
    assertTrue(newRedeem.getAtt().verify());
    assertTrue(AttestationCrypto.verifyEqualityProof(newRedeem.getAtt().getUnsignedAttestation().getCommitment(), newRedeem.getAttestableObject().getCommitment(), newRedeem.getPok()));

    assertArrayEquals(
        attestedCheque.getAttestableObject().getDerEncoding(), newRedeem.getAttestableObject().getDerEncoding());
    assertArrayEquals(attestedCheque.getAtt().getDerEncoding(), newRedeem.getAtt().getDerEncoding());
    assertArrayEquals(attestedCheque.getPok().getDerEncoding(), newRedeem.getPok().getDerEncoding());
    assertArrayEquals(attestedCheque.getSignature(), newRedeem.getSignature());
    assertEquals(attestedCheque.getUserPublicKey(), subjectKeys.getPublic());
    assertArrayEquals(attestedCheque.getDerEncoding(), newRedeem.getDerEncoding());
    assertArrayEquals(attestedCheque.getDerEncodingWithSignature(), newRedeem.getDerEncodingWithSignature());

    AttestedObject newConstructor = new AttestedObject(attestedCheque.getAttestableObject(), attestedCheque
        .getAtt(), attestedCheque.getPok(),
        attestedCheque.getSignature());

    assertArrayEquals(attestedCheque.getDerEncoding(), newConstructor.getDerEncoding());
    assertArrayEquals(attestedCheque.getDerEncodingWithSignature(), newConstructor.getDerEncodingWithSignature());
  }

  @Test
  public void testNegativeAttestation() throws Exception {
    Attestation att = attestedCheque.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("version");
    field.setAccessible(true);
    // Invalid version for Identifier Attestation along with failing signature
    field.set(att, new ASN1Integer(19));
    // Only correctly formed Identifier Attestations are allowed
    assertFalse(att.checkValidity());
    assertFalse(attestedCheque.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(attestedCheque.getAtt().verify());
    assertFalse(attestedCheque.verify());
  }

  @Test
  public void testNegativeCheque() throws Exception {
    Cheque cheque = attestedCheque.getAttestableObject();
    Field field = cheque.getClass().getDeclaredField("notValidAfter");
    field.setAccessible(true);
    // Set validity to the past
    field.set(cheque, Clock.systemUTC().millis()-1000);
    assertFalse(cheque.checkValidity());
    assertFalse(attestedCheque.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(cheque.verify());
    assertFalse(attestedCheque.verify());
  }

  // Test that the key used to sign the RedeemCheque is the same as attested to
  @Test
  public void testNegativeUnmatchingKeys() throws Exception {
    Attestation att = attestedCheque.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuerKeys.getPublic());
    assertFalse(Arrays.equals(spki.getEncoded(), att.getSubjectPublicKeyInfo().getEncoded()));
    // Change public key
    field.set(att, spki);
    // Validation should not fail for attestation
    assertTrue(attestedCheque.getAtt().checkValidity());
    // However it should for the whole object since the keys no longer match
    assertFalse(attestedCheque.checkValidity());
    // Verification should fail
    assertFalse(attestedCheque.getAtt().verify());
    assertFalse(attestedCheque.verify());
  }

  @Test
  public void testNegativeDifferentKeys() throws Exception {
    SignedIdentifierAttestation att = attestedCheque.getAtt();
    Field field = att.getClass().getDeclaredField("attestationVerificationKey");
    field.setAccessible(true);
    // Change public key
    field.set(att, subjectKeys.getPublic());
    // Verification should fail
    assertFalse(att.verify());
    assertFalse(attestedCheque.verify());
  }

  @Test
  public void testNegativeWrongProofIdentifier() throws Exception {
    // Add an extra "t" in the mail address
    FullProofOfExponent newPok = crypto.computeAttestationProof( new BigInteger("42424242"));
    Field field = attestedCheque.getClass().getDeclaredField("pok");
    field.setAccessible(true);
    // Change the proof
    field.set(attestedCheque, newPok);
    // Validation should still pass
    assertTrue(attestedCheque.checkValidity());
    assertTrue(AttestationCrypto.verifyFullProof(newPok));
    // Verification should fail since the proof is not for the same identifier as the attestation and cheque
    assertFalse(attestedCheque.verify());
  }

  @Test
  public void testNegativeWrongRiddle() throws Exception {
    BigInteger secret =  new BigInteger("42424242");
    Cheque newCheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, secret);
    assertTrue(newCheque.checkValidity());
    assertTrue(newCheque.verify());
    Field field = attestedCheque.getClass().getDeclaredField("attestableObject");
    field.setAccessible(true);
    // Set cheque to the new cheque, with a different secret
    field.set(attestedCheque, newCheque);
    // Validation should still pass
    assertTrue(attestedCheque.checkValidity());
    // Verification should noq fail since the secret is not correct
    assertFalse(attestedCheque.verify());
  }

  @Test
  public void testNegativeConstruction() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret, "something@google.com");
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
    // Wrong mail
    Cheque cheque = new Cheque("something@else.com", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    try {
      AttestedObject current = new AttestedObject(cheque, signed, subjectKeys, subjectSecret, senderSecret, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong email
    }
  }

  @Test
  public void testNegativeConstruction2() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    String mail = "something@google.com";
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret, mail);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
    Cheque cheque = new Cheque(mail, AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    try {
      // Wrong subject secret
      AttestedObject current = new AttestedObject(cheque, signed, subjectKeys, subjectSecret.add(BigInteger.ONE), senderSecret, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Wrong sender secret
      AttestedObject current = new AttestedObject(cheque, signed, subjectKeys, subjectSecret, senderSecret.add(BigInteger.ONE), crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
  }
}
