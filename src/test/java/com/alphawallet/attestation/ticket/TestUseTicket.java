package com.alphawallet.attestation.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.ProofOfExponent;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.DERUtility;
import com.alphawallet.attestation.ticket.Ticket.TicketClass;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestUseTicket {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final TicketClass TICKET_CLASS = TicketClass.REGULAR;
  private static final int CONFERENCE_ID = 6;
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private AttestedObject<Ticket> attestedTicket;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
    attestorKeys = crypto.constructECKeys();
    ticketIssuerKeys = crypto.constructECKeys();
  }

  @BeforeEach
  public void makeAttestedTicket() {
    Attestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    attestedTicket = new AttestedObject<Ticket>(ticket, signed, subjectKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
  }

  @Test
  public void testSunshine() {
    // *** PRINT DER ENCODING OF OBJECTS ***
    try {
      PublicKey pk;
      System.out.println("Signed attestation:");
      System.out.println(DERUtility.printDER(attestedTicket.getAtt().getDerEncoding(), "SIGNABLE"));
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(attestorKeys.getPublic()));
      System.out.println("Attestation verification key:");
      System.out.println(DERUtility.printDER(pk.getEncoded(), "PUBLIC KEY"));

      System.out.println("Ticket:");
      System.out.println(
          DERUtility.printDER(attestedTicket.getAttestableObject().getDerEncoding(), "TICKET"));
      System.out.println("Signed ticket verification key:");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticketIssuerKeys.getPublic()));
      System.out.println(DERUtility.printDER(pk.getEncoded(), "PUBLIC KEY"));

      System.out.println("Attested Ticket:");
      System.out.println(DERUtility.printDER(attestedTicket.getDerEncoding(), "ATTESTED-TICKET"));
      System.out.println("Signed user public key (for verification of attested ticket):");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic()));
      System.out.println(DERUtility.printDER(pk.getEncoded(), "PUBLIC KEY"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testDecoding() throws InvalidObjectException {
    AttestedObject newAttestedTicket = new AttestedObject(attestedTicket.getDerEncoding(), new TicketDecoder(
        ticketIssuerKeys.getPublic()), attestorKeys.getPublic(), subjectKeys.getPublic());
    assertTrue(newAttestedTicket.getAttestableObject().verify());
    assertTrue(newAttestedTicket.getAtt().verify());
    ASN1Sequence extensions = DERSequence
        .getInstance(newAttestedTicket.getAtt().getUnsignedAttestation().getExtensions().getObjectAt(0));
    byte[] attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
    assertTrue(AttestationCrypto.verifyEqualityProof(attCom, newAttestedTicket.getAttestableObject().getCommitment(), newAttestedTicket.getPok()));

    assertArrayEquals(attestedTicket.getAttestableObject().getDerEncoding(),
        newAttestedTicket.getAttestableObject().getDerEncoding());
    assertArrayEquals(attestedTicket.getAtt().getDerEncoding(), newAttestedTicket.getAtt().getDerEncoding());
    assertArrayEquals(attestedTicket.getPok().getDerEncoding(), newAttestedTicket.getPok().getDerEncoding());
    assertArrayEquals(attestedTicket.getSignature(), newAttestedTicket.getSignature());
    assertEquals(attestedTicket.getUserPublicKey(), subjectKeys.getPublic());
    assertArrayEquals(attestedTicket.getDerEncoding(), attestedTicket.getDerEncoding());

    AttestedObject newConstructor = new AttestedObject(attestedTicket.getAttestableObject(),
        attestedTicket.getAtt(), attestedTicket.getPok(),
        attestedTicket.getSignature(), attestorKeys.getPublic(), subjectKeys.getPublic());

    assertArrayEquals(attestedTicket.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void testNegativeAttestation() throws Exception {
    Attestation att = attestedTicket.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("version");
    field.setAccessible(true);
    // Invalid version for Identity Attestation along with failing signature
    field.set(att, new ASN1Integer(19));
    // Only correctly formed Identity Attestations are allowed
    assertFalse(att.checkValidity());
    assertFalse(attestedTicket.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(attestedTicket.getAtt().verify());
    assertFalse(attestedTicket.verify());
  }

  // Test that the key used to sign the Attested Ticket is the same as attested to
  @Test
  public void testNegativeUnmatchingKeys() throws Exception {
    Attestation att = attestedTicket.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory
        .createSubjectPublicKeyInfo(attestorKeys.getPublic());
    assertFalse(Arrays.equals(spki.getEncoded(), att.getSubjectPublicKeyInfo().getEncoded()));
    // Change public key
    field.set(att, spki);
    // Validation should not fail
    assertFalse(attestedTicket.getAtt().checkValidity());
    assertFalse(attestedTicket.checkValidity());
    // Verification should fail
    assertFalse(attestedTicket.getAtt().verify());
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeDifferentKeys() throws Exception {
    SignedAttestation att = attestedTicket.getAtt();
    Field field = att.getClass().getDeclaredField("publicKey");
    field.setAccessible(true);
    // Change public key
    field.set(att, subjectKeys.getPublic());
    // Verification should fail
    assertFalse(att.verify());
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeWrongProofIdentity() throws Exception {
    ASN1Sequence extensions = DERSequence.getInstance(attestedTicket.getAtt().getUnsignedAttestation().getExtensions().getObjectAt(0));
    byte[] attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
    // Wrong attestation secret
    ProofOfExponent newPok = crypto
        .computeEqualityProof(attCom, attestedTicket.getAttestableObject().getCommitment(), new BigInteger("42424242"), TICKET_SECRET);
    Field field = attestedTicket.getClass().getDeclaredField("pok");
    field.setAccessible(true);
    // Change the proof
    field.set(attestedTicket, newPok);
    // Validation should still pass
    assertTrue(attestedTicket.checkValidity());
    // Verification of the proof itself should fail
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(newPok));
    // Verification should fail of the attested ticket
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeWrongRiddle() throws Exception {
    Ticket newTicket  = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    assertTrue(newTicket.checkValidity());
    assertTrue(newTicket.verify());
    Field field = attestedTicket.getClass().getDeclaredField("attestableObject");
    field.setAccessible(true);
    // Set new ticket
    field.set(attestedTicket, newTicket);
    // Validation should still pass since tickets on their own are always valid
    assertTrue(attestedTicket.checkValidity());
    // Verification should not fail
    assertTrue(attestedTicket.verify());
  }

  @Test
  public void testNegativeConstruction() {
    Attestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    // Add an extra t in the mail
    Ticket ticket = new Ticket("testt@test.ts", CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    try {
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys, ATTESTATION_SECRET,
          TICKET_SECRET, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong email
    }
  }

  @Test
  public void testNegativeConstruction2() {
    Attestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    try {
      // Wrong subject secret
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys,
          TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Wrong attestation secret
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys, TICKET_SECRET,
          ATTESTATION_SECRET.add(BigInteger.ONE), crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Correlated secrets
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys,
          TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET.add(BigInteger.ONE), crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
  }
}
