package com.alphawallet.attestation.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.ticket.Ticket.TicketClass;

import java.io.File;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestTicket {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("48646");
  private static final TicketClass TICKET_CLASS = TicketClass.REGULAR;
  private static final int CONFERENCE_ID = 6;
  private static final BigInteger SECRET = new BigInteger("546048445646851568430134455064804806");

  private static AsymmetricCipherKeyPair senderKeys;
  private static AsymmetricCipherKeyPair otherKeys;
  private static SecureRandom rand;

  private static final String PREFIX = "build/test-results/";

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AttestationCrypto crypto = new AttestationCrypto(rand);
    senderKeys = crypto.constructECKeys();
    otherKeys = crypto.constructECKeys();
  }

  @Test
  public void testFullDecoding() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoded = ticket.getDerEncoding();
    // write the ticket data
    Files.write(new File(PREFIX + "signed-devcon-ticket.der").toPath(), encoded);

    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(encoded);
    assertTrue(ticket.verify());
    assertTrue(newTicket.verify());
    assertArrayEquals(encoded, newTicket.getDerEncoding());

    Ticket otherConstructor = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), newTicket.getPublicKey());
    assertEquals(ticket.getTicketId(), otherConstructor.getTicketId());
    assertEquals(ticket.getTicketClass(), otherConstructor.getTicketClass());
    assertEquals(ticket.getDevconId(), otherConstructor.getDevconId());
    assertEquals(ticket.getAlgorithm(), otherConstructor.getAlgorithm());
    assertArrayEquals(ticket.getCommitment(), otherConstructor.getCommitment());
    assertArrayEquals(ticket.getSignature(), otherConstructor.getSignature());
    SubjectPublicKeyInfo ticketSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticket.getPublicKey());
    SubjectPublicKeyInfo otherSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherConstructor.getPublicKey());
    assertArrayEquals(ticketSpki.getEncoded(), otherSpki.getEncoded());

    assertArrayEquals(encoded, otherConstructor.getDerEncoding());
  }

  @Test
  public void testFullDecodingWithPK() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoded = ticket.getDerEncodingWithPK();
    // write the ticket data
    Files.write(new File(PREFIX + "signed-devcon-ticket.der").toPath(), encoded);

    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(encoded);
    assertTrue(ticket.verify());
    assertTrue(newTicket.verify());
    assertArrayEquals(encoded, newTicket.getDerEncodingWithPK());

    Ticket otherConstructor = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), newTicket.getPublicKey());
    assertEquals(ticket.getTicketId(), otherConstructor.getTicketId());
    assertEquals(ticket.getTicketClass(), otherConstructor.getTicketClass());
    assertEquals(ticket.getDevconId(), otherConstructor.getDevconId());
    assertEquals(ticket.getAlgorithm(), otherConstructor.getAlgorithm());
    assertArrayEquals(ticket.getCommitment(), otherConstructor.getCommitment());
    assertArrayEquals(ticket.getSignature(), otherConstructor.getSignature());
    SubjectPublicKeyInfo ticketSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticket.getPublicKey());
    SubjectPublicKeyInfo otherSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherConstructor.getPublicKey());
    assertArrayEquals(ticketSpki.getEncoded(), otherSpki.getEncoded());

    assertArrayEquals(encoded, otherConstructor.getDerEncodingWithPK());

    Ticket noPKDecodingTicket = (new TicketDecoder()).decode(encoded);
    assertTrue(noPKDecodingTicket.verify());
    assertArrayEquals(encoded, noPKDecodingTicket.getDerEncodingWithPK());
  }


  @Test
  public void testIllegalKeys() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    Field field = ticket.getClass().getDeclaredField("signature");
    field.setAccessible(true);
    // Change a bit in the signature
    ((byte[]) field.get(ticket))[20] ^= 1;
    assertFalse(ticket.verify());
    // Check we cannot make a new ticket with invalid signature
    try {
      Ticket newTicket = new Ticket(ticket.getDevconId(), ticket.getTicketId(), ticket.getTicketClass(),
          ticket.getCommitment(), ticket.getSignature(),
          senderKeys.getPublic());
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testWrongKey() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoding = ticket.getDerEncodingWithPK();
    try {
      Ticket otherTicket = (new TicketDecoder(otherKeys.getPublic())).decode(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testWrongKeyNoPKArgument() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoding = ticket.getDerEncoding();
    try {
      Ticket otherTicket = (new TicketDecoder(otherKeys.getPublic())).decode(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }
}
