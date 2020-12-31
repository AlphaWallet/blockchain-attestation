package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.cheque.Cheque;
import com.alphawallet.attestation.cheque.ChequeDecoder;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.ticket.Ticket;
import com.alphawallet.attestation.ticket.Ticket.TicketClass;
import com.alphawallet.attestation.ticket.TicketDecoder;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestURL {
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AttestationCrypto crypto = new AttestationCrypto(rand);
    senderKeys = crypto.constructECKeys();
  }

  @Test
  public void testChequeSunshine() throws IOException  {
    BigInteger senderSecret = new BigInteger("112");
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);

    byte[] senderPublicKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic()).getPublicKeyData().getEncoded();
    String url = URLUtility.encodeList(Arrays.asList(cheque.getDerEncoding(), senderPublicKey));

    List<byte[]> decoded = URLUtility.decodeList(url);
    Cheque newCheque = (new ChequeDecoder()).decode(decoded.get(0));
    assertTrue(newCheque.verify());
    assertTrue(newCheque.checkValidity());
    assertArrayEquals(cheque.getDerEncoding(), newCheque.getDerEncoding());

    AsymmetricKeyParameter newIssuerPublicKey = SignatureUtility.restoreKey(decoded.get(1));
    Cheque otherConstructorCheque = new Cheque(newCheque.getCommitment(), newCheque.getAmount(),
        newCheque.getNotValidBefore(), newCheque.getNotValidAfter(), newCheque.getSignature(), newIssuerPublicKey);
    assertArrayEquals(cheque.getDerEncoding(), otherConstructorCheque.getDerEncoding());
  }

  @Test
  public void testChequeConsistentEncoding() throws IOException {
    BigInteger senderSecret = new BigInteger("112");
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    String url = URLUtility.encodeData(cheque.getDerEncoding());
    Cheque newCheque =  (new ChequeDecoder()).decode(URLUtility.decodeData(url));
    String newUrl = URLUtility.encodeData(newCheque.getDerEncoding());
    assertEquals(url, newUrl);
  }

  @Test
  public void testTicketSunshine() throws IOException  {
    BigInteger ticketID = new BigInteger("417541561854");
    TicketClass ticketClass = TicketClass.REGULAR;
    BigInteger senderSecret = new BigInteger("45845870684");
    Ticket ticket = new Ticket("mah@mah.com", 6, ticketID, ticketClass, senderKeys, senderSecret);

    byte[] senderPublicKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic()).getPublicKeyData().getEncoded();
    String url = URLUtility.encodeList(Arrays.asList(ticket.getDerEncoding(), senderPublicKey));

    List<byte[]> decoded = URLUtility.decodeList(url);
    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(decoded.get(0));
    assertTrue(newTicket.verify());
    assertTrue(newTicket.checkValidity());
    assertArrayEquals(ticket.getDerEncoding(), newTicket.getDerEncoding());

    AsymmetricKeyParameter newIssuerPublicKey = SignatureUtility.restoreKey(decoded.get(1));
    Ticket otherConstructorTicket = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), newIssuerPublicKey);
    assertArrayEquals(ticket.getDerEncoding(), otherConstructorTicket.getDerEncoding());
  }

  @Test
  public void testTicketConsistentEncoding() throws IOException {
    BigInteger ticketID = new BigInteger("14840860468475837258758376");
    TicketClass ticketClass = TicketClass.VIP;
    BigInteger senderSecret = new BigInteger("186416");
    Ticket ticket = new Ticket("ticket@test.ts", 6, ticketID, ticketClass, senderKeys, senderSecret);
    String url = URLUtility.encodeData(ticket.getDerEncoding());
    Ticket newTicket =  (new TicketDecoder(senderKeys.getPublic())).decode(URLUtility.decodeData(url));
    String newUrl = URLUtility.encodeData(newTicket.getDerEncoding());
    assertEquals(url, newUrl);
    /*** PRINT URL ***/
    System.out.println(url);
  }
}
