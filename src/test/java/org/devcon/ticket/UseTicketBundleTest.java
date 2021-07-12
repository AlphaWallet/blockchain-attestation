package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class UseTicketBundleTest {
  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "Åø"; // Ensure non-number non ASCII can be handled
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static byte[] macKey;
  private static UnpredictableNumberTool unt;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private AttestedObject<Ticket> useTicket;

  @Mock
  AttestedObject<Ticket> mockedUseTicket;
  @Mock
  UnpredictableNumberBundle mockedUn;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(rand);
    ticketIssuerKeys = SignatureUtility.constructECKeys(rand);
    macKey = rand.generateSeed(16);
    unt = new UnpredictableNumberTool(rand, macKey, DOMAIN, UnpredictableNumberTool.DEFAULT_VALIDITY_IN_MS);
  }

  @BeforeEach
  public void makeUseTicket() {
    MockitoAnnotations.initMocks(this);

    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    useTicket = new AttestedObject<Ticket>(ticket, signed, subjectKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);

    Mockito.when(mockedUseTicket.verify()).thenReturn(true);
    Mockito.when(mockedUseTicket.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedUseTicket.getUserPublicKey()).thenReturn(subjectKeys.getPublic());

    Mockito.when(mockedUn.getDomain()).thenReturn(DOMAIN);
    Mockito.when(mockedUn.getExpiration()).thenReturn(Long.MAX_VALUE);
    Mockito.when(mockedUn.getRandomness()).thenReturn(new byte[UnpredictableNumberTool.BYTES_IN_SEED]);
    Mockito.when(mockedUn.getNumber()).thenReturn("abcdefghijk");
  }

  @Test
  public void sunshine() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(useTicket, un, subjectKeys.getPrivate());
    assertTrue(bundle.verify());
    assertTrue(bundle.validateAndVerify(unt));
  }

  @Test
  public void testDeEncoding1() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(useTicket, un, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(refJson, ticketIssuerKeys.getPublic(), attestorKeys.getPublic());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(unt));
    assertEquals(refJson, newBundle.getJsonBundle());
  }

  @Test
  public void testDeEncoding2() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(useTicket, un, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(bundle.getUseTicket(), bundle.getUn(), bundle.getSignature());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(unt));
    assertEquals(refJson, newBundle.getJsonBundle());
  }

  @Test
  public void sanity() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UnpredictableNumberBundle newerUn = unt.getUnpredictableNumberBundle();
    ObjectMapper jsonMapper = new ObjectMapper();
    // Verify that the ticket is different
    assertNotEquals(jsonMapper.writeValueAsString(un), jsonMapper.writeValueAsString(newerUn));
  }

  @Test
  public void sanityTime() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    UnpredictableNumberTool unt = new UnpredictableNumberTool(rand, macKey, DOMAIN, UnpredictableNumberTool.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    rand.setSeed("seed".getBytes()); // Reset the randomness generator
    Thread.sleep(2); // Ensure the expiration changes
    UnpredictableNumberBundle newerUn = unt.getUnpredictableNumberBundle();
    ObjectMapper jsonMapper = new ObjectMapper();
    // Verify that the ticket is different
    assertNotEquals(jsonMapper.writeValueAsString(un), jsonMapper.writeValueAsString(newerUn));
  }

  @Test
  public void worksInTheFuture() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    // Check it is valid at least 58 min in the future
    assertTrue(un.getExpiration() > Clock.systemUTC().millis() + 3500 * 1000);
  }

  @Test
  public void unverifiableUseTicketConstructorFailure() throws Exception {
    Mockito.when(mockedUseTicket.verify()).thenReturn(false);

    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    assertThrows(IllegalArgumentException.class, ()-> new UseTicketBundle(mockedUseTicket, un, subjectKeys.getPrivate()));
  }

  @Test
  public void badChallengeSignatureConstructor() throws Exception {
    // Return wrong key, it is supposed to be the subjectKey
    Mockito.when(mockedUseTicket.getUserPublicKey()).thenReturn(attestorKeys.getPublic());

    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    assertThrows(IllegalArgumentException.class, ()-> new UseTicketBundle(mockedUseTicket, un, subjectKeys.getPrivate()));
  }

  @Test
  public void unverifiableUseTicket() throws Exception {
    // Return true first to make test in constructor pass
    Mockito.when(mockedUseTicket.verify()).thenReturn(true).thenReturn(false);

    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(mockedUseTicket, un, subjectKeys.getPrivate());
    assertFalse(bundle.verify());
  }

  @Test
  public void unvalidatableUseTicket() throws Exception {
    Mockito.when(mockedUseTicket.checkValidity()).thenReturn(false);

    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(mockedUseTicket, un, subjectKeys.getPrivate());
    assertFalse(bundle.validateAndVerify(unt));
  }

  @Test
  public void invalidUn() throws Exception {
    Mockito.when(mockedUn.getNumber()).thenReturn("somethingwrong");

    UseTicketBundle bundle = new UseTicketBundle(useTicket, mockedUn, subjectKeys.getPrivate());
    assertFalse(bundle.validateAndVerify(unt));
  }
}
