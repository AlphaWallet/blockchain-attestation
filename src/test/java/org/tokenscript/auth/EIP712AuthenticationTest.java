package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Timestamp;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.TicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.eip712.Eip712Test;
import org.tokenscript.eip712.FullEip712InternalData;

public class EIP712AuthenticationTest {
  private static final String validatorDomain = "http://www.hotelbogota.com";

  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "6";
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair userKeys, attestorKeys, ticketKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static Eip712AuthValidator validator;
  private static Eip712AuthIssuer issuer;
  private static AuthenticatorEncoder encoder;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    ticketKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    encoder = new AuthenticatorEncoder(1, rand);
    validator = new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), validatorDomain);
    issuer = new Eip712AuthIssuer(userKeys.getPrivate(), encoder);
  }

  private static AttestedObject<Ticket> makeAttestedTicket() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, userKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
    return attestedTicket;
  }

  @Test
  public void legalRequest() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    assertTrue(validator.validateRequest(token));
  }

  @Test
  public void eipEncoding() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    Eip712Test.validateEncoding(encoder, token);
  }

  @Test
  public void testNewChainID() throws Exception {
    AuthenticatorEncoder localAuthenticator = new AuthenticatorEncoder(42, rand);
    Eip712AuthIssuer localIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), localAuthenticator);
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = localIssuer.buildSignedToken(attestedTicket, validatorDomain);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712AuthValidator localValidator = new Eip712AuthValidator(decoder, localAuthenticator, attestorKeys.getPublic(), validatorDomain);
    assertTrue(localValidator.validateRequest(token));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void testConsistency() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis();
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    String newToken = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertEquals(token, newToken);
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

  @Test
  public void wrongAttestedKey() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(newKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, newKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);

    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712AuthIssuer newIssuer = new Eip712AuthIssuer(newKeys.getPrivate(), encoder.getChainId());
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = newIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis() + 2 * Timestamp.ALLOWED_ROUNDING;
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = 10000;
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712AuthValidator newValidator = new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), validatorDomain);
    assertFalse(newValidator.validateRequest(token));
  }

  @Test
  public void incorrectModifiedToken() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[40] ^= 0x01;
    assertFalse(validator.validateRequest(new String(tokenBytes, StandardCharsets.UTF_8)));
  }

  @Test
  public void incorrectDomain() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    // Extra a in domain
    String token = issuer.buildSignedToken(attestedTicket, "http://www.hotelbogotaa.com");
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void invalidDomainVerifier() {
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    assertThrows( RuntimeException.class, () -> {
      new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    AttestedObject attestedTicket = makeAttestedTicket();
    assertThrows( RuntimeException.class, () -> {
      AuthenticatorEncoder authenticator = new AuthenticatorEncoder(1, rand);
      Eip712AuthIssuer issuer = new Eip712AuthIssuer(userKeys.getPrivate(), authenticator);
      issuer.buildSignedToken(attestedTicket, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidVersion() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712AuthIssuer testIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), new TestAuthenticatorEncoder("2.2", 1));
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void consistentSalt() {
    String salt = encoder.getSalt();
    assertNotNull(salt);
    String otherSalt = encoder.getSalt();
    assertEquals(salt, otherSalt);
  }

  private class TestEip712Authentication extends Eip712AuthIssuer {
    private final Timestamp testTimestamp;

    public TestEip712Authentication(AsymmetricKeyParameter signingKey, AuthenticatorEncoder authenticator, long testTimestamp) {
      super(signingKey, authenticator);
      this.testTimestamp = new Timestamp(testTimestamp);
    }

    @Override
    public String buildSignedToken(AttestedObject attestedObject, String webDomain) throws JsonProcessingException {
      String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
      FullEip712InternalData auth = new FullEip712InternalData(
          encoder.getUsageValue(), encodedObject, testTimestamp);
      return buildSignedTokenFromJsonObject(auth, webDomain);
    }
  }

  private class TestAuthenticatorEncoder extends AuthenticatorEncoder {
    private String protoVersion = super.getProtocolVersion();

    public TestAuthenticatorEncoder(String protoVersion, long chainId) {
      super(chainId, new SecureRandom());
      this.protoVersion = protoVersion;
    }

    public TestAuthenticatorEncoder() {
      super(1, new SecureRandom());
    }

    @Override
    public String getSalt() {
      return "0102030405060708090001020304050607080900010203040506070809000102";
    }

    @Override
    public String getProtocolVersion() {
      return protoVersion;
    }
  }
}
