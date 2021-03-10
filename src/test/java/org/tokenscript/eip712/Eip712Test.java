package org.tokenscript.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class Eip712Test {
  private static final String testDomain = "http://www.test.com";
  private static final FullEip712InternalData testObject = new FullEip712InternalData("description", "payload", 0L);

  private static AsymmetricCipherKeyPair userKeys;
  private static SecureRandom rand;
  private static Eip712Validator validator;
  private static Eip712Issuer issuer;
  private static Eip712Encoder encoder;
  private static ObjectMapper mapper;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    encoder = new TestEncoder();
    validator = new Eip712Validator(testDomain, encoder);
    issuer = new Eip712Issuer(userKeys.getPrivate(), encoder);
    mapper = new ObjectMapper();
  }

  private void checkEquality(FullEip712InternalData computedObject) {
    assertEquals(testObject.getPayload(), computedObject.getPayload());
    assertEquals(testObject.getDescription(), computedObject.getDescription());
    assertEquals(testObject.getTimestamp(), computedObject.getTimestamp());
    assertEquals(testObject.getSignableVersion().getPayload(), computedObject.getSignableVersion().getPayload());
  }

  @Test
  public void testSunshine() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void testNewChainID() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 1);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void testConsistency() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    String newToken = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    assertEquals(token, newToken);
  }

  @Test
  public void nullInput() {
    assertThrows( InvalidObjectException.class, () -> validator.retrieveUnderlyingObject(null, FullEip712InternalData.class));
  }

  @Test
  public void testDifferenceWithDifferentChainIds() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    String newToken = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 1);
    assertFalse(token.equals(newToken));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712Issuer newIssuer = new Eip712Issuer(newKeys.getPrivate(), encoder);
    String token = newIssuer.buildSignedTokenFromJsonObject(testObject, testDomain, 1);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(newKeys.getPublic()), FullEip712InternalData.class));
    assertFalse(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void incorrectModifiedToken() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[0] ^= 0x01;
    assertFalse(validator.verifySignature(new String(tokenBytes, StandardCharsets.UTF_8), SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
    assertThrows(InvalidObjectException.class, () -> validator.retrieveUnderlyingObject(new String(tokenBytes, StandardCharsets.UTF_8), FullEip712InternalData.class));
  }

  @Test
  public void incorrectDomain() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, "http://www.not-test.com", 0);
    assertThrows(InvalidObjectException.class, () -> validator.getDomainFromJson(token));
  }

  @Test
  public void invalidDomainIssuer() {
    assertThrows(IllegalArgumentException.class, () -> issuer.buildSignedTokenFromJsonObject(testObject, "www.noHttpPrefix.com", 0));
  }

  @Test
  public void invalidDomainVerifier() {
    assertThrows(IllegalArgumentException.class, () -> new Eip712Validator("www.noHttpPrefix.com", encoder));
  }

  @Test
  public void invalidVersionIssuer() throws Exception {
    Eip712Issuer newIssuer = new Eip712Issuer(userKeys.getPrivate(), new TestEncoder("2.0"));
    String token = newIssuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    assertThrows(InvalidObjectException.class, () -> validator.getDomainFromJson(token));
  }

  @Test
  public void invalidVersionValidator() throws Exception {
    Eip712Validator newValidator = new Eip712Validator(testDomain, new TestEncoder("2.0"));
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain, 0);
    assertThrows(InvalidObjectException.class, () -> newValidator.getDomainFromJson(token));
  }

  @Test
  public void invalidTimestamp() {
    // Does not contain millisecond accuracy
    assertFalse(validator.verifyTimeStamp("1970.01.01 at 01:00:00 CET"));
  }

  private static class TestEncoder extends Eip712Encoder {

    private String protocolVersion = "1.0";

    public TestEncoder() {}
    public TestEncoder(String protocolVersion) {
      this.protocolVersion = protocolVersion;
    }

    @Override
    public HashMap<String, List<Entry>> getTypes() {
      HashMap<String, List<Entry>> types = new HashMap<>();
      List<Entry> content = new ArrayList<>();
      content.add(new Entry("testElement", STRING));
      types.put("Test", content);
      List<Entry> domainContent = new ArrayList<>();
      domainContent.add(new Entry("name", STRING));
      domainContent.add(new Entry("version", STRING));
      domainContent.add(new Entry("salt", BYTES32));
      types.put("EIP712Domain", domainContent);
      return types;
    }

    @Override
    public String getPrimaryName() {
      return "Test";
    }

    @Override
    public String getProtocolVersion() {
      return protocolVersion;
    }

    @Override
    public String getSalt() {
      return null;
    }
  }

}
