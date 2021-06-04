package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestationRequestWithUsage;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationRequestWithUsageEip712 {
  private static final String DOMAIN = "https://www.attestation.id";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final Eip712AttestationRequestWithUsageEncoder encoder = new Eip712AttestationRequestWithUsageEncoder();

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static AttestationRequestWithUsage requestWithUsage;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricKeyParameter userSigningKey;
  private static AsymmetricKeyParameter sessionKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    requestWithUsage = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    assertTrue(requestWithUsage.verify());
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void referenceJsonFormat() {
    String request = "{\"signatureInHex\":\"0xe20b46004135bc1842942528d9605c42389e0f7b62d06033c7927346c4554632415d5af70c52e22a915ac60e36c03b5a38e6f392e46a66e818568dbea4b1fde31c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICTQIBATCB_ARBBB62SP-dgZtAemxY0nl4cjxOW0UKyYmDPOz2_YfDFgzeCa3ZVleOniCjeTfuoR9NTatdcoM4IruwzSUv-DniQbcEIBYanUtFbiNBDc4xKTmIFA2ndvUloBWRCPnmQjmJMH0wBEEEDFVwBw77_sz-3PcHsmrwCbfzlcYJpvrh1dcYJCcxAAQlgxlEE72jadyvtgoUs-ttKmV-pQN0FXiBiBgU0q9vswRSMFg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1Sm1UC7EZ7FbQ1gD2qvRqimx8roUC_TlKlL_iMtn-uNsAAAF51yxyyDCCAUcwgfgGByqGSM49AgEwgewCAQEwJQYHKoZIzj0BAjAaAgIBGwYJKoZIzj0BAgMDMAkCAQUCAQcCAQwwTAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEESQQFAyE_eMpEiD8aO4Fi8YjlU80mXyPBVnoWh2kTsMKsJFhJKDYBzNo4DxyeMY2Q-V0H5UJv6H5FwOgYRpjkWWI2TjQRYXfdIlkCJAH______________________-muLtB1dyZd_3-URR4GHhY8YQIBBANKAAQFK7J9i33xUcv3NBo2Xh82NNDkiqCBaefEwx4sRgxdgUaXmNUHJ8zGwAtvOMuXXHqoJpsCyU_aPLbGNP7o0kTjE75DVoiAbHQ=\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Fri Jun 4 2021 15:18:06 GMT+0200\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Mon Jun 21 2021 15:58:34 GMT+0200\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage eiprequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
    assertTrue(eiprequest.checkTokenValidity());
    Eip712AttestationRequestWithUsage lessValidRequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, 1000L*10L, Timestamp.UNLIMITED, request);
    assertTrue(lessValidRequest.verify());
    assertFalse(lessValidRequest.checkValidity());
    assertTrue(lessValidRequest.checkTokenValidity());
    Eip712AttestationRequestWithUsage leastValidRequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, 1000L*10L, 1000L*60L*20L, request);
    assertTrue(leastValidRequest.verify());
    assertFalse(leastValidRequest.checkValidity());
    // Note that the server trumps the limit on validity even if the client tries to construct a toke to last for 10 years
    assertFalse(leastValidRequest.checkTokenValidity());
  }

  @Test
  public void testSunshine() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void otherTimeLimit() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN,  1000L*60L, Timestamp.UNLIMITED, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }


  @Test
  public void testDecoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    Eip712AttestationRequestWithUsage newRequest = new Eip712AttestationRequestWithUsage(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());
    assertTrue(newRequest.checkTokenValidity());

    assertEquals(request.getIdentifier(), newRequest.getIdentifier());
    assertEquals(request.getType(), newRequest.getType());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertArrayEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sessionKey).getEncoded(),
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newRequest.getSessionPublicKey()).getEncoded());
    assertEquals( ((ECKeyParameters) request.getUserPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getUserPublicKey()).getParameters());
  }

  @Test
  public void eipEncoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + 1000);
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
        encoder.getUsageValue(), MAIL, URLUtility.encodeData(requestWithUsage.getDerEncoding()), now, expirationTime);
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestWUsageData>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  public void badSignature() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), new String(encoding)));
  }

  @Test
  public void expiredToken() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS, -1,
        MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidTimestamp() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, -1,
        Timestamp.DEFAULT_TOKEN_TIME_LIMIT, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notCorrect.com", new Timestamp());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidNonce() {
    byte[] wrongNonce = new byte[] {0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Mock
  AttestationRequestWithUsage mockedAttReqUsage;
  @Test
  public void nonVerifiableUseAttestation() {
    // First verification is done in the constructor of Eip712AttestationUsage
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true).thenReturn(false);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedAttReqUsage.getPok()).thenReturn(pok);
    Mockito.when(mockedAttReqUsage.getType()).thenReturn(TYPE);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        mockedAttReqUsage, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void invalidConstructor() {
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        mockedAttReqUsage,
        userSigningKey));
    assertEquals("Could not encode object", e.getMessage());
  }

  @Test
  public void invalidOtherConstructor() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage,
        userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, wrongJson));
    assertEquals("Could not decode object", e.getMessage());
  }

}
