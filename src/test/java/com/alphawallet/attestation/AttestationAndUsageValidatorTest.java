package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder;
import com.alphawallet.attestation.eip712.Nonce;
import com.alphawallet.attestation.eip712.Timestamp;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class AttestationAndUsageValidatorTest {
  private static final String DOMAIN = "https://www.hotelbogota.com";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final long CHAIN_ID = 1;
  private static final Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static SignedIdentityAttestation signedAttestation;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair userKeys;
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
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signedAttestation = new SignedIdentityAttestation(att, attestorKeys);
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
  }

  @Mock
  UseAttestation mockedUseAttestation;
  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
    // Standard mock
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedUseAttestation.getAttestation()).thenReturn(signedAttestation);
    Mockito.when(mockedUseAttestation.getPok()).thenReturn(pok);
    Mockito.when(mockedUseAttestation.getType()).thenReturn(TYPE);
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(true);
  }

  @Test
  public void testSunshine() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    AttestationAndUsageValidator validator = new AttestationAndUsageValidator(usage, MAIL, userKeys.getPublic());
    assertArrayEquals(usage.getDerEncoding(), validator.getUseAttestation().getDerEncoding());
    assertEquals(MAIL, validator.getIdentifier());
    assertEquals(userAddress, SignatureUtility.addressFromKey(validator.getUserPublicKey()));
    assertTrue(validator.checkTokenValidity());
    assertTrue(validator.verify());
  }

  @Test
  public void unverifiableUseAttestation() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(false);
    AttestationAndUsageValidator validator = new AttestationAndUsageValidator(mockedUseAttestation, MAIL, userKeys.getPublic());
    assertTrue(validator.checkTokenValidity());
    assertFalse(validator.verify());
  }

  @Test
  public void unvalidatableUseAttestation() {
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(false);
    AttestationAndUsageValidator validator = new AttestationAndUsageValidator(mockedUseAttestation, MAIL, userKeys.getPublic());
    assertFalse(validator.checkTokenValidity());
    assertTrue(validator.verify());
  }

  @Test
  public void invalidAddress() {
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AttestationAndUsageValidator validator = new AttestationAndUsageValidator(mockedUseAttestation, MAIL, otherKeys.getPublic());
    assertFalse(validator.checkTokenValidity());
    assertTrue(validator.verify());
  }

  @Test
  public void invalidProofLinking() {
    AttestationAndUsageValidator validator = new AttestationAndUsageValidator(mockedUseAttestation, "incorrect@email.com", userKeys.getPublic());
    assertFalse(validator.checkTokenValidity());
    assertTrue(validator.verify());
  }
}
