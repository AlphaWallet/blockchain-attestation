package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CryptoTest {
  private AsymmetricCipherKeyPair subjectKeys;
  private AsymmetricCipherKeyPair issuerKeys;
  private AsymmetricCipherKeyPair senderKeys;
  private SecureRandom rand;
  private AttestationCrypto crypto;
  private static final String ID = "test@test.ts";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger SECRET1 = new BigInteger("684084084843542003217847860141382018669978641584584765489");
  private static final BigInteger SECRET2 = new BigInteger("137957078946249796347561580210756254704202645642012518546347679798121784");

  @BeforeEach
  public void setupCrypto() throws NoSuchAlgorithmException {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
    issuerKeys = crypto.constructECKeys();
    senderKeys = crypto.constructECKeys();
  }

  @Test
  public void testAddressFromKey() {
    String key = AttestationCrypto.addressFromKey(subjectKeys.getPublic());
    assertTrue(key.startsWith("0x"));
    assertEquals(key.length(), 2+2*20); // prefix 0x and two chars per byte
    // Assert consistency
    String keyAgain = AttestationCrypto.addressFromKey(subjectKeys.getPublic());
    assertTrue(keyAgain.equals(key));

    // Negative test
    String otherKey = AttestationCrypto.addressFromKey(issuerKeys.getPublic());
    assertFalse(otherKey.equals(key));
  }

  @Test
  public void testMakeCommitment() {
    byte[] point = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    // Sanity checks
    assertTrue(point.length > 32);
    assertFalse(Arrays.equals(point, new byte[point.length]));
    ECPoint encodedPoint = AttestationCrypto.decodePoint(point);
    assertFalse(encodedPoint.isInfinity());

    // Check consistency
    byte[] point2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    assertArrayEquals(point, point2);

    // Negative tests
    point2 = AttestationCrypto.makeCommitment("test", TYPE, SECRET1);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID + "   1", TYPE, SECRET1);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID, AttestationType.PHONE, SECRET1);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1.add(BigInteger.ONE));
    assertFalse(Arrays.equals(point, point2));
  }

  @Test
  public void testMakeRiddle() {
    ECPoint hiding = AttestationCrypto.H.multiply(SECRET1);
    byte[] riddleBytes = AttestationCrypto.makeCommitment(ID, TYPE, hiding);
    byte[] commitmentBytes = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    ECPoint riddle = AttestationCrypto.decodePoint(riddleBytes);
    // Sanity checks
    assertFalse(riddle.isInfinity());
    assertArrayEquals(riddleBytes, commitmentBytes);

    // Check consistency
    byte[] riddleBytes2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    assertArrayEquals(riddleBytes, riddleBytes2);

    // Negative tests
    riddleBytes2 = AttestationCrypto.makeCommitment("test", TYPE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeCommitment(ID + "   1", TYPE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeCommitment(ID, AttestationType.PHONE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeCommitment(ID, TYPE, hiding.add(hiding));
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
  }

  @Test
  public void testAttestationRequestProof() {
    ProofOfExponent pok = crypto.computeAttestationProof(SECRET1);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));
    // Test with other randomness
    ProofOfExponent pok2 = crypto.computeAttestationProof(SECRET1);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok2));
    assertNotEquals(pok.getPoint(), pok2.getPoint());
    assertNotEquals(pok.getChallenge(), pok2.getChallenge());
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getRiddle(), pok2.getRiddle());

    // Test with other secret
    pok = crypto.computeAttestationProof(BigInteger.ONE);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));

    // Negative tests
    pok = crypto.computeAttestationProof(SECRET1);
    pok2 = new ProofOfExponent(pok.getBase().add(pok.getBase()), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle().add(pok.getBase()), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint().add(pok.getBase()), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));
  }

  @Test
  public void testEqualityProof() {
    byte[] com1 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    byte[] com2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(AttestationCrypto.verifyEqualityProof(com1, com2, pok));
    // Check that the order matters
    assertFalse(AttestationCrypto.verifyEqualityProof(com2, com1, pok));
    // Test with other internal randomness
    ProofOfExponent pok2 = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(AttestationCrypto.verifyEqualityProof(com1, com2, pok2));
    assertTrue(AttestationCrypto.verifyEqualityProof(com1, com2, pok));
    assertNotEquals(pok.getPoint(), pok2.getPoint());
    assertNotEquals(pok.getChallenge(), pok2.getChallenge());
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getRiddle(), pok2.getRiddle());

    // Test with other commitment
    BigInteger otherSec = new BigInteger("45864684786789758065458745212314458");
    byte[] otherCom = AttestationCrypto.makeCommitment(ID, TYPE, otherSec);
    pok = crypto.computeEqualityProof(com1, otherCom, SECRET1, otherSec);
    assertTrue(AttestationCrypto.verifyEqualityProof(com1, otherCom, pok));
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok));

    // *** Negative tests ***
    // Test inconsistent commitments
    pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2.add(BigInteger.ONE));
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok));
    pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    otherCom = AttestationCrypto.makeCommitment(ID, TYPE, otherSec);
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, otherCom, pok));
    otherCom = crypto.makeCommitment(ID, TYPE, SECRET2.add(BigInteger.ONE));
    pok = crypto.computeEqualityProof(com1, otherCom, SECRET1, SECRET2);
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, otherCom, pok));
    otherCom = crypto.makeCommitment("test@test.tsss", TYPE, SECRET2);
    pok = crypto.computeEqualityProof(com1, otherCom, SECRET1, SECRET2);
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, otherCom, pok));
    otherCom = crypto.makeCommitment(ID, AttestationType.PHONE, SECRET2);
    pok = crypto.computeEqualityProof(com1, otherCom, SECRET1, SECRET2);
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, otherCom, pok));

    // Test wrong values
    pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(AttestationCrypto.verifyEqualityProof(com1, com2, pok));

    pok2 = new ProofOfExponent(pok.getBase().add(pok.getBase()), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle().add(pok.getBase()), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint().add(pok.getBase()), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pok2));
  }

  @Test
  public void testMakeSecret() {
    BigInteger sec = crypto.makeSecret();
    // Sanity check
    assertTrue(sec.bitLength() > 230); // Except with negligible prob the minimal representation will be at least 230 bits
    // Check not static
    BigInteger sec2 = crypto.makeSecret();
    assertNotEquals(sec, sec2);
  }

  @Test
  public void testMapToInteger() {
    BigInteger value = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID);
    // Sanity checks
    assertFalse(value.equals(BigInteger.ZERO));
    assertFalse(value.equals(BigInteger.ONE));
    assertFalse(value.equals(AttestationCrypto.curveOrder));
    assertFalse(value.equals(AttestationCrypto.fieldSize));
    assertFalse(value.equals(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)));
    assertFalse(value.equals(AttestationCrypto.fieldSize.subtract(BigInteger.ONE)));

    // Check consistency
    BigInteger value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID);
    assertEquals(value, value2);

    // Negative tests
    value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), "test");
    assertNotEquals(value, value2);
    value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID + "   1");
    assertNotEquals(value, value2);
    value2 = AttestationCrypto.mapToInteger(AttestationType.PHONE.ordinal(), ID);
    assertNotEquals(value, value2);
  }

  @Test
  public void testConstructAttRequestProof() throws NoSuchAlgorithmException{
    SecureRandom rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    AttestationCrypto crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok = crypt2.computeAttestationProof(SECRET1);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));

    // Check consistency
    rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok2 = crypt2.computeAttestationProof(SECRET1);
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getPoint(), pok2.getPoint());
    assertEquals(pok.getRiddle(), pok2.getRiddle());
    assertEquals(pok.getChallenge(), pok2.getChallenge());
  }

  @Test
  public void testDecodePoint() {
    byte[] encoded = AttestationCrypto.makeCommitment(ID, TYPE, SECRET1);
    ECPoint decoded = AttestationCrypto.decodePoint(encoded);
    ECPoint point = AttestationCrypto.curve.decodePoint(encoded);
    assertEquals(point, decoded);

    ECPoint newPoint = point.add(point);
    byte[] newEncoded = newPoint.getEncoded(false);
    ECPoint newDecoded = AttestationCrypto.decodePoint(newEncoded);
    assertEquals(newPoint, newDecoded);

    // Negative tests
    assertNotEquals(point, newPoint);
    assertNotEquals(encoded, newEncoded);
    assertNotEquals(decoded, newDecoded);
  }

  /**
   * This test is here to show that we have nothing-up-our-sleeve in picking the generators
   * @throws Exception
   */
  @Test
  public void computeGenerators() throws Exception {
    assertFalse(AttestationCrypto.G.add(AttestationCrypto.G).isInfinity());
    assertFalse(AttestationCrypto.H.add(AttestationCrypto.H).isInfinity());

    Method mapToInteger = AttestationCrypto.class.getDeclaredMethod("mapToInteger", byte[].class);
    mapToInteger.setAccessible(true);

    byte[] input = new byte[1];
    input[0] = 0;
    BigInteger gVal = (BigInteger) mapToInteger.invoke(crypto, input);
    ECPoint g = computePoint(gVal);
    assertEquals(AttestationCrypto.G, g);
    // Check order
    assertTrue(g.multiply(AttestationCrypto.curveOrder).isInfinity());
    assertArrayEquals(g.multiply(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)).normalize().getXCoord().getEncoded(), g.normalize().getXCoord().getEncoded());
    input[0] = 1;
    BigInteger hVal = (BigInteger) mapToInteger.invoke(crypto, input);
    ECPoint h = computePoint(hVal);
    assertEquals(AttestationCrypto.H, h);
    // Check order
    assertTrue(h.multiply(AttestationCrypto.curveOrder).isInfinity());
    assertArrayEquals(h.multiply(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)).normalize().getXCoord().getEncoded(), h.normalize().getXCoord().getEncoded());
  }

  /**
   * Compute a specific point on the curve (generator) based on x using the try-and-increment method
   * https://eprint.iacr.org/2009/226.pdf
   * @param x The x-coordinate for which we will compute y
   * @return A corresponding y coordinate for x
   */
  private static ECPoint computePoint(BigInteger x) {
    x = x.mod(AttestationCrypto.fieldSize);
    BigInteger ySquare, quadraticResidue;
    ECPoint resPoint, referencePoint;
    do {
      do {
        x = x.add(BigInteger.ONE).mod(AttestationCrypto.fieldSize);
        BigInteger a = AttestationCrypto.curve.getA().toBigInteger();
        BigInteger b = AttestationCrypto.curve.getB().toBigInteger();
        ySquare = x.modPow(new BigInteger("3"), AttestationCrypto.fieldSize).add(a.multiply(x)).add(b).mod(AttestationCrypto.fieldSize);
        BigInteger quadraticResidueExp = AttestationCrypto.fieldSize.subtract(BigInteger.ONE).shiftRight(1);
        quadraticResidue = ySquare.modPow(quadraticResidueExp, AttestationCrypto.fieldSize);
      } while (!quadraticResidue.equals(BigInteger.ONE));
      // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)
      BigInteger magicExp = AttestationCrypto.fieldSize.add(BigInteger.ONE).shiftRight(2); // fieldSize + 1 / 4
      BigInteger y = ySquare.modPow(magicExp, AttestationCrypto.fieldSize);
      resPoint = AttestationCrypto.curve.createPoint(x, y).normalize();
      // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
      if (resPoint.getYCoord().toBigInteger().compareTo(AttestationCrypto.fieldSize.shiftRight(1)) > 0) {
        resPoint = resPoint.negate().normalize();
      }
      referencePoint = resPoint.multiply(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)).normalize();
      if (referencePoint.getYCoord().toBigInteger().compareTo(AttestationCrypto.fieldSize.shiftRight(1)) > 0) {
        referencePoint = referencePoint.negate().normalize();
      }
      // Verify that the element is a member of the expected (subgroup) by ensuring that it has the right order, through Fermat's little theorem
      // NOTE: this is ONLY needed if we DON'T use secp256k1, so currently it is superflous but we are keeping it this check is crucial for security on most other curves!
    } while(!resPoint.equals(referencePoint) || resPoint.isInfinity());
    // Multiply with co-factor to ensure correct subgroup
    return resPoint.multiply(AttestationCrypto.cofactor).normalize();
  }

  @Test
  public void testBarret() {
    byte[] input = new byte[1];
    BigInteger regVal = AttestationCrypto.mapToInteger(input).mod(AttestationCrypto.curveOrder);
    BigInteger barrettsVal = AttestationCrypto.barrettsMapToInteger(input);
    assertEquals(regVal, barrettsVal);
  }
}
