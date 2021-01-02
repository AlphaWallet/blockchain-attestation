package com.alphawallet.attestation.core;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.ProofOfExponent;
import com.sun.org.apache.xerces.internal.impl.xs.SchemaGrammar.BuiltinSchemaGrammar;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class AttestationCrypto {
  public static final String ECDSA_CURVE = "secp256k1";
  public static final String MAC_ALGO = "HmacSHA256";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
  public static final X9ECParameters ECDSACurve = SECNamedCurves.getByName(AttestationCrypto.ECDSA_CURVE);
  public static final ECDomainParameters ECDSAdomain = new ECDomainParameters(ECDSACurve.getCurve(), ECDSACurve.getG(), ECDSACurve.getN(), ECDSACurve.getH());
  public static final BigInteger fieldSize = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
  // IMPORTANT: if another group is used then curveOrder should be the largest subgroup order
  public static final BigInteger curveOrder = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
  public static final BigInteger cofactor = new BigInteger("1");
  public static final ECCurve curve = new Fp(fieldSize, BigInteger.ZERO, new BigInteger("3"), curveOrder, cofactor);
  // Generator for message part of Pedersen commitments generated deterministically from mapToInteger queried on 0 and mapped to the curve using try-and-increment
  public static final ECPoint G = curve.createPoint(new BigInteger("12022136709705892117842496518378933837282529509560188557390124672992517127582"), new BigInteger("6765325636686621066142015726326349598074684595222800743368698766652936798612"));
  // Generator for randomness part of Pedersen commitments generated deterministically from  mapToInteger queried on 1 to the curve using try-and-increment
  public static final ECPoint H = curve.createPoint(new BigInteger("12263903704889727924109846582336855803381529831687633314439453294155493615168"), new BigInteger("1637819407897162978922461013726819811885734067940976901570219278871042378189"));
  private final SecureRandom rand;

  public AttestationCrypto(SecureRandom rand) {
    Security.addProvider(new BouncyCastleProvider());
    this.rand = rand;
    // Verify that fieldSize = 3 mod 4, otherwise the crypto won't work
    if (!fieldSize.mod(new BigInteger("4")).equals(new BigInteger("3"))) {
      throw new RuntimeException("The crypto will not work with this choice of curve");
    }
  }

  /**
   * Code shamelessly stolen from https://medium.com/@fixone/ecc-for-ethereum-on-android-7e35dc6624c9
   * @param key
   * @return
   */
  public static String addressFromKey(AsymmetricKeyParameter key) {
    // Todo should be verified that is works as intended, are there any reference values?
    byte[] pubKey;
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      pubKey = spki.getPublicKeyData().getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    //discard the first byte which only tells what kind of key it is //i.e. encoded/un-encoded
    pubKey = Arrays.copyOfRange(pubKey,1,pubKey.length);
    MessageDigest KECCAK = new Keccak.Digest256();
    KECCAK.reset();
    KECCAK.update(pubKey);
    byte[] hash = KECCAK.digest();
    //finally get only the last 20 bytes
    return "0x" + Hex.toHexString(Arrays.copyOfRange(hash,hash.length-20,hash.length)).toUpperCase();
  }

  public AsymmetricCipherKeyPair constructECKeys() {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ECDSAdomain, rand);
    generator.init(keygenParams);
    return generator.generateKeyPair();
  }


  /**
   * Construct a Pedersen commitment to an identifier using a specific secret.
   * @param identity The common identifier
   * @param type The type of identifier
   * @param secret The secret randomness to be used in the commitment
   * @return
   */
  public static byte[] makeCommitment(String identity, AttestationType type, BigInteger secret) {
    BigInteger hashedIdentity = mapToInteger(type.ordinal(), identity);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentity).add(H.multiply(secret));
    return commitment.getEncoded(false);
  }

  /**
   * Constructs a commitment to an identity based on hidden randomization supplied from a user.
   * This is used to construct an attestation.
   * @param identity The user's identity.
   * @param type The type of identity.
   * @param hiding The hiding the user has picked
   * @return
   */
  public static byte[] makeCommitment(String identity, AttestationType type, ECPoint hiding) {
    BigInteger hashedIdentity = mapToInteger(type.ordinal(), identity);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentity).add(hiding);
    return commitment.getEncoded(false);
  }

  /**
   * Computes a proof of knowledge of a random exponent
   * This is used to convince the attestor that the user knows a secret which the attestor will
   * then use to construct a Pedersen commitment to the user's identifier.
   * @param randomness The randomness used in the commitment
   * @return
   */
  public ProofOfExponent computeAttestationProof(BigInteger randomness) {
    // Compute the random part of the commitment, i.e. H^randomness
    ECPoint riddle = H.multiply(randomness);
    BigInteger r = makeSecret();
    ECPoint t = H.multiply(r);
    BigInteger c = mapToInteger(makeArray(Arrays.asList(G, H, riddle, t))).mod(curveOrder);
    BigInteger d = r.add(c.multiply(randomness)).mod(curveOrder);
    return new ProofOfExponent(H, riddle.normalize(), t.normalize(), d);
  }

  /**
   * Compute a proof that commitment1 and commitment2 are Pedersen commitments to the same message and that the user
   * knows randomness1-randomness2.
   * NOTE: We are actually not proving that the user knows the message and randomness1 and randomness2.
   * This is because we assume the user has already proven knowledge of his message (mail) and the
   * randomness1 used in the attestation to the attestor. Because of this assumption it is enough to prove
   * knowledge of randomness2 (equivalent to proving knowledge of randomness1-randomness2) and that the
   * commitments are to the same message.
   * The reason we do this is that this weaker proof is significantly cheaper to execute on the blockchain.
   *
   * In conclusion what this method actually proves is knowledge that randomness1-randomness2 is the
   * discrete log of commitment1/commitment2.
   * I.e. that commitment1/commitment2 =H^(randomness1-randomness2)
   * @param commitment1 First Pedersen commitment to some message m
   * @param commitment2 Second Pedersen commitment to some message m
   * @param randomness1 The randomness used in commitment1
   * @param randomness2 The randomness used in commitment2
   * @return
   */
  public ProofOfExponent computeEqualityProof(byte[] commitment1, byte[] commitment2, BigInteger randomness1, BigInteger randomness2) {
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute H*(randomness1-randomness2=commitment1-commitment2=G*msg+H*randomness1-G*msg+H*randomness2
    ECPoint riddle = comPoint1.subtract(comPoint2);
    BigInteger hiding = makeSecret();
    ECPoint t = H.multiply(hiding);
    // TODO ideally Bob's ethreum address should also be part of the challenge
    BigInteger c = mapToInteger(makeArray(Arrays.asList(G, H, comPoint1, comPoint2, t))).mod(curveOrder);
    BigInteger d = hiding.add(c.multiply(randomness1.subtract(randomness2))).mod(curveOrder);
    return new ProofOfExponent(H, riddle.normalize(), t.normalize(), d);
  }

  /**
   * Verifies a zero knowledge proof of knowledge of a riddle used in an attestation request
   * @param pok The proof to verify
   * @return True if the proof is OK and false otherwise
   */
  public static boolean verifyAttestationRequestProof(ProofOfExponent pok)  {
    BigInteger c = mapToInteger(makeArray(Arrays.asList(G, pok.getBase(), pok.getRiddle(), pok.getPoint()))).mod(curveOrder);
    // Ensure that the right base has been used in the proof
    if (!pok.getBase().equals(H)) {
      return false;
    }
    return verifyPok(pok, c);
  }

  /**
   * Verifies a zero knowledge proof of knowledge of the two riddles used in two different
   * commitments to the same message.
   * This is used by the smart contract to verify that a request is ok where one commitment is the
   * riddle for a cheque/ticket and the other is the riddle from an attesation.
   * @param pok The proof to verify
   * @return True if the proof is OK and false otherwise
   */
  public static boolean verifyEqualityProof(byte[] commitment1, byte[] commitment2, ProofOfExponent pok)  {
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute the value the riddle should have
    ECPoint riddle = comPoint1.subtract(comPoint2);
    // Verify the proof matches the commitments
    if (!riddle.equals(pok.getRiddle())) {
      return false;
    }
    // Ensure that the right base has been used in the proof
    if (!pok.getBase().equals(H)) {
      return false;
    }
    BigInteger c = mapToInteger(makeArray(Arrays.asList(G, pok.getBase(), comPoint1, comPoint2, pok.getPoint()))).mod(curveOrder);
    return verifyPok(pok, c);
  }

  private static boolean verifyPok(ProofOfExponent pok, BigInteger c) {
    ECPoint lhs = pok.getBase().multiply(pok.getChallenge());
    if (lhs.isInfinity()) {
      return false;
    }
    ECPoint rhs = pok.getRiddle().multiply(c).add(pok.getPoint());
    if (rhs.isInfinity()) {
      return false;
    }
    return lhs.equals(rhs);
  }

  public BigInteger makeSecret() {
    return new BigInteger(256+128, rand).mod(curveOrder);
  }

  private static byte[] makeArray(List<ECPoint> points ) {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      for (ECPoint current : points) {
        outputStream.write(current.normalize().getEncoded(false));
      }
      byte[] res = outputStream.toByteArray();
      outputStream.close();
      return res;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Map a byte array into a Big Integer using an double execution of Keccak 256.
   * @param value
   * @return
   *
   * TODO: Implement reference Barrett Reduction algorithm in Java to verify Solidity algorithm
   *       - Then we can revert to previous adjacent hash method
   */
  public static BigInteger mapToInteger(byte[] value) {
    try {
      MessageDigest KECCAK = new Keccak.Digest256();
      KECCAK.reset();
      KECCAK.update((byte) 0);
      KECCAK.update(value);
      byte[] hash0 = KECCAK.digest();
      KECCAK.reset();
      KECCAK.update((byte) 1); //probably don't need these additional inputs with the double hash
      KECCAK.update(value);
      byte[] hash1 = KECCAK.digest();
      byte[] res = new byte[56];
      System.arraycopy(hash1, 0, res, 0, 24); // Use the first 192 bits
      System.arraycopy(hash0, 0, res, 24, hash0.length);
      // res now contains 48 bytes, where the first 24 are the most significant from hash1
      // Note that we use double hashing to get a digest that is at least fieldSize or curve order
      // + security parameter in length to avoid any potential bias
      return new BigInteger(1, res);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static BigInteger barrettsMapToInteger(byte[] value) {
    MessageDigest KECCAK = new Keccak.Digest256();
    KECCAK.reset();
    KECCAK.update((byte) 0);
    KECCAK.update(value);
    byte[] hash0 = KECCAK.digest();
    KECCAK.reset();
    KECCAK.update((byte) 1);
    KECCAK.update(value);
    byte[] hash1 = KECCAK.digest();
    return barrettModCurveOrder(hash1, hash0);
  }

  // Assuming wordsize 8
  // k = 15 since 8 * (15 + 1) = 256
  // Computed as new BigDecimal("256").pow(2*31).divideToIntegralValue(new BigDecimal(curveOrder)).toBigIntegerExact();
  private static final BigInteger MU = new BigInteger("9346886097317750151219352360153887284354127572198641262375670094198727134");
  private static final BigInteger twoTo128 = BigInteger.ONE.shiftLeft(128);
  private static final BigInteger twoTo256 = BigInteger.ONE.shiftLeft(256);

  public static BigInteger barrettModCurveOrder(byte[] highestBits, byte[] lowestBits) {
    BigInteger tempLow = new BigInteger(1, Arrays.copyOfRange(lowestBits, 0, 2)); // Take the two first bytes which are the most significant bits since BigIntger is big endian
    BigInteger tempHigh = new BigInteger(1, Arrays.copyOfRange(highestBits, 0, 24)); // Use the first 128 bits
    // q1 is the 24 most significant bytes of x = highest bits || lowestBits
    BigInteger q1 = tempHigh.shiftLeft(2 * 8).add(tempLow); // Add the 2 most significant bytes of the lowestBits with the first 24 bytes of the highestBits
    BigInteger q3 = upperMult(q1, MU); // the 256 most significant bits of q1 * MU
    BigInteger r1 = new BigInteger(1, lowestBits);
    BigInteger r2 = lowerMult(q3, curveOrder);
    BigInteger r = r1.subtract(r2);
    if (r.compareTo(BigInteger.ZERO) < 0) {
      r = r.add(twoTo256); // r = r + 2^256
    }
    while (r.compareTo(curveOrder) > 0) {
      r = r.subtract(curveOrder);
    }
    return r;
  }

  /**
   * Multiplies two 256 bit BigIntegers together and return the 256 bit most significant part of the 512 bit result.
   * All BigIntegers in this method is at most 256 bits (unsigned)
   */
  public static BigInteger upperMult(BigInteger left, BigInteger right) {
    if (left.compareTo(twoTo256) >= 0 || right.compareTo(twoTo256) >= 0) {
      throw new IllegalArgumentException("Input too large for Karatsuba multiplication");
    }
    if (left.compareTo(twoTo128) <= 0 || right.compareTo(twoTo128) <= 0) {
      throw new IllegalArgumentException("Input too small for Karatsuba multiplication");
    }
    BigInteger[] decomposedLeft = decompose(left);
    BigInteger leftHigh = decomposedLeft[0];
    BigInteger leftLow = decomposedLeft[1];
    BigInteger[] decomposedRight = decompose(right);
    BigInteger rightHigh = decomposedRight[0];
    BigInteger rightLow = decomposedRight[1];

    // See the base step of the Karatsuba multiplication algorithm
    BigInteger z0 = leftLow.multiply(rightLow);
    BigInteger z2 = leftHigh.multiply(rightHigh);
    BigInteger z1 = (leftLow.add(leftHigh)).multiply(rightLow.add(rightHigh)).subtract(z2).subtract(z0);

    // Compute bits 128 to 256 of the result. This is the 128 most significant bits of z0 added to the 128 least significant bits of z1
    BigInteger sumz0z1 = z0.shiftRight(128).add(z1.mod(twoTo128));
    // Compute the potential carry if this is larger than 2^128 which should be carried over
    BigInteger lowCarry = sumz0z1.shiftRight(128);
    // Note that we are adding a 1 bit and a 128 bit number to a 256 bit number but we know it won't overflow since it is the most significant 256 bits of the at most 512 bit result
    BigInteger res = z1.shiftRight(128).add(z2).add(lowCarry);
    return res;
  }

  /**
   * Decomposes a 256 bit input into its least and most significant 128 bit parts in big endian order.
   */
  private static BigInteger[] decompose(BigInteger input) {
    // The 128 least significant bits of input, equivalent to low = new BigInteger(1, Arrays.copyOfRange(input.toByteArray(), input.toByteArray().length - 16, input.toByteArray().length));
    BigInteger low = input.mod(twoTo128);
    // The 128 most significant bits of input, equivalent to high = new BigInteger(1, Arrays.copyOfRange(input.toByteArray(), 0, input.toByteArray().length - 16));
    BigInteger high = input.shiftRight(128);
    return new BigInteger[] {high, low};
  }

  /**
   * Multiplies two 256 bit BigIntegers together and return the 256 bit least significant part of the 512 bit result.
   * All BigIntegers in this method is at most 256 bits (unsigned)
   */
  public static BigInteger lowerMult(BigInteger left, BigInteger right) {
    if (left.compareTo(twoTo256) >= 0 || right.compareTo(twoTo256) >= 0) {
      throw new IllegalArgumentException("Input too large for Karatsuba multiplication");
    }
    if (left.compareTo(twoTo128) <= 0 || right.compareTo(twoTo128) <= 0) {
      throw new IllegalArgumentException("Input too small for Karatsuba multiplication");
    }
    BigInteger[] decomposedLeft = decompose(left);
    BigInteger leftHigh = decomposedLeft[0];
    BigInteger leftLow = decomposedLeft[1];
    BigInteger[] decomposedRight = decompose(right);
    BigInteger rightHigh = decomposedRight[0];
    BigInteger rightLow = decomposedRight[1];

    // See the base step of the Karatsuba multiplication algorithm
    BigInteger z0 = leftLow.multiply(rightLow);
    BigInteger z2 = leftHigh.multiply(rightHigh);
    BigInteger z1 = (leftLow.add(leftHigh)).multiply(rightLow.add(rightHigh)).subtract(z2).subtract(z0);

    // Compute bits 128 to 256 of the result. This is the 128 most significant bits of z0 added to the 128 least significant bits of z1
    BigInteger sumz0z1 = z0.shiftRight(128).add(z1.mod(twoTo128));
    // Remove any potential; carry from the result
    BigInteger sumWOCarry = sumz0z1.mod(twoTo128);
    // Compute the result which is sumWOCarry << 128 plus the least significant 128 bits of z0
    BigInteger res = sumWOCarry.shiftLeft(128).add(z0.mod(twoTo128));
    return res;
  }

  /**
   *
   * @param type
   * @param identity
   * @return
   */
  public static BigInteger mapToInteger(int type, String identity) {
    byte[] identityBytes = identity.trim().toLowerCase().getBytes(StandardCharsets.UTF_8);
    ByteBuffer buf = ByteBuffer.allocate(4 + identityBytes.length);
    buf.putInt(type);
    buf.put(identityBytes);
    return mapToInteger(buf.array());
  }

  public static ECPoint decodePoint(byte[] point) {
    return curve.decodePoint(point).normalize();
  }
}
