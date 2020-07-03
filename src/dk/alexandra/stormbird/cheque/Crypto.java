package dk.alexandra.stormbird.cheque;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Crypto {

  public static final int COMP_SEC = 32; // 256 bits
  public final BigInteger fieldSize;
  public final BigInteger curveOrder;
  public final ECNamedCurveParameterSpec spec;
  private final Random rand;

  public Crypto(Random rand) {
    this.rand = rand;
    spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(),
        spec.getN());
    fieldSize = ((ECFieldFp) params.getCurve().getField()).getP();
    curveOrder = params.getOrder();
  }

  public KeyPair createKeyPair() throws Exception {

    Security.addProvider(new BouncyCastleProvider());
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
    keyGen.initialize(ecSpec, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  public BigInteger makeRandomExponent() {
    return new BigInteger(256, rand).mod(curveOrder);
  }

  public ECPoint decodePoint(byte[] point) {
    return spec.getCurve().decodePoint(point);
  }


  public List<byte[]> computeProof(ECPoint base, ECPoint riddle, BigInteger exponent) throws Exception {
    BigInteger r = makeRandomExponent();
    ECPoint t = base.multiply(r);
    // TODO ideally Bob's ethreum address should also be part of the challenge
    BigInteger c = mapToInteger(makeArray(Arrays.asList(base, riddle, t))).mod(curveOrder);
    BigInteger d = r.add(c.multiply(exponent)).mod(curveOrder);
    return Arrays.asList(base.getEncoded(), riddle.getEncoded(), t.getEncoded(), d.toByteArray());
  }

  public boolean verifyProof(List<byte[]> proof) throws Exception {
    ECPoint base = decodePoint(proof.get(0));
    ECPoint riddle = decodePoint(proof.get(1));
    ECPoint t = decodePoint(proof.get(2));
    BigInteger d = new BigInteger(proof.get(3));
    BigInteger c = mapToInteger(makeArray(Arrays.asList(base, riddle, t))).mod(curveOrder);
    ECPoint lhs = base.multiply(d);
    ECPoint rhs = riddle.multiply(c).add(t);
    return lhs.equals(rhs);
  }

  private byte[] makeArray(List<ECPoint> points ) throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    for (ECPoint current : points) {
      outputStream.write(current.getX().toBigInteger().toByteArray());
      outputStream.write(current.getY().toBigInteger().toByteArray());
    }
    byte[] res = outputStream.toByteArray();
    outputStream.close();
    return res;
  }

  public ECPoint generateRiddle(int type, String identifier, BigInteger secret) {
    try {
      BigInteger idenNum = mapToInteger(type, identifier.getBytes(StandardCharsets.UTF_8));
      ECPoint identityGen = computePoint(spec.getCurve(), fieldSize, idenNum);
      return identityGen.multiply(secret);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private BigInteger mapToInteger(byte[] value) {
    try {
      // We use HMAC to avoid issues with extension attacks, although SHA3 or double hashing should be sufficient on its own
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec("static_key".getBytes((StandardCharsets.UTF_8)), "HmacSHA256");
      mac.init(keySpec);
      mac.update(value);
      byte[] macData = mac.doFinal();

      BigInteger idenNum = new BigInteger(macData);
      idenNum.abs();
      return idenNum.mod(fieldSize);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private BigInteger mapToInteger(int type, byte[] identity) {
    ByteBuffer buf = ByteBuffer.allocate(4 + identity.length);
    buf.putInt(type);
    buf.put(identity);
    return mapToInteger(buf.array());
  }

  /**
   * Compute a specific point on the curve (generator) based on x
   * @param params
   * @param p The size of the underlying field
   * @param x The x-coordiante for which we will compute y
   * @return A corresponding y coordinate for x
   */
  private ECPoint computePoint(ECCurve params, BigInteger p, BigInteger x) {
    x = x.mod(p);
    BigInteger y, expected, ySquare;
    do {
      x = x.add(BigInteger.ONE).mod(p);
      BigInteger a = params.getA().toBigInteger();
      BigInteger b = params.getB().toBigInteger();
      ySquare = x.modPow(new BigInteger("3"), p).add(a.multiply(x)).add(b).mod(p);
      // Since we use secp256k1 we use the Lagrange trick to compute the squareroot (since p mod 4=3)
      BigInteger magicExp = p.add(BigInteger.ONE).divide(new BigInteger("4"));
      y = ySquare.modPow(magicExp, p);
      // Check that the squareroot actually exists and hence that we have a point on the curve
      expected = y.multiply(y).mod(p);
    } while (!expected.equals(ySquare));
    return params.createPoint(x, y, false);
  }
}
