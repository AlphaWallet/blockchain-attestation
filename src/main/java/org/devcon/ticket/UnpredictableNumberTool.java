package org.devcon.ticket;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.URLUtility;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.tokenscript.eip712.Eip712Common;

public class UnpredictableNumberTool {
  private static final Logger logger = LogManager.getLogger(UnpredictableNumberTool.class);
  public static final int BYTES_IN_SEED = AttestationCrypto.BYTES_IN_DIGEST;
  public static final long DEFAULT_VALIDITY_IN_MS = 3600*1000;
  public static final int BYTES_IN_UN = 8; // 64 bits
  private static final ByteBuffer longBuffer = ByteBuffer.allocate(Long.BYTES);

  private final SecureRandom random;
  private final String domain;
  private final long validityInMs;
  private final HMac hmac = new HMac(new KeccakDigest(256));

  public UnpredictableNumberTool(byte[] key, String domain) {
    this(new SecureRandom(), key, domain);
  }

  public UnpredictableNumberTool(SecureRandom random, byte[] key, String domain) {
    this(random, key, domain, DEFAULT_VALIDITY_IN_MS);
  }

  public UnpredictableNumberTool(SecureRandom random, byte[] key, String domain, long validityInMs) {
    this.random = random;
    this.domain = domain.toLowerCase();
    this.validityInMs = validityInMs;
    hmac.init(new KeyParameter(key));
    // todo should be moved to url utility
    if (!Eip712Common.isDomainValid(domain)) {
      ExceptionUtil.throwException(logger, new IllegalArgumentException("Domain is not a valid domain"));
    }
  }

  public String getDomain() {
    return domain;
  }

  /**
   * Computes an URL friendly base 64 encoding of HMAC(expirationInMs || domain).
   * The encoding consists of BYTES_IN_UN bytes
   * ExpirationInMs is computed from current time plus DEFAULT_VALIDITY_IN_MS
   */
  public UnpredictableNumberBundle getUnpredictableNumberBundle() {
    long expiration = Clock.systemUTC().millis() + validityInMs;
    byte[] randomness = random.generateSeed(BYTES_IN_SEED);
    return new UnpredictableNumberBundle(getUnpredictableNumber(randomness, expiration), randomness, domain, expiration);
  }

  private String getUnpredictableNumber(byte[] randomness, long expirationInMs) {
    hmac.reset();
    hmac.update(longToBytes(expirationInMs), 0, Long.BYTES);
    hmac.update(randomness, 0, BYTES_IN_SEED);
    hmac.update(domain.getBytes(StandardCharsets.UTF_8), 0, domain.getBytes(StandardCharsets.UTF_8).length);
    byte[] digest = new byte[256 / 8];
    hmac.doFinal(digest, 0);
    byte[] result = new byte[BYTES_IN_UN];
    System.arraycopy(digest, 0, result, 0, BYTES_IN_UN);
    return URLUtility.encodeData(result);
  }

  public boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs) {
    if (Clock.systemUTC().millis() > expirationInMs) {
      logger.error("Unpredictable number has expired");
      return false;
    }
    String expectedNumber = getUnpredictableNumber(randomness, expirationInMs);
    if (!expectedNumber.equals(un)) {
      logger.error("The unpredictable number is computed incorrectly. Either wrong key or wrong domain");
      return false;
    }
    return true;
  }

  private static byte[] longToBytes(long x) {
    longBuffer.putLong(0, x);
    return longBuffer.array();
  }
}
