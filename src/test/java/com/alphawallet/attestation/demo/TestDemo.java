package com.alphawallet.attestation.demo;

import com.alphawallet.attestation.core.AttestationCrypto;
import java.io.File;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestDemo {
  private static final String PREFIX = "build/test-results/";
  @BeforeEach
  public void cleanup() throws Exception {
    String[] files = new String[]{"sender-pub.pem", "sender-priv.pem", "receiver-pub.pem",
        "receiver-priv.pem", "attestor-pub.pem", "attestor-priv.pem", "cheque.pem",
        "cheque-secret.pem", "attestation-request.pem", "attestation-secret.pem", "attestation.pem"};
    File currentKey;
    for (String current : files) {
      currentKey = new File(PREFIX+current);
      currentKey.delete();
    }
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    // Set the demo to use deterministic randomness
    Demo.crypto = new AttestationCrypto(rand);
  }

  @Test
  public void executeFlow() {
    String[] args;
    // Keys
    args = new String[]{"keys", PREFIX + "sender-pub.pem", PREFIX + "sender-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "receiver-pub.pem", PREFIX + "receiver-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "attestor-pub.pem", PREFIX + "attestor-priv.pem"};
    Demo.main(args);
    // Send
    args = new String[]{"create-cheque", "42", "test@test.ts", "mail", "3600", PREFIX + "sender-priv.pem", PREFIX + "cheque.pem", PREFIX + "cheque-secret.pem"};
    Demo.main(args);
    // Request attestation
    args = new String[]{"request-attest", PREFIX + "receiver-priv.pem", "test@test.ts", "mail", PREFIX + "attestation-request.pem", PREFIX + "attestation-secret.pem"};
    Demo.main(args);
    // Construct attestation
    args = new String[]{"construct-attest", PREFIX + "attestor-priv.pem", "AlphaWallet", "3600", PREFIX + "attestation-request.pem", PREFIX + "attestation.pem"};
    Demo.main(args);
    // Construct redeem request
    args = new String[]{"receive-cheque", PREFIX + "receiver-priv.pem", PREFIX + "cheque-secret.pem", PREFIX + "attestation-secret.pem", PREFIX + "cheque.pem", PREFIX + "attestation.pem", PREFIX + "attestor-pub.pem", PREFIX + "redeem-cheque.pem"};
    Demo.main(args);
    // Redeem using the redeem request
    args = new String[]{"redeem-cheque", PREFIX + "receiver-priv.pem", PREFIX + "redeem-cheque.pem", PREFIX + "attestor-pub.pem"};
    Demo.main(args);
  }
}
