package com.alphawallet.attestation.demo;

import com.alphawallet.attestation.core.AttestationCrypto;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestDemo {
  private static final String PREFIX = "build/test-results/";
  @BeforeAll
  public static void cleanup() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    // Set the demo to use deterministic randomness
    Demo.crypto = new AttestationCrypto(rand);
    Demo.rand = rand;
  }

  @Test
  public void constructKeys() {
    String[] args;
    // Keys
    args = new String[]{"keys", PREFIX + "sender-pub.pem", PREFIX + "sender-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "user-pub.pem", PREFIX + "user-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "attestor-pub.pem", PREFIX + "attestor-priv.pem"};
    Demo.main(args);
  }

  @Test
  public void executeChequeFlow() {
    String[] args;
    // Send
    args = new String[]{"create-cheque", "42", "test@test.ts", "mail", "3600", PREFIX + "sender-priv.pem", PREFIX + "cheque.pem", PREFIX + "cheque-secret.pem"};
    Demo.main(args);
    getAttestation();
    // Redeem
    args = new String[]{"receive-cheque", PREFIX + "user-priv.pem", PREFIX + "cheque-secret.pem", PREFIX + "attestation-secret.pem", PREFIX + "cheque.pem", PREFIX + "attestation.crt", PREFIX + "attestor-pub.pem"};
    Demo.main(args);
  }

  @Test
  public void executeEipFlow() {
    String[] args;
    getAttestation();
    // Use attestation
    args = new String[]{"use-attest", PREFIX + "user-priv.pem", PREFIX + "attestation.crt", PREFIX + "attestation-secret.pem", PREFIX + "attestor-pub.pem", "test@test.ts", "mail", PREFIX + "session-priv.pem", PREFIX + "use-attestation.json"};
    Demo.main(args);
    // Sign message
    args = new String[]{"sign-message", PREFIX + "session-priv.pem", "message", PREFIX + "signature.bin"};
    Demo.main(args);
    // Verify usage
    args = new String[]{"verify-usage", PREFIX + "use-attestation.json", PREFIX + "attestor-pub.pem", "message", PREFIX + "signature.bin"};
    Demo.main(args);
  }

  private void getAttestation() {
    String[] args;
    // Request attestation
    args = new String[]{"request-attest", PREFIX + "user-priv.pem", "test@test.ts", "mail", PREFIX + "attestation-request.json", PREFIX + "attestation-secret.pem"};
    Demo.main(args);
    // Construct attestation
    args = new String[]{"construct-attest", PREFIX + "attestor-priv.pem", "AlphaWallet", "3600", PREFIX + "attestation-request.json", PREFIX + "attestation.crt"};
    Demo.main(args);
  }

  @Test
  public void executeCombinedEipFlow() {
    String[] args;
    // Request attestation with usage
    args = new String[]{"request-attest-and-usage", PREFIX + "user-priv.pem", "test@test.ts", "mail",  PREFIX + "session-priv.pem", PREFIX + "use-and-request-attestation.json", PREFIX + "attestation-secret.pem"};
    Demo.main(args);
    // Construct attestation
    args = new String[]{"construct-attest-and-usage", PREFIX + "attestor-priv.pem", "AlphaWallet", "3600", PREFIX + "use-and-request-attestation.json", PREFIX + "attestation.crt"};
    Demo.main(args);
    // Sign message
    args = new String[]{"sign-message", PREFIX + "session-priv.pem", "message", PREFIX + "signature.bin"};
    Demo.main(args);
    // Verify usage
    args = new String[]{"verify-attest-and-usage", PREFIX + "use-and-request-attestation.json", PREFIX + "attestation.crt", PREFIX + "attestor-pub.pem", "message", PREFIX + "signature.bin"};
    Demo.main(args);
  }

}
