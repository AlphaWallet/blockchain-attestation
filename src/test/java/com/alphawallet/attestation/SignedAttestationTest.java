package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.core.SignatureUtility;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SignedAttestationTest {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair issuerKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testSignAttestation() {
    Attestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, "some@mail.com" );
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    assertTrue(signed.checkValidity());
    assertTrue(signed.verify());
    assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), issuerKeys.getPublic()));
    assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
  }

  @Test
  public void testDecoding() throws Exception {
    Attestation att = HelperTest.makeMaximalAtt(subjectKeys.getPublic());
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), issuerKeys.getPublic()));
    assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
    byte[] signedEncoded = signed.getDerEncoding();
    SignedAttestation newSigned = new SignedAttestation(signedEncoded, issuerKeys.getPublic());
    assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
  }

  @Test
  public void testX509() throws Exception {
    X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
    AsymmetricCipherKeyPair newSubjectKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    AsymmetricCipherKeyPair newIssuerKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    Attestation att = HelperTest.makeUnsignedx509Att(newSubjectKeys.getPublic());
    byte[] toSign = att.getPrehash();
    byte[] digestBytes = new byte[32];
    Digest digest = new SHA256Digest();
    digest.update(toSign, 0, toSign.length);
    digest.doFinal(digestBytes, 0);
    byte[] signature = SignatureUtility.signHashedRandomized(digestBytes, newIssuerKeys.getPrivate());
    byte[] signed = SignedAttestation.constructSignedAttestation(att, signature);
    // Test X509 compliance
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream stream = new ByteArrayInputStream(signed);
    X509Certificate cert = (X509Certificate) fact.generateCertificate(stream);
    try {
      cert.checkValidity();
    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      fail();
    }
    PublicKey pk = new EC().generatePublic(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newIssuerKeys.getPublic()));
    cert.verify(pk, new BouncyCastleProvider());
  }
}
