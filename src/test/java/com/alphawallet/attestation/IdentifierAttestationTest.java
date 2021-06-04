package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/* TODO: this should later be collected into id.attestation package */
public class IdentifierAttestationTest {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair otherKeys;

  private static SecureRandom rand;
  // private identifier
  final String mail = "test@test.ts";
  // public identifier
  final String labeledURI = "https://twitter.com/king_midas";

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }


  @Test
  public void makePublicIdAttestation() throws IOException
  {
    IdentifierAttestation att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());

    Path p = Files.createTempFile("x509", ".der");

    att.setIssuer("CN=attestation.id");
    att.setSerialNumber(1);
    assertTrue(att.checkValidity());

    Files.write(p, (new SignedIdentifierAttestation(att, otherKeys)).getDerEncoding());
    System.out.println("To check the X509 attestation, run this:");
    System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
  }

  @Test
  public void testFullDecoding() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    byte[] encoding = initial.getDerEncoding();
    Attestation newAtt = new IdentifierAttestation(encoding);
    assertArrayEquals(encoding, newAtt.getPrehash());
  }

  @Test
  public void testNotStandard() throws Exception {
    Attestation initial = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic());
    byte[] encoding = initial.getPrehash();
    try {
      new IdentifierAttestation(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testCannotSet() {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, "otherTest@test.ts");
    try {
      initial.setSubject("012345678901234567890123456789012345678901234");
      fail();
    } catch (RuntimeException e) {
      // Expected
    }
    try {
      initial.setVersion(2);
      fail();
    } catch (RuntimeException e) {
      // Expected
    }
  }

  @Test
  public void testOtherSubject() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("subject");
    field.setAccessible(true);
    // Change the subject
    field.set(initial, new X500Name("CN=John Doe"));
    // Common Names are allowed
    assertTrue(initial.checkValidity());
  }

  @Test
  public void testInvalidPublicKey() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    // Change the public key
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherKeys.getPublic());
    field.set(initial, spki);
    // The key is only stored one place so it is allowed to change it as long as the attestation has not been signed
    assertTrue(initial.checkValidity());
  }

  @Test
  public void testNoCommitment() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("extensions");
    field.setAccessible(true);
    // Change the extensions
    DERSequence extensions = new DERSequence(new DERSequence());
    field.set(initial, extensions);
    // There must be a commitment in the extensions
    assertFalse(initial.checkValidity());
  }

  @Test
  public void testWrongExtension() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("extensions");
    field.setAccessible(true);
    // Wrong oid
    ASN1EncodableVector extension = new ASN1EncodableVector();
    extension.add(new ASN1ObjectIdentifier("1.2.3.4.5"));
    extension.add(ASN1Boolean.FALSE);
    extension.add(new DERIA5String("something wrong"));
    // Change the extensions
    DERSequence extensions = new DERSequence(new DERSequence(extension));
    field.set(initial, extensions);
    // There must be a commitment in the extensions
    assertFalse(initial.checkValidity());
  }

  @Test
  public void testUrlEncoding() {
    String mail = "tæst@test.ts";
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    assertEquals( initial.getAsUrlWithoutIdentifier() + "&email=t%C3%A6st%40test.ts", initial.getAsUrlWithIdentifier());
    assertEquals( initial.getAsUrlWithoutIdentifier() + "&email=" + mail, URLDecoder.decode(initial.getAsUrlWithIdentifier(), StandardCharsets.UTF_8));
    // Ensure that we get a valid URL
    String decodedWithoutId = URLDecoder.decode(initial.getAsUrlWithoutIdentifier(), StandardCharsets.UTF_8);
    assertEquals(decodedWithoutId, initial.getAsUrlWithoutIdentifier());
  }

  @Test
  public void testUrlEncodingNFT() throws Exception {
    IdentifierAttestation att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
    assertEquals( att.getAsUrlWithoutIdentifier() + "&205521676=https%3A%2F%2Ftwitter.com%2Fzhangweiwu", att.getAsUrlWithIdentifier());
    assertEquals( att.getAsUrlWithoutIdentifier() + "&205521676=https://twitter.com/zhangweiwu", URLDecoder.decode(att.getAsUrlWithIdentifier(), StandardCharsets.UTF_8));
    // Ensure that we get a valid URL
    String decodedWithoutId = URLDecoder.decode(att.getAsUrlWithoutIdentifier(), StandardCharsets.UTF_8);
    assertEquals(decodedWithoutId, att.getAsUrlWithoutIdentifier());
  }

  @Test
  public void testUrlEncodingFromBin() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    IdentifierAttestation decoded = new IdentifierAttestation(initial.getDerEncoding());
    assertEquals(initial.getAsUrlWithoutIdentifier() + "&" + IdentifierAttestation.HIDDEN_TYPE + "=" + IdentifierAttestation.HIDDEN_IDENTIFIER, decoded.getAsUrlWithIdentifier());
    // Ensure that we get a valid URL
    String decodedWithId = URLDecoder.decode(decoded.getAsUrlWithIdentifier(), StandardCharsets.UTF_8);
    assertEquals(decodedWithId, decoded.getAsUrlWithIdentifier());
  }

}
