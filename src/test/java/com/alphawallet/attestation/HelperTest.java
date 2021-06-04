package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;


/* created to help other test-cases - James
 * this class should be refactored away entirely - Weiwu */

public class HelperTest {

  public static final long VALIDITY = 1000L*60L*60L*24L*365L*10L; // 10 years

  public static IdentifierAttestation makeUnsignedStandardAtt(AsymmetricKeyParameter subjectPublicKey,
      BigInteger secret, String mail) {
    IdentifierAttestation att = new IdentifierAttestation(mail, AttestationType.EMAIL,
        subjectPublicKey, secret);
    att.setIssuer("CN=ALX");
    att.setSerialNumber(1);
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(System.currentTimeMillis() + VALIDITY));
    att.setSmartcontracts(Arrays.asList(42L, 1337L));
    assertTrue(att.checkValidity());
    assertFalse(att.isValidX509()); // Since the version is wrong, and algorithm is non-standard
    return att;
  }

  public static IdentifierAttestation makeUnsignedStandardAtt(AsymmetricKeyParameter subjectPublicKey,
                                                              AsymmetricKeyParameter issuerPublicKey, BigInteger secret, String mail) {
    IdentifierAttestation att = makeUnsignedStandardAtt(subjectPublicKey, secret, mail);
    assertTrue(att.checkValidity());
    assertTrue(issuerPublicKey instanceof ECPublicKeyParameters);
    return att;
  }

  /* the unsigned x509 attestation will have a subject of "CN=0x2042424242424564648" */
  public static Attestation makeUnsignedx509Att(AsymmetricKeyParameter key) throws IOException  {
    Attestation att = new Attestation();
    att.setVersion(2); // =v3 since counting starts from 0
    att.setSerialNumber(42);
    att.setSigningAlgorithm(SignedIdentifierAttestation.ECDSA_WITH_SHA256); // ECDSA with SHA256 which is needed for a proper x509
    att.setIssuer("CN=ALX");
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(System.currentTimeMillis()+VALIDITY));
    att.setSubject("CN=0x2042424242424564648");
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
    att.setSubjectPublicKeyInfo(spki);
    ASN1EncodableVector extensions = new ASN1EncodableVector();
    extensions.add(Attestation.OID_OCTETSTRING);
    extensions.add(ASN1Boolean.TRUE);
    extensions.add(new DEROctetString("hello world".getBytes()));
    // Double Sequence is needed to be compatible with X509V3
    att.setExtensions(new DERSequence(new DERSequence(extensions)));
    assertTrue(att.isValidX509());
    return att;
  }

  public static IdentifierAttestation makeMaximalAtt(AsymmetricKeyParameter key) throws IOException {
    IdentifierAttestation att = new IdentifierAttestation("Twitter", "King Midas", key);
    att.setSerialNumber(42);
    att.setSigningAlgorithm(IdentifierAttestation.DEFAULT_SIGNING_ALGORITHM);
    att.setIssuer("CN=ALX");
    att.setSmartcontracts(Arrays.asList(42L, 1337L));
    ASN1EncodableVector dataObject = new ASN1EncodableVector();
    dataObject.add(new DEROctetString("hello world".getBytes()));
    dataObject.add(new ASN1Integer(42));
    att.setDataObject(new DERSequence(dataObject));
    assertTrue(att.checkValidity());
    return att;
  }

  public static Attestation makeMinimalAtt() {
    Attestation att = new Attestation();
    att.setVersion(IdentifierAttestation.HIDDEN_IDENTIFIER_VERSION); // Our initial version
    att.setSerialNumber(42);
    att.setSubject("CN="); // Blank subject info
    att.setSigningAlgorithm(IdentifierAttestation.DEFAULT_SIGNING_ALGORITHM);
    ASN1EncodableVector dataObject = new ASN1EncodableVector();
    dataObject.add(new DEROctetString("hello world".getBytes()));
    att.setDataObject(new DERSequence(dataObject));
    assertTrue(att.checkValidity());
    return att;
  }
}
