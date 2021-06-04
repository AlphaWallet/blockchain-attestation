package com.alphawallet.attestation.demo;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.AttestationRequestWithUsage;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.UseAttestation;
import com.alphawallet.attestation.cheque.Cheque;
import com.alphawallet.attestation.cheque.ChequeDecoder;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.DERUtility;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequest;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsage;
import com.alphawallet.attestation.eip712.Eip712AttestationUsage;
import com.alphawallet.attestation.eip712.Nonce;
import com.alphawallet.attestation.eip712.Timestamp;
import com.alphawallet.attestation.eip712.TokenValidateable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Random;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Demo {
  static SecureRandom rand = new SecureRandom();
  static AttestationCrypto crypto = new AttestationCrypto(rand);

  public static final X9ECParameters SESSION_KEY_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
  public static final String ATTESTOR_DOMAIN = "http://wwww.attestation.id";
  public static final String WEB_DOMAIN = "http://wwww.hotelbogota.com";

  public static void main(String args[])  {
    CommandLineParser parser = new DefaultParser();
    CommandLine line;
    try {
      try {
        line = parser.parse(new Options(), args);
      } catch (ParseException e) {
        System.err.println("Could not parse commandline arguments");
        throw e;
      }
      List<String> arguments = line.getArgList();
      if (arguments.size() == 0) {
        System.err.println("First argument must be either \"keys\", \"create-cheque\", \"receive-cheque\", "
            + "\"request-attest\" or \"construct-attest\".");
        return;
      }
      switch (arguments.get(0).toLowerCase()) {
        case "keys":
          System.out.println("Constructing key pair...");
          try {
            createKeys(Paths.get(arguments.get(1)), Paths.get(arguments.get(2)));
          } catch (Exception e) {
            System.err.println("Was expecting: <output file to public key> <output file to private key>.");
            throw e;
          }
          System.out.println("Constructed keys");
          break;

        case "create-cheque":
          System.out.println("Constructing a cheque...");
          try {
            int amount = Integer.parseInt(arguments.get(1));
            String receiverId = arguments.get(2);
            AttestationType type = getType(arguments.get(3));
            long validity = 1000*Long.parseLong(arguments.get(4)); // Validity in milliseconds
            createCheque(crypto, amount, receiverId, type, validity,
                Paths.get(arguments.get(5)), Paths.get(arguments.get(6)), Paths.get(arguments.get(7)));

          } catch (Exception e) {
            System.err.println("Was expecting: <integer amount to send> <identifier of the receiver> "
                + "<type of ID, Either \"mail\" or \"phone\"> <validity in seconds> <signing key input dir>"
                + " <output dir for cheque> <output dir for secret>");
            throw e;
          }
          System.out.println("Constructed the cheque");
          break;

        case "receive-cheque":
          System.out.println("Making cheque redeem request...");
          try {
            receiveCheque(Paths.get(arguments.get(1)),
                    Paths.get(arguments.get(2)),
                    Paths.get(arguments.get(3)),
                    Paths.get(arguments.get(4)),
                    Paths.get(arguments.get(5)),
                    Paths.get(arguments.get(6)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <cheque secret input dir> "
                + "<attestation secret input dir> <cheque input dir> <attestation input dir> "
                + "<attestation signing key input dir>");
            throw e;
          }
          System.out.println("Finished redeeming cheque");
          break;

        case "request-attest":
          System.out.println("Constructing attestation request");
          try {
            AttestationType type = getType(arguments.get(3));
            requestAttest(crypto, Paths.get(arguments.get(1)), arguments.get(2), type, Paths.get(arguments.get(4)), Paths.get(arguments.get(5)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <identifier> "
                + "<type of ID, Either \"mail\" or \"phone\"> <attestation request output dir> <secret output dir>");
            throw e;
          }
          System.out.println("Finished constructing attestation request");
          break;

        case "request-attest-and-usage":
          System.out.println("Constructing attestation along with usage object");
          try {
            AttestationType type = getType(arguments.get(3));
            requestAndUseAttest(crypto, Paths.get(arguments.get(1)), arguments.get(2), type, Paths.get(arguments.get(4)),
                Paths.get(arguments.get(5)), Paths.get(arguments.get(6)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <identifier> "
                + "<type of ID, Either \"mail\" or \"phone\"> <private session key output dir> <usage/attestation request output dir> <secret output dir");
            throw e;
          }
          System.out.println("Finished constructing attestation and EIP712 usage object");
          break;

        case "construct-attest":
          // TODO very limited functionality.
          // Should use a configuration file and have a certificate to its signing key
          System.out.println("Signing attestation...");
          try {
            long validity = Timestamp.DEFAULT_TIME_LIMIT_MS;
            constructAttest(Paths.get(arguments.get(1)), arguments.get(2), validity, Paths.get(arguments.get(4)), Paths.get(arguments.get(5)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <issuer name> "
                + "<validity in seconds> <attestation request input dir> "
                + "<signed attestation output dir>");
            throw e;
          }
          System.out.println("Finished signing attestation");
          break;

        case "use-attest":
          System.out.println("Constructing attestation usage object");
          try {
            AttestationType type = getType(arguments.get(6));
            useAttest(crypto, Paths.get(arguments.get(1)), Paths.get(arguments.get(2)), Paths.get(arguments.get(3)),
                Paths.get(arguments.get(4)), arguments.get(5), type, Paths.get(arguments.get(7)), Paths.get(arguments.get(8)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <attestation dir> <attestation secret input dir> <attestor verification key dir> <identifier> "
                + "<type of ID, Either \"mail\" or \"phone\"> <private session key output dir> <usage request output dir>");
            throw e;
          }
          System.out.println("Finished constructing usage EIP712");
          break;

        case "sign-message":
          System.out.println("Signing a message using session keys");
          try {
            signMessage(Paths.get(arguments.get(1)), arguments.get(2), Paths.get(arguments.get(3)));
          } catch (Exception e) {
            System.err.println("Was expecting: <private session key dir> <message> <signature output dir>");
            throw e;
          }
          System.out.println("Finished signing message");
          break;

        case "verify-usage":
          System.out.println("Verifying message usage");
          try {
            verifyUsage(Paths.get(arguments.get(1)), Paths.get(arguments.get(2)), arguments.get(3), Paths.get(arguments.get(4)));
          } catch (Exception e) {
            System.err.println("Was expecting: <usage request dir> <attestor verification key dir> <message> <signature dir>");
            throw e;
          }
          System.out.println("Finished verifying message");
          break;

        default:
          System.err.println("First argument must be either \"keys\", \"create-cheque\", \"receive-cheque\", "
              + "\"request-attest\", \"construct-attest\", \"use-attest\", \"sign-message\", \"verify-usage\","
              + " or \"request-attest-and-usage\".");
          throw new IllegalArgumentException("Unknown role");
      }
    }
    catch(Exception e) {
      System.err.println("FAILURE!");
      throw new RuntimeException(e);
    }
    System.out.println("SUCCESS!");
  }

  private static void createKeys(Path pathPubKey, Path pathPrivKey) throws IOException {
    AsymmetricCipherKeyPair keys = SignatureUtility.constructECKeysWithSmallestY(rand);
    writePrivKey(keys.getPrivate(), pathPrivKey);
    writePubKey(keys.getPublic(), pathPubKey);
  }

  private static void writePrivKey(AsymmetricKeyParameter privKey, Path pathPrivKey) throws IOException {
    PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privKey);
    DERUtility.writePEM(privInfo.getEncoded(), "PRIVATE KEY", pathPrivKey);
  }

  private static void writePubKey(AsymmetricKeyParameter pubKey, Path pathPubKey) throws IOException {
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);
    byte[] pub = spki.getEncoded();
    DERUtility.writePEM(pub, "PUBLIC KEY", pathPubKey);
  }

  private static void createCheque(AttestationCrypto crypto, int amount, String receiverId, AttestationType type,
      long validityInMilliseconds, Path pathInputKey, Path outputDirCheque, Path outputDirSecret) throws IOException {
    AsymmetricCipherKeyPair keys = DERUtility.restoreBase64Keys(Files.readAllLines(pathInputKey));

    BigInteger secret = crypto.makeSecret();
    Cheque cheque = new Cheque(receiverId, type, amount, validityInMilliseconds, keys, secret);
    byte[] encoding = cheque.getDerEncoding();

    DERUtility.writePEM(encoding, "CHEQUE", outputDirCheque);
    DERUtility.writePEM(DERUtility.encodeSecret(secret), "CHEQUE SECRET", outputDirSecret);
  }

  private static void receiveCheque(Path pathUserKey, Path chequeSecretDir,
                                    Path pathAttestationSecret, Path pathCheque, Path pathAttestation, Path pathAttestationKey)
  throws Exception {
    AsymmetricCipherKeyPair userKeys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    byte[] chequeSecretBytes = DERUtility.restoreBytes(Files.readAllLines(chequeSecretDir));
    BigInteger chequeSecret = DERUtility.decodeSecret(chequeSecretBytes);
    byte[] attestationSecretBytes = DERUtility.restoreBytes(Files.readAllLines(pathAttestationSecret));
    BigInteger attestationSecret = DERUtility.decodeSecret(attestationSecretBytes);
    byte[] chequeBytes = DERUtility.restoreBytes(Files.readAllLines(pathCheque));
    Cheque cheque = (new ChequeDecoder()).decode(chequeBytes);
    byte[] attestationBytes = DERUtility.restoreBytes(Files.readAllLines(pathAttestation));
    AsymmetricKeyParameter attestationProviderKey = PublicKeyFactory.createKey(
        DERUtility.restoreBytes(Files.readAllLines(pathAttestationKey)));
    SignedIdentifierAttestation att = new SignedIdentifierAttestation(attestationBytes, attestationProviderKey);

    if (!cheque.checkValidity()) {
      System.err.println("Could not validate cheque");
      throw new RuntimeException("Validation failed");
    }
    if (!cheque.verify()) {
      System.err.println("Could not verify cheque");
      throw new RuntimeException("Verification failed");
    }
    if (!att.checkValidity()) {
      System.err.println("Could not validate attestation");
      throw new RuntimeException("Validation failed");
    }
    if (!att.verify()) {
      System.err.println("Could not verify attestation");
      throw new RuntimeException("Verification failed");
    }

    AttestedObject redeem = new AttestedObject(cheque, att, userKeys, attestationSecret, chequeSecret, crypto);
    if (!redeem.checkValidity()) {
      System.err.println("Could not validate redeem request");
      throw new RuntimeException("Validation failed");
    }
    if (!redeem.verify()) {
      System.err.println("Could not verify redeem request");
      throw new RuntimeException("Verification failed");
    }
    // TODO how should this actually be?
    SmartContract sc = new SmartContract();
    byte[] attestationCommit = redeem.getAtt().getUnsignedAttestation().getCommitment();
    if (!sc.verifyEqualityProof(attestationCommit, redeem.getAttestableObject().getCommitment(), redeem.getPok())) {
      System.err.println("Could not submit proof of knowledge to the chain");
      throw new RuntimeException("Chain submission failed");
    }
  }

  private static void requestAttest(AttestationCrypto crypto, Path pathUserKey, String receiverId, AttestationType type,
      Path outputDirRequest, Path outputDirSecret) throws IOException {
    AsymmetricCipherKeyPair keys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    BigInteger secret = crypto.makeSecret();
    String address = SignatureUtility.addressFromKey(keys.getPublic());
    byte[] nonce = Nonce.makeNonce(address, ATTESTOR_DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(secret, nonce);
    AttestationRequest attRequest = new AttestationRequest(type, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(ATTESTOR_DOMAIN, receiverId, attRequest, keys.getPrivate());
    Files.write(outputDirRequest, request.getJsonEncoding().getBytes(StandardCharsets.UTF_8),
        CREATE, TRUNCATE_EXISTING);
    DERUtility.writePEM(DERUtility.encodeSecret(secret), "SECRET", outputDirSecret);
  }

  private static void requestAndUseAttest(AttestationCrypto crypto, Path pathUserKey, String receiverId, AttestationType type,
      Path outputSessionPrivKeyDir, Path outputDirRequest, Path outputDirSecret) throws IOException {
    AsymmetricCipherKeyPair userKeys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    BigInteger secret = crypto.makeSecret();
    String address = SignatureUtility.addressFromKey(userKeys.getPublic());
    byte[] nonce = Nonce.makeNonce(address, ATTESTOR_DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(secret, nonce);
    AsymmetricCipherKeyPair sessionKeys = SignatureUtility.constructECKeys(SESSION_KEY_CURVE, rand);
    AttestationRequestWithUsage attRequest = new AttestationRequestWithUsage(type, pok, sessionKeys.getPublic());
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(ATTESTOR_DOMAIN, receiverId, attRequest, userKeys.getPrivate());
    Files.write(outputDirRequest, request.getJsonEncoding().getBytes(StandardCharsets.UTF_8),
        CREATE, TRUNCATE_EXISTING);
    DERUtility.writePEM(DERUtility.encodeSecret(secret), "SECRET", outputDirSecret);
    Files.write(outputDirRequest, request.getJsonEncoding().getBytes(StandardCharsets.UTF_8),
        CREATE, TRUNCATE_EXISTING);
    writePrivKey(sessionKeys.getPrivate(), outputSessionPrivKeyDir);
  }

  private static void constructAttest(Path pathAttestorKey, String issuerName,
      long validityInMilliseconds, Path pathRequest, Path attestationDir) throws Exception {
    AsymmetricCipherKeyPair keys = DERUtility.restoreBase64Keys(Files.readAllLines(pathAttestorKey));
    String jsonRequest = String.join("", Files.readAllLines(pathRequest));
    IdentifierAttestation att = null;
    try {
      Eip712AttestationRequest attestationRequest = new Eip712AttestationRequest(ATTESTOR_DOMAIN, jsonRequest);
      checkAttestRequestVerifiability(attestationRequest);
      checkAttestRequestValidity(attestationRequest);
      byte[] commitment = AttestationCrypto.makeCommitment(attestationRequest.getIdentifier(), attestationRequest.getType(), attestationRequest.getPok().getRiddle());
      att = new IdentifierAttestation(commitment, attestationRequest.getUserPublicKey());
    } catch (IllegalArgumentException e) {
      // Restores as an Eip712AttestationRequestWithUsage object instead
      Eip712AttestationRequestWithUsage attestationRequest = new Eip712AttestationRequestWithUsage(ATTESTOR_DOMAIN, jsonRequest);
      checkAttestRequestVerifiability(attestationRequest);
      checkAttestRequestValidity(attestationRequest);
      byte[] commitment = AttestationCrypto.makeCommitment(attestationRequest.getIdentifier(), attestationRequest.getType(), attestationRequest.getPok().getRiddle());
      att = new IdentifierAttestation(commitment, attestationRequest.getUserPublicKey());
    }
    att.setIssuer("CN=" + issuerName);
    att.setSerialNumber(new Random().nextLong());
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(Clock.systemUTC().millis() + validityInMilliseconds));
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, keys);
    DERUtility.writePEM(signed.getDerEncoding(), "ATTESTATION", attestationDir);
  }

  private static void checkAttestRequestVerifiability(Verifiable input) {
    if (!input.verify()) {
      System.err.println("Could not verify attestation signing request");
      throw new RuntimeException("Verification failed");
    }
  }
  private static void checkAttestRequestValidity(Validateable input) {
    if (!input.checkValidity()) {
      System.err.println("Could not validate attestation signing request");
      throw new RuntimeException("Validation failed");
    }
  }

  private static void useAttest(AttestationCrypto crypto, Path pathUserKey, Path attestationDir, Path pathAttestationSecret, Path attestorVerificationKey,
      String receiverId, AttestationType type, Path outputSessionPrivKeyDir, Path outputDirRequest) throws IOException {
    AsymmetricCipherKeyPair userKeys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    AsymmetricKeyParameter attestorKey = PublicKeyFactory.createKey(DERUtility.restoreBytes(Files.readAllLines(attestorVerificationKey)));
    SignedIdentifierAttestation att = new SignedIdentifierAttestation(DERUtility.restoreBytes(Files.readAllLines(attestationDir)), attestorKey);
    AsymmetricCipherKeyPair sessionKeys = SignatureUtility.constructECKeys(SESSION_KEY_CURVE, rand);
    String address = SignatureUtility.addressFromKey(userKeys.getPublic());
    byte[] nonce = Nonce.makeNonce(address, WEB_DOMAIN, new Timestamp());
    byte[] attSecretBytes = DERUtility.restoreBytes(Files.readAllLines(pathAttestationSecret));
    BigInteger attSecret = DERUtility.decodeSecret(attSecretBytes);
    FullProofOfExponent pok = crypto.computeAttestationProof(attSecret, nonce);
    UseAttestation attUsage = new UseAttestation(att, type, pok, sessionKeys.getPublic());
    Eip712AttestationUsage usageRequest = new Eip712AttestationUsage(WEB_DOMAIN, receiverId, attUsage, userKeys.getPrivate());
    Files.write(outputDirRequest, usageRequest.getJsonEncoding().getBytes(StandardCharsets.UTF_8),
        CREATE, TRUNCATE_EXISTING);
    writePrivKey(sessionKeys.getPrivate(), outputSessionPrivKeyDir);
  }

  private static void signMessage(Path pathSessionKey, String message, Path signatureOutDir) throws IOException {
    AsymmetricCipherKeyPair sessionKeys = DERUtility.restoreBase64Keys(Files.readAllLines(pathSessionKey));
    byte[] signature = SignatureUtility.signDeterministicSHA256(message.getBytes(StandardCharsets.UTF_8), sessionKeys.getPrivate());
    Files.write(signatureOutDir, signature, CREATE, TRUNCATE_EXISTING);
  }

  private static void verifyUsage(Path pathRequest,
      Path attestorVerificationKeyDir, String message, Path signatureDir) throws IOException {
    AsymmetricKeyParameter attestorKey = PublicKeyFactory.createKey(DERUtility.restoreBytes(Files.readAllLines(attestorVerificationKeyDir)));
    byte[] signature = Files.readAllBytes(signatureDir);
    String jsonRequest = Files.readString(pathRequest);
    AsymmetricKeyParameter sessionPublicKey = null;
    try {
      Eip712AttestationUsage usageRequest = new Eip712AttestationUsage(WEB_DOMAIN, attestorKey, jsonRequest);
      checkUsageVerifiability(usageRequest);
      checkUsageValidity(usageRequest);
      sessionPublicKey = usageRequest.getSessionPublicKey();
    } catch (IllegalArgumentException e) {
      // Try as an  Eip712AttestationRequestWithUsage object instead, which is NOT linked to a specific website
      Eip712AttestationRequestWithUsage usageRequest = new Eip712AttestationRequestWithUsage(ATTESTOR_DOMAIN, jsonRequest);
      checkUsageVerifiability(usageRequest);
      checkUsageValidity(usageRequest);
      sessionPublicKey = usageRequest.getSessionPublicKey();
    }
    // Validate signature
    if (!SignatureUtility.verifySHA256(message.getBytes(StandardCharsets.UTF_8), signature, sessionPublicKey)) {
      System.err.println("Could not verify message signature");
      throw new RuntimeException("Signature verification failed");
    }
    System.out.println("SUCCESSFULLY validated usage request!");
  }

  private static void checkUsageVerifiability(Verifiable input) {
    if (!input.verify()) {
      System.err.println("Could not verify usage request");
      throw new RuntimeException("Verification failed");
    }
  }
  private static void checkUsageValidity(TokenValidateable input) {
    if (!input.checkTokenValidity()) {
      System.err.println("Could not validate usage request");
      throw new RuntimeException("Validation failed");
    }
  }

  private static AttestationType getType(String stringType) throws IllegalArgumentException {
    AttestationType type;
    switch (stringType.toLowerCase()) {
      case "mail":
        type = AttestationType.EMAIL;
        break;
      case "phone":
        type = AttestationType.PHONE;
        break;
      default:
        System.err.println("Could not parse identifier type, must be either \"mail\" or \"phone\"");
        throw new IllegalArgumentException("Wrong type of identifier");
    }
    return type;
  }
}
