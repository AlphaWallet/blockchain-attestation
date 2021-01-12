package com.alphawallet.attestation.demo;

import com.alphawallet.attestation.*;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.cheque.Cheque;
import com.alphawallet.attestation.cheque.ChequeDecoder;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.AttestationCryptoWithEthereumCharacteristics;
import com.alphawallet.attestation.core.DERUtility;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.Random;

public class Demo {
  static AttestationCrypto crypto = new AttestationCryptoWithEthereumCharacteristics(new SecureRandom());
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
      SecureRandom rand = new SecureRandom();
      crypto = new AttestationCrypto(rand);
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
            createKeys(crypto, Paths.get(arguments.get(1)), Paths.get(arguments.get(2)));
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
                    Paths.get(arguments.get(6)),
                    Paths.get(arguments.get(7)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <cheque secret input dir> "
                + "<attestation secret input dir> <cheque input dir> <attestation input dir> "
                + "<attestation verification key input dir> <redeem request output dir>");
            throw e;
          }
          System.out.println("Finished redeeming cheque");
          break;

        case "redeem-cheque":
          System.out.println("Posting cheque redeem request to the blockchain...");
          try {
            redeemCheque(Paths.get(arguments.get(1)),
                Paths.get(arguments.get(2)),
                Paths.get(arguments.get(3)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <redeem request input dir> "
                + "<attestation verification key input dir>");
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

        case "construct-attest":
          // TODO very limited functionality.
          // Should use a configuration file and have a certificate to its signing key
          System.out.println("Signing attestation...");
          try {
            long validity = 1000*Long.parseLong(arguments.get(3)); // Validity in milliseconds
            constructAttest(Paths.get(arguments.get(1)), arguments.get(2), validity, Paths.get(arguments.get(4)), Paths.get(arguments.get(5)));
          } catch (Exception e) {
            System.err.println("Was expecting: <signing key input dir> <issuer name> "
                + "<validity in seconds> <attestation request input dir> "
                + "<signed attestation output dir>");
            throw e;
          }
          System.out.println("Finished signing attestation");
          break;

        default:
          System.err.println("First argument must be either \"keys\", \"create-cheque\", \"receive-cheque\", "
              + "\"request-attest\" or \"construct-attest\".");
          throw new IllegalArgumentException("Unknown role");
      }
    }
    catch( Exception e) {
      System.err.println("FAILURE!");
      return;
    }
    System.out.println("SUCCESS!");
  }

  private static void createKeys(AttestationCrypto crypto, Path pathPubKey, Path pathPrivKey) throws IOException {
    AsymmetricCipherKeyPair keys = crypto.constructECKeys();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory
        .createSubjectPublicKeyInfo(keys.getPublic());
    byte[] pub = spki.getEncoded();
    DERUtility.writePEM(pub, "PUBLIC KEY", pathPubKey);
    PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(keys.getPrivate());
    DERUtility.writePEM(privInfo.getEncoded(), "CHEQUE", pathPrivKey);
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
      Path pathAttestationSecret, Path pathCheque, Path pathAttestation,
      Path pathAttestationKey, Path outputRedeemDir) throws IOException {
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
    SignedAttestation att = new SignedAttestation(attestationBytes, attestationProviderKey);

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
    byte[] encoding = redeem.getDerEncoding();
    DERUtility.writePEM(encoding, "REDEEM", outputRedeemDir);
  }

  private static void redeemCheque(Path pathUserKey, Path pathRedeemRequest, Path pathAttestationKey) throws IOException {
    AsymmetricCipherKeyPair userKeys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    byte[] redeemRequestBytes = DERUtility.restoreBytes(Files.readAllLines(pathRedeemRequest));
    AsymmetricKeyParameter attestationProviderKey = PublicKeyFactory.createKey(
        DERUtility.restoreBytes(Files.readAllLines(pathAttestationKey)));
    AttestedObject redeemRequest = new AttestedObject(redeemRequestBytes, new ChequeDecoder(), attestationProviderKey,
        userKeys.getPublic());
    if (!redeemRequest.checkValidity()) {
      System.err.println("Could not validate redeem request");
      throw new RuntimeException("Validation failed");
    }
    if (!redeemRequest.verify()) {
      System.err.println("Could not verify redeem request");
      throw new RuntimeException("Verification failed");
    }
    // TODO how should this actually be?
    SmartContract sc = new SmartContract();
    if (!sc.testEncoding(redeemRequest.getPok())) {
      System.err.println("Could not submit proof of knowledge to the chain");
      throw new RuntimeException("Blockchain submission failed");
    }
  }

  private static void requestAttest(AttestationCrypto crypto, Path pathUserKey, String receiverId, AttestationType type,
      Path outputDirRequest, Path outputDirSecret) throws IOException {
    AsymmetricCipherKeyPair keys = DERUtility.restoreBase64Keys(Files.readAllLines(pathUserKey));
    BigInteger secret = crypto.makeSecret();
    ProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(receiverId, type, pok, keys);

    DERUtility.writePEM(request.getDerEncoding(), "ATTESTATION REQUEST", outputDirRequest);
    DERUtility.writePEM(DERUtility.encodeSecret(secret), "SECRET", outputDirSecret);
  }

  private static void constructAttest(Path pathAttestorKey, String issuerName,
      long validityInMilliseconds, Path pathRequest, Path attestationDir) throws IOException {
    AsymmetricCipherKeyPair keys = DERUtility.restoreBase64Keys(Files.readAllLines(pathAttestorKey));
    byte[] requestBytes = DERUtility.restoreBytes(Files.readAllLines(pathRequest));
    AttestationRequest request = new AttestationRequest(requestBytes);
    // TODO here is where it should be verified the user actually controls the mail
    if (!request.verify()) {
      System.err.println("Could not verify attestation signing request");
      throw new RuntimeException("Validation failed");
    }
    byte[] commitment = AttestationCrypto.makeCommitment(request.getIdentity(), request.getType(), request.getPok().getRiddle());
    Attestation att = new IdentifierAttestation(commitment, request.getPublicKey());
    att.setIssuer("CN=" + issuerName);
    att.setSerialNumber(new Random().nextLong());
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(System.currentTimeMillis() + validityInMilliseconds));
    SignedAttestation signed = new SignedAttestation(att, keys);
    DERUtility.writePEM(signed.getDerEncoding(), "ATTESTATION", attestationDir);
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
