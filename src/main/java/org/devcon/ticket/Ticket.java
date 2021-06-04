package org.devcon.ticket;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Ticket implements Attestable {
  private static final Logger logger = LogManager.getLogger(Ticket.class);

  private final BigInteger ticketId;
  private final int ticketClass;
  private final String devconId;
  private final byte[] commitment;
  private final AlgorithmIdentifier algorithm;
  private final byte[] signature;
  public static final String magicLinkURLPrefix = "https://ticket.devcon.org/";
  private final AsymmetricKeyParameter publicKey;
  private final byte[] encoded;

  /**
   *  @param mail The mail address of the recipient
   * @param devconId The id of the conference for which the ticket should be used
   * @param ticketId The Id of the ticket
   * @param ticketClass The type of this ticket
   * @param keys The keys used to sign the cheque
   * @param secret the secret that must be known to cash the cheque
   */
  public Ticket(String mail, String devconId, BigInteger ticketId, int ticketClass,
      AsymmetricCipherKeyPair keys, BigInteger secret ) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
    this.commitment = AttestationCrypto.makeCommitment(mail, AttestationType.EMAIL, secret);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          keys.getPublic());
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not construct spki", e);
    }
    ASN1Sequence asn1Tic = makeTicket();
    try {
      this.signature = SignatureUtility.signWithEthereum(asn1Tic.getEncoded(), keys.getPrivate());
      this.encoded = encodeSignedTicket(asn1Tic);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode signature", e);
    }
    this.publicKey = keys.getPublic();
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is invalid"));
    }
  }

  public Ticket(String devconId, BigInteger ticketId, int ticketClass, byte[] commitment, byte[] signature, AsymmetricKeyParameter publicKey) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
    this.commitment = commitment;
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          publicKey);
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode spki", e);
    }
    this.signature = signature;
    ASN1Sequence ticket = makeTicket();
    try {
      this.encoded = encodeSignedTicket(ticket);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode ticket", e);
    }
    this.publicKey = publicKey;
    if (!verify()) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Signature is invalid"));
    }
  }

  private ASN1Sequence makeTicket() {
    ASN1EncodableVector ticket = new ASN1EncodableVector();
    ticket.add(new DERUTF8String(devconId));
    ticket.add(new ASN1Integer(ticketId));
    ticket.add(new ASN1Integer(ticketClass));
    return new DERSequence(ticket);
  }

  private byte[] encodeSignedTicket(ASN1Sequence ticket) throws IOException {
    ASN1EncodableVector signedTicket = new ASN1EncodableVector();
    signedTicket.add(ticket);
    signedTicket.add(new DEROctetString(commitment));
    signedTicket.add(new DERBitString(signature));
    return new DERSequence(signedTicket).getEncoded();
  }

  public byte[] getDerEncodingWithPK() {
    try {
      ASN1Sequence ticket = makeTicket();
      ASN1EncodableVector signedTicket = new ASN1EncodableVector();
      signedTicket.add(ticket);
      signedTicket.add(new DEROctetString(commitment));
      ASN1EncodableVector publicKeyInfo = new ASN1EncodableVector();
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
      publicKeyInfo.add(spki.getAlgorithm());
      publicKeyInfo.add(spki.getPublicKeyData());
      signedTicket.add(new DERSequence(publicKeyInfo));
      signedTicket.add(new DERBitString(signature));
      return new DERSequence(signedTicket).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not create public key info", e);
    }
  }

  @Override
  public byte[] getDerEncoding() {
    return encoded;
  }

  public String getUrlEncoding()  {
    try {
      SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory
          .createSubjectPublicKeyInfo(this.publicKey);
      return URLUtility
          .encodeList(Arrays.asList(this.encoded, keyInfo.getPublicKeyData().getEncoded()));
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode public key", e);
    }
  }

  @Override
  public boolean verify() {
    try {
      ASN1Sequence ticket = makeTicket();
      if (!SignatureUtility.verifyEthereumSignature(ticket.getEncoded(), signature, this.publicKey)) {
        logger.error("Could not verify signature");
        return false;
      }
    } catch (IOException e) {
      logger.error("Could not decode signature");
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    // The ticket is always valid on its own. It depends on which conference it is used
    // and whether it has been revoked that decides if it can be used
    return true;
  }

  public BigInteger getTicketId() {
    return ticketId;
  }

  public int getTicketClass() {
    return ticketClass;
  }

  public String getDevconId() {
    return devconId;
  }

  public byte[] getCommitment() {
    return commitment;
  }

  public AlgorithmIdentifier getAlgorithm() {
    return algorithm;
  }

  public byte[] getSignature() {
    return signature;
  }

  public AsymmetricKeyParameter getPublicKey() {
    return publicKey;
  }
}
